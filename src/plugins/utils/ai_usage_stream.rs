//! Bounded, incremental provider-usage extraction for AI response streams.
//!
//! An enforcement plugin that charges a token budget needs exactly one thing
//! from a model response: the terminal usage counters. Buffering the whole
//! response to get them destroys streaming semantics and lets a client hold an
//! unbounded number of growing buffers open (GHSA-q2r2-6r7h-f69x). This module
//! provides the alternative: a state machine that is fed the response bytes as
//! they flow past, forwards nothing, and retains only
//!
//!   * a bounded partial-unit carry buffer ([`MAX_SSE_EVENT_BYTES`] for SSE,
//!     [`MAX_EVENT_STREAM_MESSAGE_BYTES`] for AWS event-stream framing), and
//!   * four small scalars of accumulated usage ([`UsageAccumulator`]).
//!
//! Retention is therefore independent of stream length: a never-ending stream
//! costs one carry buffer, not one copy of the response.
//!
//! The same [`UsageAccumulator`] is used for the buffered (non-streaming) SSE
//! path, so a provider event is interpreted identically whether the response
//! was streamed or collected.
//!
//! # Supported terminal-usage signals
//!
//! | Family | Signal |
//! |---|---|
//! | OpenAI / Mistral / Azure | root `usage` object on a chunk (`stream_options.include_usage`) |
//! | Anthropic | `message_start.message.usage.input_tokens`, `message_delta.usage.output_tokens` |
//! | Cohere v2 | `message-end` event's `delta.usage.tokens.*` |
//! | Google Gemini / Vertex | `usageMetadata` on a `GenerateContentResponse` SSE event |
//! | AWS Bedrock | `application/vnd.amazon.eventstream` framing with verified prelude and message CRC32; `amazon-bedrock-invocationMetrics` in the base64 `bytes` chunk payload, or a `ConverseStream` `metadata` event's `usage` |
//! | Hugging Face TGI | terminal `details.generated_tokens` (`/generate_stream`) |
//!
//! Anything else is left unobserved, which the caller must treat as "no
//! authoritative usage" and resolve through its configured unmetered policy —
//! never as a charge of zero. Bedrock frames whose prelude or message CRC
//! fails verification are never admitted as usage (already-observed counters
//! from earlier valid frames are retained).

use base64::Engine;
use serde_json::Value;

use super::ai_providers::{AiProvider, AiTokenUsage, detect_sse_provider, extract_response_usage};

/// Media type AWS Bedrock uses for `InvokeModelWithResponseStream` and
/// `ConverseStream` responses.
pub const AWS_EVENT_STREAM_MEDIA_TYPE: &str = "application/vnd.amazon.eventstream";

/// Largest single SSE line retained while waiting for its terminating newline.
/// A longer line is discarded and the parser resynchronizes at the next
/// newline, so a provider (or an attacker-controlled upstream) cannot turn one
/// unterminated line into unbounded gateway memory.
pub const MAX_SSE_EVENT_BYTES: usize = 64 * 1024;

/// Largest AWS event-stream message retained whole. Larger messages are skipped
/// by length without ever being buffered; Bedrock usage frames are far smaller.
pub const MAX_EVENT_STREAM_MESSAGE_BYTES: usize = 64 * 1024;

/// Largest base64 `bytes` payload decoded out of one event-stream message.
pub const MAX_EVENT_STREAM_PAYLOAD_BYTES: usize = 64 * 1024;

/// AWS event-stream prelude: total length, headers length, prelude CRC.
const EVENT_STREAM_PRELUDE_LEN: usize = 12;
/// Trailing message CRC.
const EVENT_STREAM_MESSAGE_CRC_LEN: usize = 4;
/// Smallest structurally valid event-stream message (prelude + message CRC).
const EVENT_STREAM_MIN_MESSAGE_LEN: usize = EVENT_STREAM_PRELUDE_LEN + EVENT_STREAM_MESSAGE_CRC_LEN;

/// Big-endian `u32` from the first four bytes of `bytes` (which must be at
/// least four long — every caller slices an already-validated prelude).
fn be_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// AWS event-stream CRC32 (ITU-T V.42 / IEEE / ZIP polynomial).
fn event_stream_crc32(bytes: &[u8]) -> u32 {
    crc32fast::hash(bytes)
}

/// True for the AWS event-stream media type (parameters tolerated).
pub fn is_aws_event_stream_content_type(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case(AWS_EVENT_STREAM_MEDIA_TYPE)
}

/// Accumulated provider usage counters.
///
/// Fixed size (three `Option<u64>` plus a flag) regardless of how many events
/// the stream carried. Later explicit values replace earlier ones; an absent
/// field never erases a previously observed one, because supported providers
/// report cumulative counters and split them across events (Anthropic reports
/// input tokens on `message_start` and output tokens on `message_delta`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsageAccumulator {
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
    total_tokens: Option<u64>,
    observed: bool,
}

impl UsageAccumulator {
    /// Whether any authoritative provider usage counter was seen. `false` means
    /// the caller must apply its unmetered policy, not charge zero.
    pub fn observed(&self) -> bool {
        self.observed
    }

    /// These counters in the shared [`AiTokenUsage`] shape.
    ///
    /// Both resolution rules below delegate through this so the streaming and
    /// buffered halves cannot drift: `total_for_mode` and `is_complete_for_mode`
    /// together decide whether an observation may release the reserved estimate,
    /// and a second copy of either rule here would be a fail-open waiting to
    /// happen.
    fn as_usage(&self) -> AiTokenUsage {
        AiTokenUsage {
            prompt_tokens: self.prompt_tokens,
            completion_tokens: self.completion_tokens,
            total_tokens: self.total_tokens,
            model: None,
            provider: None,
        }
    }

    /// Resolve the configured `count_mode` counter, or `None` when this stream
    /// never reported the selected counter.
    pub fn total_for_mode(&self, count_mode: &str) -> Option<u64> {
        self.as_usage().total_for_mode(count_mode)
    }

    /// Whether the selected counter is complete rather than a partial lower
    /// bound. A lone prompt/completion counter is authoritative for that
    /// component's mode, but not for `total_tokens`.
    pub fn is_complete_for_mode(&self, count_mode: &str) -> bool {
        self.as_usage().is_complete_for_mode(count_mode)
    }

    fn record(&mut self, usage: &AiTokenUsage) {
        if usage.prompt_tokens.is_none()
            && usage.completion_tokens.is_none()
            && usage.total_tokens.is_none()
        {
            return;
        }
        if usage.prompt_tokens.is_some() {
            self.prompt_tokens = usage.prompt_tokens;
        }
        if usage.completion_tokens.is_some() {
            self.completion_tokens = usage.completion_tokens;
        }
        if usage.total_tokens.is_some() {
            self.total_tokens = usage.total_tokens;
        } else if usage.prompt_tokens.is_some() || usage.completion_tokens.is_some() {
            // Recompute only from both components; a single component never
            // synthesizes a total that `total_for_mode` would then prefer.
            self.total_tokens = match (self.prompt_tokens, self.completion_tokens) {
                (Some(prompt), Some(completion)) => prompt.checked_add(completion),
                _ => self.total_tokens,
            };
        }
        self.observed = true;
    }

    /// Apply one dispatched SSE event's assembled `data` payload.
    ///
    /// Per the WHATWG event-stream grammar an event may carry several `data`
    /// fields, whose values are joined with `\n` and dispatched as ONE payload.
    /// The assembled document is therefore what is parsed first: parsing each
    /// field on its own discarded a legal usage document split across two of
    /// them, so the authoritative provider counts were lost and the budget
    /// followed the pre-request heuristic estimate instead
    /// (`GHSA-pqjf-4jcj-34rp`).
    ///
    /// A provider that omits the blank line between two complete documents
    /// leaves them joined here, which is not itself valid JSON. That case falls
    /// back to parsing each line on its own so a non-conformant stream keeps
    /// exactly the accounting it had before event assembly existed.
    ///
    /// `[DONE]` and non-JSON payloads are ignored — a malformed frame in the
    /// middle of an otherwise valid stream must not discard counters already
    /// observed, and must never be charged as zero.
    pub fn apply_sse_data(&mut self, data: &str, configured: Option<AiProvider>) {
        if self.apply_sse_json(data, configured) || !data.contains('\n') {
            return;
        }
        for line in data.lines() {
            self.apply_sse_json(line, configured);
        }
    }

    /// Parse one candidate JSON payload. Returns `true` when the payload was
    /// recognized (a parsed document, the `[DONE]` sentinel, or empty), so the
    /// caller knows whether the per-line fallback above is worth attempting.
    fn apply_sse_json(&mut self, data: &str, configured: Option<AiProvider>) -> bool {
        let data = data.trim();
        if data.is_empty() || data == "[DONE]" {
            return true;
        }
        let Ok(json) = serde_json::from_str::<Value>(data) else {
            return false;
        };
        self.apply_event_json(&json, configured);
        true
    }

    /// Apply one parsed provider event or terminal document.
    ///
    /// Every recognized shape is checked independently rather than dispatching
    /// on a single detected provider: a stream may interleave shapes (a Bedrock
    /// chunk payload carries both `usage` and `amazon-bedrock-invocationMetrics`),
    /// and an explicitly configured `provider` must not suppress the
    /// authoritative terminal signal of the format the backend actually sent.
    pub fn apply_event_json(&mut self, json: &Value, configured: Option<AiProvider>) {
        // OpenAI Responses streaming (`response.*` events). The authoritative
        // counters ride the TERMINAL `response.completed` event and live under
        // `response.usage`, not root `usage`, so without this arm a completed
        // Responses stream reported no usage at all and the budget kept the
        // pre-request estimate (`GHSA-pqjf-4jcj-34rp`). Every other
        // `response.*` event — `response.created`, `response.in_progress`,
        // `response.incomplete`, `response.failed`, the per-item deltas — is a
        // progress snapshot, never a usage authority, so the whole family
        // returns here rather than falling through to the generic arms below.
        // Mirrors the sibling `ai_token_metrics` terminal-event handling, and
        // matches no supported provider's own event names (Anthropic uses
        // `message_*`/`content_block_*`, Cohere v2 `message-*`).
        if let Some(kind) = json.get("type").and_then(Value::as_str)
            && kind.starts_with("response.")
        {
            if kind == "response.completed"
                && let Some(response) = json.get("response")
            {
                let provider = detect_sse_provider(response)
                    .or(configured)
                    .unwrap_or(AiProvider::OpenAi);
                self.record(&extract_response_usage(response, provider));
            }
            return;
        }

        // Root `usage` object: OpenAI / Mistral chunks with
        // `stream_options.include_usage`, Cohere v2 buffered, Bedrock Converse.
        // An explicitly empty or null `usage` (sent on every non-terminal
        // OpenAI chunk) is not a usage report.
        if json
            .get("usage")
            .and_then(Value::as_object)
            .is_some_and(|usage| !usage.is_empty())
        {
            // Prefer an unambiguous wire-shape discriminator. A configured
            // provider remains the fallback for genuinely ambiguous `usage`
            // documents, but must not suppress the authoritative format the
            // backend actually emitted (especially under the opt-in `warn`
            // policy, which would otherwise release the reservation).
            let provider = detect_sse_provider(json)
                .or(configured)
                .unwrap_or(AiProvider::OpenAi);
            self.record(&extract_response_usage(json, provider));
        }

        match json.get("type").and_then(Value::as_str) {
            // Anthropic streams input tokens once, up front.
            Some("message_start") => {
                if let Some(prompt) = json
                    .get("message")
                    .and_then(|message| message.get("usage"))
                    .and_then(|usage| usage.get("input_tokens"))
                    .and_then(Value::as_u64)
                {
                    self.record(&AiTokenUsage {
                        prompt_tokens: Some(prompt),
                        ..Default::default()
                    });
                }
            }
            // ... and the cumulative output tokens on the terminal delta.
            Some("message_delta") => {
                if let Some(completion) = json
                    .get("usage")
                    .and_then(|usage| usage.get("output_tokens"))
                    .and_then(Value::as_u64)
                {
                    self.record(&AiTokenUsage {
                        completion_tokens: Some(completion),
                        ..Default::default()
                    });
                }
            }
            // Cohere v2 nests counts under `delta.usage.tokens.*`.
            Some("message-end") => {
                self.record(&extract_response_usage(json, AiProvider::Cohere));
            }
            _ => {}
        }

        // Google Gemini / Vertex `streamGenerateContent` emits a sequence of
        // `GenerateContentResponse` values; the ones carrying `usageMetadata`
        // are cumulative, and the last one is authoritative.
        if json.get("usageMetadata").is_some() {
            self.record(&extract_response_usage(json, AiProvider::Google));
        }

        // Hugging Face TGI `/generate_stream` terminal event.
        if json
            .get("details")
            .and_then(|details| details.get("generated_tokens"))
            .is_some()
        {
            self.record(&extract_response_usage(json, AiProvider::Tgi));
        }

        // Bedrock `InvokeModelWithResponseStream` terminal chunk metrics.
        if json.get("amazon-bedrock-invocationMetrics").is_some() {
            self.record(&extract_response_usage(json, AiProvider::Bedrock));
        }
    }
}

/// Bounded assembly buffer for one SSE event's `data` fields.
///
/// Retention is capped by [`MAX_SSE_EVENT_BYTES`] across the WHOLE event, not
/// just per line: without that, a provider could split unbounded bytes over
/// many short, individually-legal `data` fields and grow this buffer without
/// limit. An event that exceeds the cap is abandoned and the parser resumes at
/// the next dispatch, exactly as an oversized single line already does — a
/// usage event is never 64 KiB, so no real charge is lost.
#[derive(Debug, Default)]
struct SseEventBuffer {
    data: String,
    /// A `data` field was seen for this event. An explicitly empty one still
    /// counts, so `data:\ndata:{...}` keeps its leading newline.
    has_data: bool,
    /// The cap was exceeded; drop the remainder of this event.
    overflowed: bool,
}

impl SseEventBuffer {
    fn push_data(&mut self, value: &str) {
        if self.overflowed {
            return;
        }
        let separator = usize::from(self.has_data);
        if self.data.len() + separator + value.len() > MAX_SSE_EVENT_BYTES {
            self.overflowed = true;
            self.data = String::new();
            self.has_data = true;
            return;
        }
        if self.has_data {
            self.data.push('\n');
        }
        self.data.push_str(value);
        self.has_data = true;
    }

    /// Reset and return the dispatched payload, or `None` when this event
    /// carried no usable `data` (no field at all, or an abandoned oversized
    /// one).
    fn take(&mut self) -> Option<String> {
        let overflowed = std::mem::take(&mut self.overflowed);
        let has_data = std::mem::take(&mut self.has_data);
        let data = std::mem::take(&mut self.data);
        (has_data && !overflowed).then_some(data)
    }
}

/// Wire framing an [`UsageStreamExtractor`] should decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageStreamFormat {
    /// `text/event-stream` newline-delimited `data:` frames.
    Sse,
    /// `application/vnd.amazon.eventstream` binary message framing.
    AwsEventStream,
}

/// Incremental terminal-usage extractor over a streaming response body.
///
/// Feed every chunk to [`push`](Self::push) in order and call
/// [`finish`](Self::finish) once at end of stream. The extractor never buffers
/// the response: peak retention is one partial unit plus the accumulator.
#[derive(Debug)]
pub struct UsageStreamExtractor {
    format: UsageStreamFormat,
    configured_provider: Option<AiProvider>,
    usage: UsageAccumulator,
    /// Partial SSE line, or partial AWS event-stream message.
    carry: Vec<u8>,
    /// Assembled `data` field values for the SSE event currently being built.
    event: SseEventBuffer,
    /// Remaining bytes of an oversized unit to discard without buffering.
    skip_remaining: u64,
    /// The current SSE line exceeded the cap: discard through the next newline.
    resyncing: bool,
    /// Total length of the AWS event-stream message currently being filled.
    pending_message_len: usize,
    /// AWS event-stream framing proved structurally invalid; stop parsing. The
    /// counters observed so far are kept, but nothing further is decoded.
    desynced: bool,
}

impl UsageStreamExtractor {
    pub fn new(format: UsageStreamFormat, configured_provider: Option<AiProvider>) -> Self {
        Self {
            format,
            configured_provider,
            usage: UsageAccumulator::default(),
            carry: Vec::new(),
            event: SseEventBuffer::default(),
            skip_remaining: 0,
            resyncing: false,
            pending_message_len: 0,
            desynced: false,
        }
    }

    pub fn usage(&self) -> &UsageAccumulator {
        &self.usage
    }

    /// Bytes currently retained by the parser. Test/diagnostic accessor for the
    /// bounded-retention guarantee.
    #[allow(dead_code)] // used only by tests/, dead code in the bin target
    pub fn retained_bytes(&self) -> usize {
        self.carry.len() + self.event.data.len()
    }

    /// Feed the next chunk of decoded response body bytes.
    pub fn push(&mut self, chunk: &[u8]) {
        if chunk.is_empty() {
            return;
        }
        match self.format {
            UsageStreamFormat::Sse => self.push_sse(chunk),
            UsageStreamFormat::AwsEventStream => self.push_event_stream(chunk),
        }
    }

    /// Flush any trailing partial unit at end of stream.
    ///
    /// A provider that omits the final newline after its terminal usage event
    /// must still be charged, so the SSE carry is applied here. An incomplete
    /// AWS event-stream message is discarded: a truncated binary frame carries
    /// no trustworthy counters.
    pub fn finish(&mut self) {
        if self.format == UsageStreamFormat::Sse {
            if !self.resyncing && !self.carry.is_empty() {
                let line = std::mem::take(&mut self.carry);
                self.apply_sse_line(&line);
            }
            // A provider that omits the terminating blank line after its final
            // usage event must still be charged, so the event assembled so far
            // is dispatched here rather than discarded.
            self.dispatch_sse_event();
        }
        self.carry = Vec::new();
        self.pending_message_len = 0;
    }

    fn push_sse(&mut self, chunk: &[u8]) {
        let mut rest = chunk;
        while let Some(index) = rest.iter().position(|byte| *byte == b'\n') {
            let (line, tail) = rest.split_at(index);
            rest = &tail[1..];
            if self.resyncing {
                // The oversized line ends here; resume with the next one.
                self.resyncing = false;
                self.carry.clear();
                continue;
            }
            // Enforce the line cap before parsing a complete unit too. The
            // unterminated-tail check below bounds retained carry, but without
            // this check a hostile backend could place an arbitrarily large
            // newline-terminated `data:` field in one body chunk, or complete
            // a near-cap carry with one large following segment. The former
            // would hand the whole borrowed slice to serde_json and the latter
            // would allocate their combined size, bypassing the bounded-parser
            // guarantee even though neither survives after this iteration.
            if self.carry.len().saturating_add(line.len()) > MAX_SSE_EVENT_BYTES {
                self.carry.clear();
                continue;
            }
            if self.carry.is_empty() {
                self.apply_sse_line(line);
            } else {
                let mut merged = std::mem::take(&mut self.carry);
                merged.extend_from_slice(line);
                self.apply_sse_line(&merged);
            }
            self.carry.clear();
        }

        if self.resyncing || rest.is_empty() {
            return;
        }
        if self.carry.len().saturating_add(rest.len()) > MAX_SSE_EVENT_BYTES {
            // Drop the oversized line entirely and resynchronize; a usage event
            // is never 64 KiB, so this cannot silently lose a real charge.
            self.carry = Vec::new();
            self.resyncing = true;
            return;
        }
        self.carry.extend_from_slice(rest);
    }

    /// Feed one complete SSE line into event assembly.
    ///
    /// Implements the WHATWG "parsing an event stream" line rules that matter
    /// to usage accounting: a blank line DISPATCHES the event, a line starting
    /// with `:` is a comment, and a `data` field's value (with one optional
    /// leading space removed) is appended to the event's payload, joined with
    /// `\n`. Only complete events are handed to the accumulator, so a usage
    /// document a provider legally split across two `data` fields is no longer
    /// discarded (`GHSA-pqjf-4jcj-34rp`).
    fn apply_sse_line(&mut self, line: &[u8]) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Ok(line) = std::str::from_utf8(line) else {
            return;
        };
        // A UTF-8 BOM is permitted at the very start of an event stream and is
        // not part of the first field name.
        let line = line.strip_prefix('\u{feff}').unwrap_or(line);
        if line.is_empty() {
            self.dispatch_sse_event();
            return;
        }
        if line.starts_with(':') {
            return;
        }
        // SSE field names are case-sensitive per the HTML Living Standard. A
        // line with no colon at all is a field with an empty value.
        let (field, value) = match line.find(':') {
            Some(index) => {
                let value = &line[index + 1..];
                (&line[..index], value.strip_prefix(' ').unwrap_or(value))
            }
            None => (line, ""),
        };
        if field != "data" {
            return;
        }
        self.event.push_data(value);
    }

    /// Hand the assembled event payload to the accumulator and reset.
    fn dispatch_sse_event(&mut self) {
        let Some(data) = self.event.take() else {
            return;
        };
        self.usage.apply_sse_data(&data, self.configured_provider);
    }

    fn push_event_stream(&mut self, chunk: &[u8]) {
        if self.desynced {
            return;
        }
        let mut rest = chunk;
        while !rest.is_empty() {
            if self.desynced {
                return;
            }
            if self.skip_remaining > 0 {
                let take = usize::try_from(self.skip_remaining)
                    .unwrap_or(usize::MAX)
                    .min(rest.len());
                rest = &rest[take..];
                self.skip_remaining -= take as u64;
                continue;
            }

            if self.carry.len() < EVENT_STREAM_PRELUDE_LEN {
                let take = (EVENT_STREAM_PRELUDE_LEN - self.carry.len()).min(rest.len());
                self.carry.extend_from_slice(&rest[..take]);
                rest = &rest[take..];
                if self.carry.len() < EVENT_STREAM_PRELUDE_LEN {
                    return;
                }
                if !self.begin_event_stream_message() {
                    return;
                }
                continue;
            }

            if self.pending_message_len == 0 && !self.begin_event_stream_message() {
                return;
            }

            // `carry.len() <= pending_message_len` holds on every path that
            // reaches here, but the bound is what keeps this parser's retention
            // at one message. Saturate rather than trust a non-local invariant
            // with attacker-controlled framing: an underflow would wrap to a
            // huge `take` and grow the carry past the cap.
            let remaining = self.pending_message_len.saturating_sub(self.carry.len());
            let take = remaining.min(rest.len());
            self.carry.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            if self.carry.len() < self.pending_message_len {
                return;
            }
            let message = std::mem::take(&mut self.carry);
            self.pending_message_len = 0;
            self.apply_event_stream_message(&message);
        }
    }

    /// Validate the buffered prelude and decide how the message is consumed.
    ///
    /// Returns `false` when the caller must stop consuming this chunk (framing
    /// proved invalid). The prelude CRC is verified **before** any length is
    /// trusted — including before the oversized-message skip path — so a
    /// corrupted length field cannot steer retention. An oversized-but-CRC-valid
    /// message is skipped by its trusted length rather than buffered; its
    /// contents are never admitted.
    fn begin_event_stream_message(&mut self) -> bool {
        let declared_prelude_crc = be_u32(&self.carry[8..12]);
        let actual_prelude_crc = event_stream_crc32(&self.carry[0..8]);
        if declared_prelude_crc != actual_prelude_crc {
            // Corrupt prelude: lengths are untrusted. Stop cleanly without
            // guessing a resynchronization point in a length-prefixed format.
            self.desync_event_stream();
            return false;
        }

        let total = be_u32(&self.carry[0..4]) as usize;
        let headers = be_u32(&self.carry[4..8]) as usize;
        if total < EVENT_STREAM_MIN_MESSAGE_LEN || headers > total - EVENT_STREAM_MIN_MESSAGE_LEN {
            // Structurally impossible even with a matching prelude CRC. Stop
            // rather than guess; the response becomes unmetered and the
            // caller's configured policy decides.
            self.desync_event_stream();
            return false;
        }
        if total > MAX_EVENT_STREAM_MESSAGE_BYTES {
            // Length is trusted only because the prelude CRC matched. Skip the
            // rest of the message without buffering it or admitting contents.
            self.skip_remaining = (total - EVENT_STREAM_PRELUDE_LEN) as u64;
            self.carry = Vec::new();
            self.pending_message_len = 0;
            return true;
        }
        self.pending_message_len = total;
        true
    }

    fn desync_event_stream(&mut self) {
        self.desynced = true;
        self.carry = Vec::new();
        self.pending_message_len = 0;
        self.skip_remaining = 0;
    }

    fn apply_event_stream_message(&mut self, message: &[u8]) {
        if message.len() < EVENT_STREAM_MIN_MESSAGE_LEN {
            self.desync_event_stream();
            return;
        }
        let (body, crc_bytes) = message.split_at(message.len() - EVENT_STREAM_MESSAGE_CRC_LEN);
        let declared_message_crc = be_u32(crc_bytes);
        let actual_message_crc = event_stream_crc32(body);
        if declared_message_crc != actual_message_crc {
            // Final CRC mismatch: do not parse headers/payload or record usage
            // from this frame. Keep any already-observed counters and stop.
            self.desync_event_stream();
            return;
        }

        let headers = be_u32(&message[4..8]) as usize;
        let payload_start = EVENT_STREAM_PRELUDE_LEN.saturating_add(headers);
        let payload_end = message.len().saturating_sub(EVENT_STREAM_MESSAGE_CRC_LEN);
        if payload_start >= payload_end {
            return;
        }
        let Ok(payload) = serde_json::from_slice::<Value>(&message[payload_start..payload_end])
        else {
            return;
        };

        // `ConverseStream` events carry the usage document directly.
        self.usage
            .apply_event_json(&payload, self.configured_provider);

        // `InvokeModelWithResponseStream` wraps the model-native chunk as
        // base64 under `bytes`. Decode bounded, then apply the inner document.
        let Some(encoded) = payload.get("bytes").and_then(Value::as_str) else {
            return;
        };
        // 4 base64 characters encode 3 bytes; refuse before allocating.
        if encoded.len() / 4 * 3 > MAX_EVENT_STREAM_PAYLOAD_BYTES {
            return;
        }
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
            return;
        };
        let Ok(inner) = serde_json::from_slice::<Value>(&decoded) else {
            return;
        };
        self.usage
            .apply_event_json(&inner, self.configured_provider);
    }
}

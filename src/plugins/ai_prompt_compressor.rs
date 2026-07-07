//! AI Prompt Compressor Plugin
//!
//! Shortens the prompt text sent to an LLM backend to cut token usage (and
//! therefore cost and latency) while preserving meaning. It rewrites the
//! prompt-bearing fields of an OpenAI-shaped chat/completions request body —
//! `messages[].content` (per configurable role) and the legacy top-level
//! `prompt` — replacing each long content string with a shorter, statistically
//! filtered version.
//!
//! # Why a model-free approach
//!
//! Model-based prompt compressors run a fine-tuned transformer (hundreds of
//! megabytes) to score token importance — accurate, but a poor fit for a
//! hot-path edge proxy that would have to load the model and run per-request
//! inference. Instead this plugin uses a compact, dependency-free **statistical
//! extractive** filter: it scores every word by a handful of cheap features —
//! stop-word membership, length, in-document rarity, and a proper-noun/entity
//! signal — protects structural spans (code, URLs, numbers, identifiers),
//! always keeps negations, then drops the lowest-scoring words until the target
//! ratio is met. It runs in microseconds with no model files, no network calls,
//! and no new crate dependencies.
//!
//! The transformation is intentionally lossy (extractive compression removes
//! filler words), so it only runs on roles the operator opts into and only on
//! content long enough to be worth compressing (`min_content_tokens`). Code
//! blocks, inline code, URLs, numbers, and identifiers are preserved verbatim,
//! and an optional `preserve_tag` lets operators wrap must-keep spans that are
//! copied through untouched.
//!
//! # Request flow
//!
//! Like `ai_prompt_shield`, the plugin does its work in two places so both the
//! normal backend-dispatch path and the `ai_federation` direct-dispatch path
//! forward the compressed body:
//!
//! * `before_proxy` compresses the buffered body and rewrites
//!   `ctx.metadata["request_body"]` so any later `before_proxy` consumer that
//!   dispatches directly from that metadata (notably `ai_federation`, priority
//!   2985) sends the compressed prompt. It also records `ai_prompt_compressor.*`
//!   observability metadata.
//! * `transform_request_body` (and its context-aware variant) re-derive the
//!   compressed body for the wire on the standard backend-dispatch path — this
//!   hook, not the metadata copy, produces the bytes actually sent upstream.
//!   Compression is gated to POST requests: the context-aware variant checks
//!   `ctx.method` (H1/H2 and the H3 cross-protocol bridge), and the no-context
//!   variant requires an explicit `:method` POST pseudo-header, which the native
//!   H3 buffered path injects. Compression is deterministic, so all paths agree.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use tracing::debug;

use super::utils::body_transform::is_json_content_type;
use super::{Plugin, PluginResult, RequestContext};

/// Default per-content token floor below which a string is left untouched.
const DEFAULT_MIN_CONTENT_TOKENS: usize = 200;
/// Default fraction of word-tokens to keep (0.5 = target ~50% reduction).
const DEFAULT_TARGET_RATIO: f32 = 0.5;
/// Default maximum request-body size to attempt compression on (1 MiB).
const DEFAULT_MAX_SCAN_BYTES: usize = 1_048_576;

pub struct AiPromptCompressor {
    /// Lowercased message roles whose `content` is compressed.
    compress_roles: HashSet<String>,
    /// Whether the legacy top-level `prompt` field is compressed (true when
    /// `"user"` is an eligible role, since a completions `prompt` is user text).
    compress_prompt_field: bool,
    /// Fraction of word-tokens to keep, in `(0.0, 1.0)`.
    target_ratio: f32,
    /// Estimated-token floor: content below this is passed through unchanged.
    min_content_tokens: usize,
    /// Skip the whole body when it exceeds this many bytes.
    max_scan_bytes: usize,
    /// Optional `(open, close)` markers whose enclosed span is kept verbatim
    /// (the markers themselves are stripped from the outgoing content).
    preserve_tags: Option<(String, String)>,
}

/// Running totals accumulated while compressing one request body.
#[derive(Default)]
struct CompressionStats {
    original_tokens: usize,
    compressed_tokens: usize,
    fields_compressed: usize,
}

impl CompressionStats {
    fn changed(&self) -> bool {
        self.fields_compressed > 0 && self.compressed_tokens < self.original_tokens
    }
}

impl AiPromptCompressor {
    pub fn new(config: &Value) -> Result<Self, String> {
        if !config.is_object() {
            return Err("ai_prompt_compressor: config must be an object".to_string());
        }

        let compress_roles: HashSet<String> = match optional_string_vec(config, "compress_roles")? {
            Some(roles) => {
                if roles.is_empty() {
                    return Err(
                        "ai_prompt_compressor: 'compress_roles' must not be empty — the plugin \
                         would have no effect"
                            .to_string(),
                    );
                }
                let normalized: HashSet<String> =
                    roles.into_iter().map(|r| r.trim().to_lowercase()).collect();
                if normalized.iter().any(String::is_empty) {
                    return Err(
                        "ai_prompt_compressor: 'compress_roles' entries must not be blank"
                            .to_string(),
                    );
                }
                normalized
            }
            // Default: compress user prompts only. System messages usually carry
            // load-bearing instructions and are preserved unless opted in.
            None => HashSet::from(["user".to_string()]),
        };
        let compress_prompt_field = compress_roles.contains("user");

        let target_ratio = match config.get("target_ratio") {
            Some(value) => {
                let ratio = value.as_f64().ok_or_else(|| {
                    "ai_prompt_compressor: 'target_ratio' must be a number".to_string()
                })? as f32;
                if !(ratio > 0.0 && ratio < 1.0) {
                    return Err(format!(
                        "ai_prompt_compressor: 'target_ratio' must be between 0 and 1 \
                         (exclusive), got {ratio}"
                    ));
                }
                ratio
            }
            None => DEFAULT_TARGET_RATIO,
        };

        let min_content_tokens =
            optional_usize(config, "min_content_tokens")?.unwrap_or(DEFAULT_MIN_CONTENT_TOKENS);

        let max_scan_bytes = match optional_usize(config, "max_scan_bytes")? {
            Some(0) => {
                return Err(
                    "ai_prompt_compressor: 'max_scan_bytes' must be greater than zero".to_string(),
                );
            }
            Some(bytes) => bytes,
            None => DEFAULT_MAX_SCAN_BYTES,
        };

        let preserve_tags = match optional_string(config, "preserve_tag")? {
            Some(tag) => {
                let tag = tag.trim();
                if tag.is_empty()
                    || !tag
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                {
                    return Err(
                        "ai_prompt_compressor: 'preserve_tag' must be a non-empty name of ASCII \
                         letters, digits, '-', or '_'"
                            .to_string(),
                    );
                }
                Some((format!("<{tag}>"), format!("</{tag}>")))
            }
            None => None,
        };

        Ok(Self {
            compress_roles,
            compress_prompt_field,
            target_ratio,
            min_content_tokens,
            max_scan_bytes,
            preserve_tags,
        })
    }

    /// Parse, compress in place, and re-serialize `body`. Returns the new bytes
    /// plus stats when compression actually reduced the token estimate, or
    /// `None` when the body is not JSON, is over the size cap, or nothing was
    /// compressed (so callers forward the original bytes untouched).
    fn compress_body(&self, body: &[u8]) -> Option<(Vec<u8>, CompressionStats)> {
        if body.len() > self.max_scan_bytes {
            return None;
        }
        let mut json: Value = serde_json::from_slice(body).ok()?;
        let stats = self.compress_json(&mut json);
        if !stats.changed() {
            return None;
        }
        let serialized = serde_json::to_vec(&json).ok()?;
        Some((serialized, stats))
    }

    /// Shared wire-path compression used by both `transform_request_body` and
    /// its context-aware variant: skip non-JSON and transport-encoded bodies,
    /// otherwise return the compressed bytes (or `None` when unchanged).
    fn compress_wire_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        request_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        // Require an explicit JSON content type; a missing Content-Type is
        // treated as ineligible so a JSON-looking body without the header is
        // never rewritten (matches `should_buffer_request_body`'s JSON gate).
        if !content_type.is_some_and(is_json_content_type) {
            return None;
        }
        if has_non_identity_content_encoding(request_headers) {
            return None;
        }
        self.compress_body(body).map(|(bytes, _stats)| bytes)
    }

    /// Walk the OpenAI-shaped request `Value`, compressing eligible prompt text
    /// in place and accumulating token stats.
    fn compress_json(&self, json: &mut Value) -> CompressionStats {
        let mut stats = CompressionStats::default();

        if let Some(messages) = json.get_mut("messages").and_then(Value::as_array_mut) {
            for message in messages.iter_mut() {
                let role_eligible = message
                    .get("role")
                    .and_then(Value::as_str)
                    .is_some_and(|role| self.compress_roles.contains(&role.to_lowercase()));
                if !role_eligible {
                    continue;
                }
                if let Some(content) = message.get_mut("content") {
                    self.compress_content(content, &mut stats);
                }
            }
        }

        // Legacy completions carry a top-level `prompt` (string or array of
        // strings) with no role; treat it as user content.
        if self.compress_prompt_field
            && let Some(prompt) = json.get_mut("prompt")
        {
            self.compress_content(prompt, &mut stats);
        }

        stats
    }

    /// Compress a message `content`, handling the string form, the multimodal
    /// array form (`[{type:"text", text:"..."}]`), and a plain array of strings
    /// (`prompt`).
    fn compress_content(&self, content: &mut Value, stats: &mut CompressionStats) {
        match content {
            Value::String(text) => {
                if let Some((compressed, orig, comp)) = self.compress_text(text) {
                    *text = compressed;
                    stats.original_tokens += orig;
                    stats.compressed_tokens += comp;
                    stats.fields_compressed += 1;
                }
            }
            Value::Array(parts) => {
                for part in parts.iter_mut() {
                    match part {
                        // Multimodal text part: {type: "text", text: "..."}.
                        Value::Object(obj)
                            if obj.get("type").and_then(Value::as_str) == Some("text") =>
                        {
                            if let Some(Value::String(text)) = obj.get_mut("text")
                                && let Some((compressed, orig, comp)) = self.compress_text(text)
                            {
                                *text = compressed;
                                stats.original_tokens += orig;
                                stats.compressed_tokens += comp;
                                stats.fields_compressed += 1;
                            }
                        }
                        // Plain string element (array-of-strings `prompt`).
                        Value::String(text) => {
                            if let Some((compressed, orig, comp)) = self.compress_text(text) {
                                *text = compressed;
                                stats.original_tokens += orig;
                                stats.compressed_tokens += comp;
                                stats.fields_compressed += 1;
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    /// Compress one text string. Returns `Some((compressed, original_tokens,
    /// compressed_tokens))` only when the content clears `min_content_tokens`
    /// and the result is a genuine token reduction; otherwise `None`.
    fn compress_text(&self, text: &str) -> Option<(String, usize, usize)> {
        let original_tokens = estimate_tokens(text);
        if original_tokens < self.min_content_tokens {
            // Too short to compress, but preserve-tag markers must still be
            // stripped — they are gateway-internal and never reach providers.
            return self.strip_markers_only(text, original_tokens);
        }
        let compressed = match &self.preserve_tags {
            Some(tags) => self.compress_with_preserve(text, tags),
            None => statistical_compress(text, self.target_ratio),
        };
        let compressed_tokens = estimate_tokens(&compressed);
        if compressed_tokens < original_tokens {
            Some((compressed, original_tokens, compressed_tokens))
        } else {
            self.strip_markers_only(text, original_tokens)
        }
    }

    /// When `preserve_tag` is configured and the text contains markers but
    /// compression does not apply (too short, or no token reduction), the
    /// markers are still removed so they never leak upstream.
    fn strip_markers_only(
        &self,
        text: &str,
        original_tokens: usize,
    ) -> Option<(String, usize, usize)> {
        let (open, close) = self.preserve_tags.as_ref()?;
        if !text.contains(open.as_str()) && !text.contains(close.as_str()) {
            return None;
        }
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        loop {
            let next = match (rest.find(open.as_str()), rest.find(close.as_str())) {
                (Some(a), Some(b)) if a <= b => Some((a, open.len())),
                (Some(_), Some(b)) => Some((b, close.len())),
                (Some(a), None) => Some((a, open.len())),
                (None, Some(b)) => Some((b, close.len())),
                (None, None) => None,
            };
            let Some((pos, len)) = next else {
                out.push_str(rest);
                break;
            };
            out.push_str(&rest[..pos]);
            rest = &rest[pos + len..];
        }
        let stripped_tokens = estimate_tokens(&out);
        Some((out, original_tokens, stripped_tokens))
    }

    /// Compress a string that may contain `preserve_tag` spans. Text outside the
    /// tags is compressed; the enclosed span is copied **verbatim** — its exact
    /// internal whitespace is retained, only the markers are stripped. A single
    /// separating space is inserted at a boundary only when needed to avoid
    /// gluing two adjacent non-whitespace characters.
    fn compress_with_preserve(&self, text: &str, tags: &(String, String)) -> String {
        let (open, close) = tags;
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        loop {
            let Some(op) = rest.find(open.as_str()) else {
                append_segment(&mut out, &statistical_compress(rest, self.target_ratio));
                break;
            };
            append_segment(
                &mut out,
                &statistical_compress(&rest[..op], self.target_ratio),
            );
            let inner_start = &rest[op + open.len()..];
            match inner_start.find(close.as_str()) {
                Some(cp) => {
                    // Preserved span: emit the raw slice so its internal spacing
                    // (blank lines, alignment) survives exactly.
                    append_segment(&mut out, &inner_start[..cp]);
                    rest = &inner_start[cp + close.len()..];
                }
                None => {
                    // Unterminated preserve span: keep the remainder verbatim.
                    append_segment(&mut out, inner_start);
                    break;
                }
            }
        }
        out
    }
}

#[async_trait]
impl Plugin for AiPromptCompressor {
    fn name(&self) -> &str {
        "ai_prompt_compressor"
    }

    fn priority(&self) -> u16 {
        super::priority::AI_PROMPT_COMPRESSOR
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        // JSON prompt bodies are an HTTP concern; native gRPC wire frames are
        // not compressed.
        super::HTTP_ONLY_PROTOCOLS
    }

    fn modifies_request_body(&self) -> bool {
        true
    }

    fn requires_request_body_before_before_proxy(&self) -> bool {
        // `before_proxy` rewrites `ctx.metadata["request_body"]` so direct
        // dispatchers (ai_federation) forward the compressed prompt.
        true
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        ctx.method == "POST"
            && ctx
                .headers
                .get("content-type")
                .is_some_and(|ct| is_json_content_type(ct))
            && !has_non_identity_content_encoding(&ctx.headers)
            // A body already over the scan cap can never be compressed, so do
            // not force buffering (and lose the streaming / direct-backend fast
            // path) just to return it unchanged.
            && !content_length_exceeds(&ctx.headers, self.max_scan_bytes)
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if ctx.method != "POST" {
            return PluginResult::Continue;
        }
        let content_type = headers
            .get("content-type")
            .map(String::as_str)
            .unwrap_or("");
        if !is_json_content_type(content_type) {
            return PluginResult::Continue;
        }
        // A transport-compressed body is opaque here (request-body decompression
        // runs later in the `compression` plugin's transform hook), so defer to
        // the wire-path `transform_request_body`, which sees decoded bytes.
        if has_non_identity_content_encoding(headers) {
            return PluginResult::Continue;
        }

        let Some(body) = ctx.metadata.get("request_body") else {
            return PluginResult::Continue;
        };
        if body.is_empty() {
            return PluginResult::Continue;
        }

        if let Some((compressed, stats)) = self.compress_body(body.as_bytes()) {
            if let Ok(serialized) = String::from_utf8(compressed) {
                ctx.metadata.insert("request_body".to_string(), serialized);
            }
            record_stats_metadata(ctx, &stats);
            debug!(
                original_tokens = stats.original_tokens,
                compressed_tokens = stats.compressed_tokens,
                fields = stats.fields_compressed,
                "ai_prompt_compressor: compressed request prompt"
            );
        }

        PluginResult::Continue
    }

    async fn transform_request_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        request_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        // No `RequestContext` here. Require an explicit POST marker: the native
        // H3 buffered path injects a `:method` pseudo-header, and other bridges
        // (H3 cross-protocol) run the context-aware variant below. A missing
        // marker is treated as ineligible so a non-POST body buffered on any
        // no-context path is never compressed.
        if !request_headers
            .get(":method")
            .is_some_and(|method| method.eq_ignore_ascii_case("POST"))
        {
            return None;
        }
        self.compress_wire_body(body, content_type, request_headers)
    }

    async fn transform_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        body: &[u8],
        content_type: Option<&str>,
        request_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        // Only compress POST bodies, even when a retry or another body-buffering
        // plugin forced buffering that bypassed `should_buffer_request_body`.
        if ctx.method != "POST" {
            return None;
        }
        self.compress_wire_body(body, content_type, request_headers)
    }
}

/// Record small, log-safe compression counters on the request context so they
/// flow to transaction summaries.
fn record_stats_metadata(ctx: &mut RequestContext, stats: &CompressionStats) {
    ctx.metadata.insert(
        "ai_prompt_compressor.original_tokens".to_string(),
        stats.original_tokens.to_string(),
    );
    ctx.metadata.insert(
        "ai_prompt_compressor.compressed_tokens".to_string(),
        stats.compressed_tokens.to_string(),
    );
    ctx.metadata.insert(
        "ai_prompt_compressor.tokens_saved".to_string(),
        stats
            .original_tokens
            .saturating_sub(stats.compressed_tokens)
            .to_string(),
    );
    ctx.metadata.insert(
        "ai_prompt_compressor.fields_compressed".to_string(),
        stats.fields_compressed.to_string(),
    );
}

/// True when a declared `Content-Length` exceeds `cap`. A missing or
/// unparseable length returns `false` (buffer and let the byte gate decide).
fn content_length_exceeds(headers: &HashMap<String, String>, cap: usize) -> bool {
    headers
        .get("content-length")
        .and_then(|value| value.trim().parse::<u64>().ok())
        .is_some_and(|len| len > cap as u64)
}

/// True when `content-encoding` marks the body as anything other than
/// `identity`. Allocation-free; tolerant of comma-separated encoding lists.
fn has_non_identity_content_encoding(headers: &HashMap<String, String>) -> bool {
    headers.get("content-encoding").is_some_and(|value| {
        value
            .split(',')
            .map(str::trim)
            .any(|token| !token.is_empty() && !token.eq_ignore_ascii_case("identity"))
    })
}

fn optional_string<'a>(config: &'a Value, field: &'static str) -> Result<Option<&'a str>, String> {
    match config.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(Some)
            .ok_or_else(|| format!("ai_prompt_compressor: '{field}' must be a string")),
    }
}

fn optional_string_vec(config: &Value, field: &'static str) -> Result<Option<Vec<String>>, String> {
    match config.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            let array = value
                .as_array()
                .ok_or_else(|| format!("ai_prompt_compressor: '{field}' must be an array"))?;
            let mut out = Vec::with_capacity(array.len());
            for entry in array {
                let text = entry.as_str().ok_or_else(|| {
                    format!("ai_prompt_compressor: '{field}' must contain only strings")
                })?;
                out.push(text.to_string());
            }
            Ok(Some(out))
        }
    }
}

fn optional_usize(config: &Value, field: &'static str) -> Result<Option<usize>, String> {
    match config.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            let number = value.as_u64().ok_or_else(|| {
                format!("ai_prompt_compressor: '{field}' must be a non-negative integer")
            })?;
            usize::try_from(number).map(Some).map_err(|_| {
                format!("ai_prompt_compressor: '{field}' is too large for this platform")
            })
        }
    }
}

/// Estimate token count with the common ~4-characters-per-token heuristic for
/// English text. This is an approximation used for thresholds and reporting;
/// the plugin embeds no model tokenizer.
fn estimate_tokens(text: &str) -> usize {
    let chars = text.chars().count();
    if chars == 0 { 0 } else { chars.div_ceil(4) }
}

/// A tokenized unit of text.
struct Token<'a> {
    /// The exact source slice to emit when this token is kept.
    text: &'a str,
    /// Lowercased alphanumeric core (empty for `Verbatim` tokens).
    core_lower: String,
    /// `true` when this token is always kept (code, URL, number, identifier,
    /// pure punctuation, or a `preserve_tag` span).
    verbatim: bool,
    /// `true` when the whitespace immediately before this token contained a
    /// newline — used to keep paragraph breaks in the reconstructed text.
    leading_newline: bool,
}

/// Append `seg` to `out`, inserting a single separating space only when needed
/// to avoid gluing two non-whitespace characters at the boundary. `seg`'s own
/// internal whitespace is preserved exactly, so this is safe for verbatim
/// `preserve_tag` spans.
fn append_segment(out: &mut String, seg: &str) {
    if seg.is_empty() {
        return;
    }
    if let (Some(last), Some(first)) = (out.chars().last(), seg.chars().next())
        && !last.is_whitespace()
        && !first.is_whitespace()
    {
        out.push(' ');
    }
    out.push_str(seg);
}

/// Compress a plain text chunk to roughly `ratio` of its word-tokens.
fn statistical_compress(text: &str, ratio: f32) -> String {
    let tokens = tokenize(text);
    if tokens.is_empty() {
        return String::new();
    }

    // In-document frequency of each candidate word (rarer => more important).
    let mut freq: HashMap<&str, u32> = HashMap::new();
    for token in &tokens {
        if !token.verbatim {
            *freq.entry(token.core_lower.as_str()).or_insert(0) += 1;
        }
    }

    // Score every candidate word; collect critical (always-keep) indices.
    let word_indices: Vec<usize> = tokens
        .iter()
        .enumerate()
        .filter(|(_, t)| !t.verbatim)
        .map(|(i, _)| i)
        .collect();
    let word_count = word_indices.len();

    let mut keep = vec![false; tokens.len()];
    let mut scored: Vec<(usize, f32)> = Vec::with_capacity(word_count);
    let mut critical_count = 0usize;
    // A kept negation whose complement is dropped re-binds to the following
    // clause ("It is not urgent. Delete logs" => "not Delete logs"), so the
    // candidate word immediately after a negation is critical too.
    let mut force_next = false;
    for &i in &word_indices {
        let token = &tokens[i];
        let negation = is_negation(&token.core_lower);
        if negation || force_next {
            keep[i] = true;
            critical_count += 1;
            force_next = negation;
            continue;
        }
        scored.push((i, word_score(token, &freq)));
    }

    // Every token is verbatim (all code/URLs/numbers/identifiers) — there is
    // nothing to score or drop, so keep them all rather than panicking on
    // `clamp(1, 0)`. Both request-path hooks reach here, so this must not abort.
    if word_count == 0 {
        return reconstruct(&tokens, &keep);
    }

    // Keep at least one word; criticals count toward the budget.
    let target_keep = ((ratio * word_count as f32).ceil() as usize).clamp(1, word_count);
    let remaining = target_keep.saturating_sub(critical_count);
    if remaining > 0 {
        // Partial selection of the highest-scoring non-critical words. Ties fall
        // back to source order so output is deterministic.
        scored.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.0.cmp(&b.0))
        });
        for &(i, _) in scored.iter().take(remaining) {
            keep[i] = true;
        }
    }

    reconstruct(&tokens, &keep)
}

/// Compute an importance score for a candidate word. Higher = more likely kept.
fn word_score(token: &Token<'_>, freq: &HashMap<&str, u32>) -> f32 {
    let mut score = if is_stopword(&token.core_lower) {
        0.0
    } else {
        1.0
    };
    // Longer words tend to carry more meaning (capped so one long word can't
    // dominate).
    let len = token.core_lower.chars().count().min(12) as f32;
    score += len * 0.1;
    // Rarity: a word appearing once scores higher than a frequently repeated one.
    let count = freq.get(token.core_lower.as_str()).copied().unwrap_or(1);
    score += 1.0 / count as f32;
    // Proper-noun / entity signal: an original-case leading capital.
    if token
        .text
        .trim_start_matches(|c: char| !c.is_alphanumeric())
        .chars()
        .next()
        .is_some_and(|c| c.is_uppercase())
    {
        score += 0.5;
    }
    score
}

/// Split `text` into [`Token`]s, marking code / URLs / numbers / identifiers /
/// punctuation as verbatim. Whitespace boundaries are ASCII-only, which is UTF-8
/// safe because multi-byte sequences never contain ASCII bytes.
fn tokenize(text: &str) -> Vec<Token<'_>> {
    let bytes = text.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        // Skip the whitespace run preceding the next token.
        let mut had_newline = false;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            if bytes[i] == b'\n' {
                had_newline = true;
            }
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }

        let start = i;
        let rest = &text[start..];

        // Fenced code block: keep from ``` to the matching ``` verbatim.
        if rest.starts_with("```") {
            let after = start + 3;
            let end = text[after..]
                .find("```")
                .map(|p| after + p + 3)
                .unwrap_or(bytes.len());
            push_verbatim(&mut tokens, &text[start..end], had_newline);
            i = end;
            continue;
        }
        // Inline code span.
        if bytes[start] == b'`' {
            let after = start + 1;
            let end = text[after..]
                .find('`')
                .map(|p| after + p + 1)
                .unwrap_or(bytes.len());
            push_verbatim(&mut tokens, &text[start..end], had_newline);
            i = end;
            continue;
        }
        // URL: keep intact so paths/query strings are never mangled.
        if rest.starts_with("http://") || rest.starts_with("https://") {
            let end = scan_to_whitespace(bytes, start);
            push_verbatim(&mut tokens, &text[start..end], had_newline);
            i = end;
            continue;
        }

        // Ordinary whitespace-delimited unit.
        let end = scan_to_whitespace(bytes, start);
        let unit = &text[start..end];
        i = end;

        let core: &str =
            unit.trim_matches(|c: char| !(c.is_alphanumeric() || c == '_' || c == '\''));
        // `contains_url` catches URLs wrapped in punctuation — Markdown
        // `(https://…)`, `<https://…>`, `[text](https://…)` — that the
        // leading-scheme fast path above misses; such a token stays verbatim so
        // links are never scored and dropped.
        if core.is_empty() || is_protected_word(core) || contains_url(unit) {
            push_verbatim(&mut tokens, unit, had_newline);
        } else {
            tokens.push(Token {
                text: unit,
                core_lower: normalize_apostrophes(core.to_lowercase()),
                verbatim: false,
                leading_newline: had_newline,
            });
        }
    }
    tokens
}

fn scan_to_whitespace(bytes: &[u8], start: usize) -> usize {
    let mut j = start;
    while j < bytes.len() && !bytes[j].is_ascii_whitespace() {
        j += 1;
    }
    j
}

fn push_verbatim<'a>(tokens: &mut Vec<Token<'a>>, text: &'a str, leading_newline: bool) {
    tokens.push(Token {
        text,
        core_lower: String::new(),
        verbatim: true,
        leading_newline,
    });
}

/// True when `s` embeds an `http(s)://` URL, including when it is wrapped in
/// punctuation such as `(https://…)` or `<https://…>`.
fn contains_url(s: &str) -> bool {
    s.contains("http://") || s.contains("https://")
}

/// A word whose form should never be split or dropped: contains a digit, is an
/// acronym (2+ letters, all uppercase), or is a `snake_case` identifier.
fn is_protected_word(core: &str) -> bool {
    if core.contains('_') || core.chars().any(|c| c.is_ascii_digit()) {
        return true;
    }
    let letters = core.chars().filter(|c| c.is_alphabetic()).count();
    letters >= 2 && core.chars().all(|c| !c.is_alphabetic() || c.is_uppercase())
}

/// Rebuild text from the kept tokens, restoring single-space or newline breaks.
fn reconstruct(tokens: &[Token<'_>], keep: &[bool]) -> String {
    let mut out = String::new();
    let mut pending_newline = false;
    let mut first = true;
    for (i, token) in tokens.iter().enumerate() {
        if token.leading_newline {
            pending_newline = true;
        }
        let emit = token.verbatim || keep[i];
        if !emit {
            continue;
        }
        if !first {
            out.push(if pending_newline { '\n' } else { ' ' });
        }
        out.push_str(token.text);
        first = false;
        pending_newline = false;
    }
    out
}

/// Common English stop words — low base importance, dropped first.
fn is_stopword(word: &str) -> bool {
    matches!(
        word,
        "a" | "an"
            | "and"
            | "are"
            | "as"
            | "at"
            | "be"
            | "been"
            | "being"
            | "but"
            | "by"
            | "can"
            | "could"
            | "did"
            | "do"
            | "does"
            | "for"
            | "from"
            | "had"
            | "has"
            | "have"
            | "he"
            | "her"
            | "here"
            | "hers"
            | "him"
            | "his"
            | "how"
            | "i"
            | "if"
            | "in"
            | "into"
            | "is"
            | "it"
            | "its"
            | "just"
            | "may"
            | "me"
            | "might"
            | "my"
            | "of"
            | "on"
            | "or"
            | "our"
            | "out"
            | "over"
            | "own"
            | "she"
            | "should"
            | "so"
            | "some"
            | "such"
            | "than"
            | "that"
            | "the"
            | "their"
            | "them"
            | "then"
            | "there"
            | "these"
            | "they"
            | "this"
            | "those"
            | "to"
            | "too"
            | "up"
            | "very"
            | "was"
            | "we"
            | "were"
            | "what"
            | "when"
            | "where"
            | "which"
            | "while"
            | "who"
            | "will"
            | "with"
            | "would"
            | "you"
            | "your"
    )
}

/// Fold typographic apostrophes (U+2019, U+02BC) to ASCII `'` so contractions
/// pasted from word processors and phones ("don’t", "can’t") are recognized by
/// `is_negation` and the stop-word tables instead of being scored as ordinary
/// droppable words.
fn normalize_apostrophes(word: String) -> String {
    if word.contains(['\u{2019}', '\u{02bc}']) {
        word.replace(['\u{2019}', '\u{02bc}'], "'")
    } else {
        word
    }
}

/// Negations and their contractions — always kept to preserve meaning.
fn is_negation(word: &str) -> bool {
    if word.ends_with("n't") {
        return true;
    }
    matches!(
        word,
        "no" | "not"
            | "nor"
            | "none"
            | "never"
            | "neither"
            | "without"
            | "cannot"
            | "cant"
            | "dont"
            | "wont"
            | "isnt"
            | "arent"
    )
}

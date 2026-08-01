//! AI Response Guard Plugin
//!
//! Validates and filters HTTP LLM response content before it reaches the client.
//! Complements `ai_prompt_shield` (which guards inputs) by providing output-side
//! guardrails including PII detection in responses, keyword/phrase blocklists,
//! and response format validation.
//!
//! Built-in PII patterns: SSN, credit card, email, US phone, API keys, AWS keys,
//! IPv4 addresses, and IBAN (shared with ai_prompt_shield).
//!
//! Actions: reject (return error to client), redact (replace matches with placeholders),
//! or warn (add metadata/headers but pass through).
//!
//! Native gRPC responses are inspected only for methods an operator explicitly
//! enrolled under the `grpc` config block. Enrolled methods are decoded against
//! a compiled `FileDescriptorSet`, scanned, and — for `redact` — re-encoded and
//! re-verified before delivery. Everything the contract cannot cover safely
//! (unknown compression, malformed or oversized framing, unknown protobuf
//! fields, an unresolvable descriptor, a residual match after redaction) fails
//! closed for enforcing actions. Methods that were never enrolled are never
//! inspected opportunistically and never forced onto the buffered path.

use async_trait::async_trait;
use flate2::bufread::GzDecoder;
use flate2::write::GzEncoder;
use prost::Message as _;
use prost_reflect::{
    DescriptorPool, DynamicMessage, Kind, MapKey, MessageDescriptor, ReflectMessage,
    Value as ProtobufValue,
};
use regex::{NoExpand, Regex, RegexSet};
use serde_json::Value;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::io::{Read as _, Write as _};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, warn};

use super::utils::body_transform::is_json_content_type;
use super::utils::json_escape::escape_json_string;
use super::utils::sse::{
    SseReassembler, SseTextKind, is_text_event_stream_media_type,
    original_response_is_event_stream, parse_sse_data_frames, parse_sse_data_frames_checked,
};
use super::{Plugin, PluginResult, RequestContext};

static NEXT_RESPONSE_GUARD_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

/// JSON object keys that are structural metadata (IDs, timestamps, model
/// names, roles, etc.) and must never be redacted, even in `ScanMode::All`.
/// This protects timestamps and IDs that may incidentally match PII regexes.
const STRUCTURAL_KEY_COUNT: usize = 17;
const STRUCTURAL_KEYS: [&str; STRUCTURAL_KEY_COUNT] = [
    "id",
    "object",
    "created",
    "model",
    "role",
    "type",
    "index",
    "finish_reason",
    "stop_reason",
    "logprobs",
    "system_fingerprint",
    "usage",
    "input_tokens",
    "output_tokens",
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
];

const CONFIG_KEYS: &[&str] = &[
    "action",
    "pii_patterns",
    "custom_pii_patterns",
    "blocked_phrases",
    "blocked_patterns",
    "scan_fields",
    "redaction_placeholder",
    "max_scan_bytes",
    "require_json",
    "required_fields",
    "max_completion_length",
    "grpc",
];

/// Closed key set for the `grpc` config block.
pub const AI_RESPONSE_GUARD_GRPC_CONFIG_KEYS: &[&str] = &[
    "descriptor_path",
    "methods",
    "max_message_bytes",
    "max_messages",
];

/// Closed key set for one `grpc.methods` entry.
pub const AI_RESPONSE_GUARD_GRPC_METHOD_KEYS: &[&str] = &["response_type", "text_fields"];

/// Default per-message decoded/decompressed ceiling for one gRPC frame.
const DEFAULT_GRPC_MAX_MESSAGE_BYTES: usize = 1_048_576;

/// Default ceiling on the number of length-prefixed frames one buffered gRPC
/// response may carry. Server-streaming responses above this are uninspectable
/// rather than silently partially inspected.
const DEFAULT_GRPC_MAX_MESSAGES: usize = 64;

/// Recursion depth ceiling for the protobuf message walk.
const GRPC_MAX_MESSAGE_DEPTH: usize = 32;

/// Total value-node ceiling for one protobuf message walk.
const GRPC_MAX_MESSAGE_NODES: usize = 50_000;

const RESPONSE_VALIDATORS: &[&str] = &[
    "etag",
    "last-modified",
    "content-digest",
    "repr-digest",
    "digest",
    "content-md5",
];

/// Action to take when guarded content is detected in the response.
#[derive(Debug, Clone, PartialEq, Eq)]
enum GuardAction {
    Reject,
    Redact,
    Warn,
}

/// A named regex pattern for content detection.
#[derive(Debug)]
struct ContentPattern {
    name: String,
    regex: Regex,
    /// Pre-rendered redaction placeholder for this pattern, with `{type}`
    /// already substituted with `name`. Built once at config-load time so
    /// `redact_text` does not re-render the template per pattern per call.
    placeholder: String,
}

/// How to scan the response body.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ScanMode {
    /// Only scan supported client-visible completion and tool-call fields.
    Content,
    /// Scan the entire response body as text.
    All,
}

pub struct AiResponseGuard {
    instance_id: u64,
    action: GuardAction,
    pii_patterns: Vec<ContentPattern>,
    blocked_phrases: Vec<ContentPattern>,
    /// All patterns (PII + blocked phrases) compiled into a single DFA for
    /// O(text_len) detection regardless of pattern count. Indices align with
    /// `pii_patterns ++ blocked_phrases`.
    detection_set: RegexSet,
    /// Total count of detection patterns (pii_patterns.len() + blocked_phrases.len()).
    /// Cached so we can short-circuit when no detection patterns are configured.
    detection_pattern_count: usize,
    scan_mode: ScanMode,
    max_scan_bytes: usize,
    /// True when action is Redact — enables transform_response_body.
    needs_body_transform: bool,
    /// True when the plugin has any active validation rule (patterns, phrases,
    /// `require_json`, `required_fields`, or `max_completion_length`). Drives
    /// response-body buffering — when no rule applies, the plugin is a no-op.
    has_validation_rules: bool,
    /// Optional: require response to be valid JSON.
    require_json: bool,
    /// Optional: required top-level JSON fields.
    required_fields: Vec<String>,
    /// Maximum allowed completion length in characters (0 = unlimited).
    max_completion_length: usize,
    /// Native-gRPC inspection contract. `None` when the operator did not
    /// configure a `grpc` block, which keeps every gRPC response outside this
    /// plugin's scope (no buffering vote, no inspection, no transform).
    grpc: Option<GrpcInspection>,
}

/// One enrolled gRPC method's response inspection contract, after the
/// descriptor pool resolved it.
struct GrpcMethodInspection {
    descriptor: MessageDescriptor,
    /// Pre-split dotted field paths. `None` means "every string field,
    /// recursively" (bounded by the walk budgets).
    text_fields: Option<Vec<Vec<String>>>,
}

/// Runtime view of the `grpc` config block.
struct GrpcInspection {
    /// Resolved per-method contracts. Empty when the descriptor dependency is
    /// unavailable on this node.
    methods: HashMap<String, GrpcMethodInspection>,
    /// Every method path the operator enrolled, independent of whether the
    /// descriptor file could be read. Enrollment is what makes a response
    /// governed, so a missing descriptor fails closed instead of silently
    /// un-enrolling the method.
    enrolled_methods: HashSet<String>,
    max_message_bytes: usize,
    max_messages: usize,
    dependency_unavailable: bool,
}

impl GrpcInspection {
    fn enrolls(&self, method_path: &str) -> bool {
        self.enrolled_methods.contains(method_path)
    }

    fn method(&self, method_path: &str) -> Option<&GrpcMethodInspection> {
        self.methods.get(method_path)
    }
}

/// Config-shape view of the `grpc` block, before descriptor resolution.
struct GrpcMethodShape {
    response_type: String,
    text_fields: Option<Vec<Vec<String>>>,
}

struct GrpcShape {
    descriptor_path: String,
    methods: HashMap<String, GrpcMethodShape>,
    max_message_bytes: usize,
    max_messages: usize,
}

/// Whether a constructor may open node-local descriptor files.
#[derive(Clone, Copy)]
enum DescriptorLoadMode {
    /// Runtime construction on a data-plane node: read the descriptor.
    Runtime,
    /// Admin / CP admission: validate the config shape only.
    ShapeOnly,
}

/// Built-in PII pattern definitions (shared with ai_prompt_shield and
/// ai_transcript_audit via [`crate::plugins::utils::ai_pii`]).
fn builtin_pii_pattern(name: &str) -> Option<&'static str> {
    crate::plugins::utils::ai_pii::builtin_pii_pattern(name)
}

impl AiResponseGuard {
    pub fn new(config: &Value) -> Result<Self, String> {
        Self::new_inner(config, DescriptorLoadMode::Runtime)
    }

    /// Validate configuration shape without opening node-local descriptor
    /// files. Mode-aware file dependency validation is performed separately by
    /// `GatewayConfig::validate_plugin_file_dependencies`.
    pub fn validate_config(config: &Value) -> Result<(), String> {
        Self::new_shape_only(config).map(|_| ())
    }

    /// Build an instance from configuration shape alone. The gRPC enrollment
    /// set — which is what drives buffering and fail-closed behavior — comes
    /// from the config shape, not from the descriptor file.
    pub fn new_shape_only(config: &Value) -> Result<Self, String> {
        Self::new_inner(config, DescriptorLoadMode::ShapeOnly)
    }

    fn new_inner(config: &Value, descriptor_mode: DescriptorLoadMode) -> Result<Self, String> {
        if !config.is_object() {
            return Err("ai_response_guard: config must be an object".to_string());
        }
        reject_unknown_keys(config, CONFIG_KEYS, "config")?;

        let action = match optional_string(config, "action")?.unwrap_or("reject") {
            "reject" => GuardAction::Reject,
            "redact" => GuardAction::Redact,
            "warn" => GuardAction::Warn,
            other => {
                return Err(format!(
                    "ai_response_guard: 'action' must be one of 'reject', 'redact', or 'warn', got {other:?}"
                ));
            }
        };

        let scan_mode = match optional_string(config, "scan_fields")?.unwrap_or("content") {
            "content" => ScanMode::Content,
            "all" => ScanMode::All,
            other => {
                return Err(format!(
                    "ai_response_guard: 'scan_fields' must be one of 'content' or 'all', got {other:?}"
                ));
            }
        };

        let redaction_template = optional_string(config, "redaction_placeholder")?
            .unwrap_or("[REDACTED:{type}]")
            .to_string();

        let max_scan_bytes =
            optional_positive_usize(config, "max_scan_bytes")?.unwrap_or(1_048_576);

        // Build PII pattern list
        let pii_pattern_names: Vec<String> =
            optional_string_vec(config, "pii_patterns")?.unwrap_or_default();

        let mut pii_patterns: Vec<ContentPattern> = Vec::new();

        for name in &pii_pattern_names {
            if let Some(regex_str) = builtin_pii_pattern(name) {
                match Regex::new(regex_str) {
                    Ok(regex) => {
                        let full_name = format!("pii:{}", name);
                        let placeholder = redaction_template.replace("{type}", &full_name);
                        pii_patterns.push(ContentPattern {
                            name: full_name,
                            regex,
                            placeholder,
                        });
                    }
                    Err(e) => {
                        // Built-in pattern failures are fatal so the operator
                        // is alerted instead of silently losing detection
                        // coverage. Symmetric with custom-pattern handling.
                        return Err(format!(
                            "ai_response_guard: failed to compile built-in PII pattern '{}': {}",
                            name, e,
                        ));
                    }
                }
            } else {
                return Err(format!(
                    "ai_response_guard: unknown built-in PII pattern '{}'",
                    name,
                ));
            }
        }

        // Add custom PII patterns
        if let Some(custom) = optional_array(config, "custom_pii_patterns")? {
            for (idx, entry) in custom.iter().enumerate() {
                if !entry.is_object() {
                    return Err(format!(
                        "ai_response_guard: 'custom_pii_patterns[{idx}]' must be an object"
                    ));
                }
                reject_unknown_keys(
                    entry,
                    &["name", "regex"],
                    &format!("custom_pii_patterns[{idx}]"),
                )?;
                let name = required_non_empty_string(entry, "custom_pii_patterns", idx, "name")?;
                let regex_str =
                    required_non_empty_string(entry, "custom_pii_patterns", idx, "regex")?;
                match Regex::new(regex_str) {
                    Ok(regex) => {
                        let full_name = format!("pii:{}", name);
                        let placeholder = redaction_template.replace("{type}", &full_name);
                        pii_patterns.push(ContentPattern {
                            name: full_name,
                            regex,
                            placeholder,
                        });
                    }
                    Err(e) => {
                        return Err(format!(
                            "ai_response_guard: failed to compile custom PII pattern '{}': {}",
                            name, e,
                        ));
                    }
                }
            }
        }

        // Build blocked phrases list
        let mut blocked_phrases: Vec<ContentPattern> = Vec::new();
        if let Some(phrases) = optional_string_vec(config, "blocked_phrases")? {
            for (i, phrase) in phrases.iter().enumerate() {
                let phrase_str = phrase.as_str();
                if phrase_str.is_empty() {
                    return Err(format!(
                        "ai_response_guard: 'blocked_phrases[{i}]' must not be empty"
                    ));
                }
                // Treat as case-insensitive literal match
                let escaped = regex::escape(phrase_str);
                match Regex::new(&format!("(?i){}", escaped)) {
                    Ok(regex) => {
                        // Never derive a public identifier from the literal: the
                        // identifier appears in placeholders, metadata, logs,
                        // and reject bodies. Position is stable within a config
                        // and reveals no configured secret phrase.
                        let name = format!("blocked_phrase:{i}");
                        let placeholder = redaction_template.replace("{type}", &name);
                        blocked_phrases.push(ContentPattern {
                            name,
                            regex,
                            placeholder,
                        });
                    }
                    Err(e) => {
                        return Err(format!(
                            "ai_response_guard: failed to compile blocked phrase {}: {}",
                            i, e,
                        ));
                    }
                }
            }
        }

        // Build blocked regex patterns
        if let Some(patterns) = optional_array(config, "blocked_patterns")? {
            for (idx, entry) in patterns.iter().enumerate() {
                if !entry.is_object() {
                    return Err(format!(
                        "ai_response_guard: 'blocked_patterns[{idx}]' must be an object"
                    ));
                }
                reject_unknown_keys(
                    entry,
                    &["name", "regex"],
                    &format!("blocked_patterns[{idx}]"),
                )?;
                let name = required_non_empty_string(entry, "blocked_patterns", idx, "name")?;
                let regex_str = required_non_empty_string(entry, "blocked_patterns", idx, "regex")?;
                match Regex::new(regex_str) {
                    Ok(regex) => {
                        let placeholder = redaction_template.replace("{type}", name);
                        blocked_phrases.push(ContentPattern {
                            name: name.to_string(),
                            regex,
                            placeholder,
                        });
                    }
                    Err(e) => {
                        return Err(format!(
                            "ai_response_guard: failed to compile blocked pattern '{}': {}",
                            name, e,
                        ));
                    }
                }
            }
        }

        let require_json = optional_bool(config, "require_json")?.unwrap_or(false);

        let required_fields: Vec<String> =
            optional_string_vec(config, "required_fields")?.unwrap_or_default();
        for (idx, field) in required_fields.iter().enumerate() {
            if field.is_empty() {
                return Err(format!(
                    "ai_response_guard: 'required_fields[{idx}]' must not be empty"
                ));
            }
        }

        let max_completion_length = optional_usize(config, "max_completion_length")?.unwrap_or(0);

        let grpc = load_grpc_inspection(config, descriptor_mode)?;
        if grpc.is_some() {
            // `require_json` / `required_fields` describe a JSON document
            // model that a protobuf message can never satisfy. Accepting the
            // combination would leave one of the two response families
            // unenforced without the operator ever being told.
            if require_json {
                return Err(
                    "ai_response_guard: 'require_json' is JSON-only and cannot be combined with 'grpc'"
                        .to_string(),
                );
            }
            if !required_fields.is_empty() {
                return Err(
                    "ai_response_guard: 'required_fields' is JSON-only and cannot be combined with 'grpc'"
                        .to_string(),
                );
            }
            if pii_patterns.is_empty() && blocked_phrases.is_empty() && max_completion_length == 0 {
                return Err(
                    "ai_response_guard: 'grpc' requires at least one detection pattern, blocked phrase, or 'max_completion_length'"
                        .to_string(),
                );
            }
        }

        let has_validation_rules = !pii_patterns.is_empty()
            || !blocked_phrases.is_empty()
            || require_json
            || !required_fields.is_empty()
            || max_completion_length > 0;

        if !has_validation_rules {
            return Err(
                "ai_response_guard: no patterns, phrases, or validation rules configured — plugin will have no effect"
                    .to_string(),
            );
        }

        let needs_body_transform = action == GuardAction::Redact
            && (!pii_patterns.is_empty() || !blocked_phrases.is_empty());

        // Build a single combined RegexSet for O(text_len) detection.
        // Patterns are already validated above (each compiled successfully
        // as an individual Regex), so RegexSet construction cannot fail
        // for syntax — but we still propagate any error defensively.
        let detection_pattern_count = pii_patterns.len() + blocked_phrases.len();
        let detection_set = RegexSet::new(
            pii_patterns
                .iter()
                .chain(blocked_phrases.iter())
                .map(|p| p.regex.as_str()),
        )
        .map_err(|e| {
            format!(
                "ai_response_guard: failed to build detection RegexSet: {}",
                e
            )
        })?;

        Ok(Self {
            instance_id: NEXT_RESPONSE_GUARD_INSTANCE_ID.fetch_add(1, Ordering::Relaxed),
            action,
            pii_patterns,
            blocked_phrases,
            detection_set,
            detection_pattern_count,
            scan_mode,
            max_scan_bytes,
            needs_body_transform,
            has_validation_rules,
            require_json,
            required_fields,
            max_completion_length,
            grpc,
        })
    }

    /// Look up the pattern name at the given combined-index position
    /// (`pii_patterns ++ blocked_phrases`).
    fn pattern_name(&self, idx: usize) -> Option<&str> {
        let pii_len = self.pii_patterns.len();
        if idx < pii_len {
            self.pii_patterns.get(idx).map(|p| p.name.as_str())
        } else {
            self.blocked_phrases
                .get(idx - pii_len)
                .map(|p| p.name.as_str())
        }
    }

    /// Extract client-visible or executable completion text from supported AI
    /// response families.
    ///
    /// Adjacent text-bearing parts of one content array (and adjacent
    /// Anthropic text blocks / Gemini parts) are joined into one fragment, so
    /// detection and length enforcement see the logical completion the client
    /// renders rather than each part in isolation. Tool/function `arguments`
    /// contribute both the raw string and its decoded JSON tokens.
    fn extract_completion_texts<'a>(&self, json: &'a Value) -> Vec<Cow<'a, str>> {
        let mut texts = Vec::new();

        // OpenAI chat/completions, including multimodal content parts, refusal
        // strings, and tool calls. Buffered delta-shaped payloads use the same
        // selectors.
        if let Some(choices) = json.get("choices").and_then(|c| c.as_array()) {
            for choice in choices {
                collect_string_value(choice.get("text"), &mut texts);
                for container in [choice.get("message"), choice.get("delta")]
                    .into_iter()
                    .flatten()
                {
                    collect_content_value(container.get("content"), &mut texts);
                    collect_string_value(container.get("refusal"), &mut texts);
                    collect_function_value(container.get("function_call"), &mut texts);
                    if let Some(tool_calls) = container.get("tool_calls").and_then(Value::as_array)
                    {
                        for tool_call in tool_calls {
                            collect_function_value(tool_call.get("function"), &mut texts);
                        }
                    }
                }
            }
        }

        // OpenAI Responses API buffered output.
        collect_string_value(json.get("output_text"), &mut texts);
        if let Some(output) = json.get("output").and_then(Value::as_array) {
            for item in output {
                collect_string_value(item.get("name"), &mut texts);
                collect_argument_value(item.get("arguments"), &mut texts);
                collect_content_value(item.get("content"), &mut texts);
            }
        }

        // Anthropic: content[].text, joining adjacent text blocks.
        if let Some(content) = json.get("content").and_then(|c| c.as_array()) {
            push_joined_adjacent_texts(
                content.iter().map(|block| {
                    if block.get("type").and_then(|t| t.as_str()) == Some("text") {
                        block.get("text").and_then(|t| t.as_str())
                    } else {
                        None
                    }
                }),
                &mut texts,
            );
        }

        // Google Gemini: candidates[].content.parts[].text, joined per candidate.
        if let Some(candidates) = json.get("candidates").and_then(|c| c.as_array()) {
            for candidate in candidates {
                if let Some(parts) = candidate
                    .get("content")
                    .and_then(|c| c.get("parts"))
                    .and_then(|p| p.as_array())
                {
                    push_joined_adjacent_texts(
                        parts
                            .iter()
                            .map(|part| part.get("text").and_then(|t| t.as_str())),
                        &mut texts,
                    );
                }
            }
        }

        texts
    }

    /// Detect content matches against all patterns. Returns names of detected matches.
    /// Uses a single `RegexSet` DFA pass per text fragment, O(text_len)
    /// regardless of pattern count.
    ///
    /// Generic over `AsRef<str>` so callers can pass borrowed `&str` slices
    /// (`ScanMode::Content`) or `Cow<str>` text (`ScanMode::All`, which must
    /// collect stringified JSON numbers that have no backing `&str`).
    fn detect_matches<S: AsRef<str>>(&self, texts: &[S]) -> Vec<String> {
        if self.detection_pattern_count == 0 {
            return Vec::new();
        }
        let mut hit = vec![false; self.detection_pattern_count];
        for text in texts {
            for idx in self.detection_set.matches(text.as_ref()).into_iter() {
                hit[idx] = true;
            }
        }
        let mut detected = Vec::new();
        for (idx, &h) in hit.iter().enumerate() {
            if h && let Some(name) = self.pattern_name(idx) {
                detected.push(name.to_string());
            }
        }
        detected
    }

    /// `ScanMode::All` JSON detection: the union of two passes over the body.
    ///
    /// 1. Decoded walker (`collect_decoded_json_strings`): scans each JSON token
    ///    after serde has resolved `\uXXXX` and other escapes, so escaped PII in
    ///    string values, object keys, and numeric scalars is caught exactly as
    ///    the client will see it (issue #1720).
    /// 2. Raw-body pass: runs the `RegexSet` over the serialized response bytes.
    ///    The original all-mode scan was raw-only, and three coverage cases
    ///    depend on it: operator custom `blocked_patterns` that span JSON context
    ///    (e.g. `"role"\s*:\s*"tool"`), which testing key and value as separate
    ///    tokens never reconstructs; numeric/scalar shapes serialized only in the
    ///    raw bytes; and duplicate object members, whose overwritten value is
    ///    dropped from the parsed `Value` but is still delivered to the client.
    ///
    /// Unioning the two only ever *adds* detections, so this strictly hardens
    /// all-mode coverage. `raw` may be `None` when the serialized bytes are not
    /// valid UTF-8 (the body still parsed via `from_slice`), in which case only
    /// the decoded pass runs.
    ///
    /// Accepted trade-off: because pass 1 evaluates each decoded value in
    /// isolation, an *anchored* custom `blocked_pattern` (e.g. `^done$`) that an
    /// operator authored against the whole serialized body will additionally fire
    /// on a lone scalar value (`{"finish_reason":"done"}`). This is intentional
    /// and load-bearing for `ScanMode::All`: the decoded per-value pass is exactly
    /// what closes the escaped-PII gap (#1720) — a value encoded as `done`
    /// must be caught after decoding — so restricting custom patterns to
    /// whole-body-only would reopen that bypass for them. Operators who need
    /// strictly whole-body matching can keep the anchor and rely on raw-pass
    /// semantics in `ScanMode::Content`, or write the pattern to include the JSON
    /// context (`"finish_reason"\s*:\s*"done"`) so the lone token does not match.
    fn detect_matches_in_decoded_json(&self, json: &Value, raw: Option<&str>) -> Vec<String> {
        if self.detection_pattern_count == 0 {
            return Vec::new();
        }
        let mut hit = vec![false; self.detection_pattern_count];
        // Pass 1: decoded tokens, plus decoded tool/function-argument tokens
        // so scan-all keeps parity with content mode on nested JSON escapes.
        let mut texts: Vec<Cow<'_, str>> = Vec::new();
        collect_decoded_json_strings(json, &mut texts);
        collect_decoded_argument_tokens(json, &mut texts);
        for text in &texts {
            for idx in self.detection_set.matches(text.as_ref()).into_iter() {
                hit[idx] = true;
            }
        }
        // Pass 2: raw serialized body (cross-token / contextual / duplicate-key).
        if let Some(raw) = raw {
            for idx in self.detection_set.matches(raw).into_iter() {
                hit[idx] = true;
            }
        }
        let mut detected = Vec::new();
        for (idx, &h) in hit.iter().enumerate() {
            if h && let Some(name) = self.pattern_name(idx) {
                detected.push(name.to_string());
            }
        }
        detected
    }

    /// `ScanMode::All` SSE detection: the union of decoded parsed frames and a
    /// raw-body pass.
    ///
    /// `parse_sse_data_frames` silently drops `data:` payloads that are not JSON
    /// (a plain `data: user@example.com` frame, or malformed JSON), so scanning
    /// only the parsed frames would let blocked content in unparseable SSE data
    /// bypass scan-all policies. Running the `RegexSet` over the raw body too
    /// restores the original whole-body coverage for those payloads, while the
    /// decoded-frame pass adds `\uXXXX`-escaped detection (issue #1720).
    /// `raw` is `None` only when the body is not valid UTF-8.
    fn detect_matches_in_decoded_sse_frames(
        &self,
        frames: &[Value],
        raw: Option<&str>,
    ) -> Vec<String> {
        if self.detection_pattern_count == 0 {
            return Vec::new();
        }
        let mut hit = vec![false; self.detection_pattern_count];
        let mut texts: Vec<Cow<'_, str>> = Vec::new();
        for frame in frames {
            collect_decoded_json_strings(frame, &mut texts);
            collect_decoded_argument_tokens(frame, &mut texts);
        }
        for text in &texts {
            for idx in self.detection_set.matches(text.as_ref()).into_iter() {
                hit[idx] = true;
            }
        }
        // Scan the coherent client-visible/executable stream as well as each
        // decoded frame. In particular, Responses API argument deltas are a
        // serialized JSON document that may span events; only reassembly can
        // expose JSON escapes such as `\u0040` to the detector.
        let accumulated = self.extract_sse_completion_texts(frames);
        for text in &accumulated {
            for idx in self.detection_set.matches(text).into_iter() {
                hit[idx] = true;
            }
        }
        if let Some(raw) = raw {
            for idx in self.detection_set.matches(raw).into_iter() {
                hit[idx] = true;
            }
        }
        let mut detected = Vec::new();
        for (idx, &h) in hit.iter().enumerate() {
            if h && let Some(name) = self.pattern_name(idx) {
                detected.push(name.to_string());
            }
        }
        detected
    }

    /// Replace all pattern matches with the redaction placeholder.
    /// Placeholders are pre-rendered at construction time so each call is one
    /// `replace_all` per pattern, with no template formatting on the hot path.
    ///
    /// The placeholder is wrapped in `regex::NoExpand` so `$`-sequences in it
    /// (e.g. an operator pattern name like `cost $5`, or a malicious `$1` in
    /// `redaction_placeholder`) are emitted literally rather than being
    /// interpreted as capture-group references by the regex `Replacer`.
    fn redact_text(&self, text: &str) -> String {
        let mut result = text.to_string();
        for pattern in self.pii_patterns.iter().chain(self.blocked_phrases.iter()) {
            result = pattern
                .regex
                .replace_all(&result, NoExpand(pattern.placeholder.as_str()))
                .to_string();
        }
        result
    }

    /// [`Self::redact_text`] for a WHOLE client-visible replacement body, written
    /// through ceiling-bounded sinks.
    ///
    /// `redact_text` is fine for one JSON string or one protobuf field — those are
    /// scalars of an already-charged document. It is not fine for a plain-text or
    /// unparseable-JSON response body, where its output IS the replacement: a
    /// placeholder-expanding pattern set would materialise the complete expanded
    /// `String` and only then be measured (GHSA-pwcm-6rh8-f2gh).
    ///
    /// The pattern passes stay SEQUENTIAL — pass `n+1` reads pass `n`'s output,
    /// exactly as `redact_text` does, because a placeholder rendered by one
    /// pattern may legitimately be rewritten by a later one. Two buffers are
    /// therefore live at once, so they share ONE ceiling: each pass writes under
    /// the room its still-live input leaves. That keeps this producer's transient
    /// scratch inside a single retained ceiling, which is what makes the module's
    /// two-ceiling peak (old body + one window) true for this path as well.
    ///
    /// `None` means a pass was refused; the caller leaves the response unchanged,
    /// the same outcome an over-ceiling final document already had.
    fn redact_text_bounded(&self, text: &str, ceiling: usize) -> Option<Vec<u8>> {
        use crate::proxy::response_buffer_budget::{BoundedResponseBodySink, bounded_vec_from};

        let mut current: Option<Vec<u8>> = None;
        for pattern in self.pii_patterns.iter().chain(self.blocked_phrases.iter()) {
            // Pass 1 reads the already-charged response body, so the whole
            // ceiling is available to it; later passes read a scratch buffer that
            // is still resident, so only the remainder is. Charge CAPACITY, not
            // length: geometric growth leaves slack above `len()`, and that
            // slack is still resident inside the covering window
            // (GHSA-pwcm-6rh8-f2gh). `checked_sub` fails closed on underflow /
            // saturation when a prior pass somehow retained more than the
            // shared ceiling.
            let room = match current.as_ref() {
                Some(buffer) => ceiling.checked_sub(buffer.capacity())?,
                None => ceiling,
            };
            let mut sink = BoundedResponseBodySink::with_ceiling(room);
            {
                let input: &str = match current.as_deref() {
                    // Every pass writes UTF-8 (matches land on character
                    // boundaries and placeholders are `str`), so this cannot
                    // fail; it is checked rather than assumed.
                    Some(bytes) => std::str::from_utf8(bytes).ok()?,
                    None => text,
                };
                if !write_pattern_replaced(
                    &mut sink,
                    &pattern.regex,
                    pattern.placeholder.as_str(),
                    input,
                ) {
                    return None;
                }
            }
            current = Some(sink.finish()?);
        }
        // No configured pattern: the redactor is the identity, exactly as
        // `redact_text` is, and the caller's unchanged-comparison handles it.
        match current {
            Some(redacted) => Some(redacted),
            None => bounded_vec_from(text.as_bytes(), ceiling),
        }
    }

    /// Remove every rendered redaction placeholder from `text`.
    ///
    /// The residual re-scan (`redact_leaves_residual`) runs the detection
    /// `RegexSet` over the body *after* redaction. Placeholders embed the
    /// pattern identity — e.g. the default template makes a blocked phrase
    /// render as `[REDACTED:blocked_phrase:0]`, and PII/custom names render as
    /// `[REDACTED:pii:ssn]` / `[REDACTED:<custom name>]`. Those
    /// marker strings can themselves match a configured expression (for
    /// example, a custom name can coincide with its own regex), making a
    /// fully-redactable body look like it still carries residual content and
    /// forcing a false 502.
    /// Stripping the placeholders before the residual scan looks only at the
    /// bytes that will actually be delivered, not at text the redactor itself
    /// wrote. Placeholders are fixed strings rendered at construction, so this
    /// is a plain substring removal with no regex on the hot path.
    fn strip_known_placeholders(&self, text: &str) -> String {
        let mut result = text.to_string();
        for pattern in self.pii_patterns.iter().chain(self.blocked_phrases.iter()) {
            if result.contains(pattern.placeholder.as_str()) {
                result = result.replace(pattern.placeholder.as_str(), "");
            }
        }
        result
    }

    /// `ScanMode::All` redact mode: after applying the same redaction the
    /// response transform performs, decide whether any *unredactable* PII still
    /// remains, so the caller can fail closed (reject) instead of forwarding the
    /// body while reporting it `redacted`.
    ///
    /// The all-mode redactor rewrites JSON string values (with serialized
    /// argument documents handled structurally), but cannot rewrite PII carried
    /// in an object key, a numeric scalar, a cross-token/contextual custom
    /// pattern, or a duplicate-key value dropped from the parsed tree. Because
    /// all-mode detection now unions a raw-body pass, those are detected — so
    /// without this re-scan the plugin would emit false "redacted" telemetry
    /// while still delivering the PII.
    ///
    /// This mirrors `redact_json_strings`' structural carve-out: top-level
    /// structural scalar values (`model`, `id`, token counts, …) are deliberately
    /// preserved even when they incidentally match a PII regex, so they are NOT
    /// residual leaks. To run the same union detection without those preserved
    /// scalars re-triggering, the re-scan is done on a copy whose top-level
    /// structural scalars are blanked to an empty string. Blanking only the
    /// scalar values keeps the surrounding JSON structure intact, so a contextual
    /// pattern such as `"role"\s*:` still matches while a preserved
    /// `"created": 1700000000` no longer does.
    ///
    /// The residual scan also strips the redactor's own placeholder markers
    /// (`strip_known_placeholders`) before matching: a successfully redacted
    /// custom pattern can render an identifier that matches its own regex. The
    /// marker would otherwise report a false residual leak (turning a fully
    /// redacted body into a spurious 502).
    fn redact_leaves_residual(&self, original: &Value) -> bool {
        if self.detection_pattern_count == 0 {
            return false;
        }
        let mut redacted = original.clone();
        self.redact_all_strings_with_argument_shield(&mut redacted);
        blank_top_level_structural_scalars(&mut redacted);

        // Union the same two passes as `detect_matches_in_decoded_json`, but run
        // each over text with the redactor's placeholder markers removed so the
        // markers cannot re-trigger their own pattern.
        let mut texts: Vec<Cow<'_, str>> = Vec::new();
        collect_decoded_json_strings(&redacted, &mut texts);
        collect_decoded_argument_tokens(&redacted, &mut texts);
        for text in &texts {
            let cleaned = self.strip_known_placeholders(text.as_ref());
            if self.detection_set.is_match(&cleaned) {
                return true;
            }
        }
        let serialized = self.strip_known_placeholders(&redacted.to_string());
        self.detection_set.is_match(&serialized)
    }

    /// `ScanMode::Content` redact mode: decide whether the structured redactor
    /// would leave detectable content in the extracted completion texts, so
    /// the caller can fail closed (reject) instead of forwarding the body
    /// while reporting it `redacted`. Two shapes are detectable but not
    /// rewritable: a match that exists only across adjacent content-array
    /// parts (each part alone is clean, so per-part redaction rewrites
    /// nothing), and tool-argument content the argument redactor cannot
    /// rewrite (a decoded object key or numeric scalar).
    fn content_redact_leaves_residual(&self, original: &Value) -> bool {
        if self.detection_pattern_count == 0 {
            return false;
        }
        let mut redacted = original.clone();
        self.redact_response_json(&mut redacted);
        let texts = self.extract_completion_texts(&redacted);
        texts.iter().any(|text| {
            self.detection_set
                .is_match(&self.strip_known_placeholders(text.as_ref()))
        })
    }

    /// `ScanMode::All` redact mode, SSE bodies: decide whether redaction would
    /// leave residual detectable content, so the caller can fail closed instead
    /// of forwarding the original bytes while reporting them `redacted`.
    ///
    /// The SSE transform (`redact_sse_body`) only rewrites `data:` payloads that
    /// parse as JSON. A plaintext or malformed `data:` frame (e.g.
    /// `data: contact user@example.com`) is matched by the raw-body union in
    /// detection but cannot be rewritten. This mirrors the JSON
    /// `redact_leaves_residual` fail-closed: run the same redaction the transform
    /// performs, then re-scan the client-visible candidate (with the redactor's
    /// own placeholder markers and preserved structural scalars excluded). If
    /// unrewritable content still matches, the caller must reject.
    /// `ceiling` is this response's retained ceiling; the candidate is built
    /// under a budget window of that size, reserved before it exists.
    fn redact_sse_leaves_residual(&self, body: &[u8], ceiling: usize) -> bool {
        if self.detection_pattern_count == 0 {
            return false;
        }
        // The candidate here is a COMPLETE would-be client-visible body, built
        // during INSPECTION — before any producer phase has opened a transform
        // window. Building it against the process fallback ceiling would leave a
        // full-size attacker-shaped replacement resident beside the response body
        // with nothing charged for it, which is exactly the aggregate-bound
        // bypass this advisory closes. So a window sized to THIS response's
        // retained ceiling is reserved first and released as soon as the scan is
        // done, keeping the peak at the documented two ceilings; a budget that
        // cannot admit it fails closed (treated as residual) rather than
        // materialising the candidate anyway (GHSA-pwcm-6rh8-f2gh).
        let Some(window) =
            crate::proxy::response_buffer_budget::ResponseTransformWindow::open(ceiling)
        else {
            return true;
        };
        // Scan the exact bytes the client would receive: transformed output
        // when redaction changed an event, otherwise the original framing.
        // The residual pass masks only preserved top-level structural scalar
        // spans, so duplicate keys and formatting remain visible and matches in
        // cross-event, key, numeric, or non-data content still fail closed.
        let redacted = self.redact_sse_body(body, window.window_bytes());
        let residual = self.sse_body_has_residual(redacted.as_deref().unwrap_or(body));
        drop(redacted);
        drop(window);
        residual
    }

    /// Re-scan an SSE body produced by [`Self::redact_sse_body`]. Scan-all
    /// redaction deliberately preserves top-level structural scalar values in
    /// each JSON event, matching the buffered JSON path. Blank those values in
    /// both decoded and raw/contextual passes so an IP-shaped `id` does not
    /// cause a false residual, while keys, numbers outside the carve-out,
    /// non-`data:` fields, and cross-token patterns remain fail-closed.
    fn sse_body_has_residual(&self, redacted: &[u8]) -> bool {
        let Ok(redacted_str) = std::str::from_utf8(redacted) else {
            // Redacted output is not valid UTF-8 — cannot re-scan safely, so
            // fail closed rather than risk forwarding undetectable residual.
            return true;
        };
        let parsed = parse_sse_data_frames_checked(redacted);
        if !parsed.fully_parsed {
            return true;
        }
        let mut frames = parsed.frames;
        if self.scan_mode == ScanMode::Content {
            let accumulated = self.extract_sse_completion_texts(&frames);
            return accumulated.iter().any(|text| {
                self.detection_set
                    .is_match(&self.strip_known_placeholders(text))
            });
        }

        // Reassemble while event routing metadata (`type`, indexes) is still
        // present. Structural masking is only for the decoded-token and raw
        // residual passes; doing it first would hide Responses delta kinds and
        // let a match split across their argument events escape this re-scan.
        let accumulated = self.extract_sse_completion_texts(&frames);

        for frame in &mut frames {
            blank_top_level_structural_scalars(frame);
        }
        let mut texts: Vec<Cow<'_, str>> = Vec::new();
        for frame in &frames {
            collect_decoded_json_strings(frame, &mut texts);
            collect_decoded_argument_tokens(frame, &mut texts);
        }
        for text in &texts {
            let cleaned = self.strip_known_placeholders(text.as_ref());
            if self.detection_set.is_match(&cleaned) {
                return true;
            }
        }

        for text in &accumulated {
            let cleaned = self.strip_known_placeholders(text);
            if self.detection_set.is_match(&cleaned) {
                return true;
            }
        }

        // Keep the raw/contextual pass without letting preserved structural
        // scalar values re-trigger it. Mask only their exact raw byte spans:
        // canonicalizing parsed frames here would drop duplicate members or
        // whitespace that the client still receives when no transform occurs.
        let Some(sanitized) = mask_sse_top_level_structural_scalars(redacted_str) else {
            return true;
        };
        let cleaned_raw = self.strip_known_placeholders(&sanitized);
        self.detection_set.is_match(&cleaned_raw)
    }

    fn redact_string_value(&self, value: &mut Value) {
        let Some(text) = value.as_str() else {
            return;
        };
        let redacted = self.redact_text(text);
        if redacted != text {
            *value = Value::String(redacted);
        }
    }

    fn redact_content_value(&self, value: &mut Value) {
        if value.is_string() {
            self.redact_string_value(value);
            return;
        }
        if let Some(parts) = value.as_array_mut() {
            for part in parts {
                if let Some(text) = part.get_mut("text") {
                    self.redact_string_value(text);
                }
                if let Some(refusal) = part.get_mut("refusal") {
                    self.redact_string_value(refusal);
                }
            }
        }
    }

    fn redact_function_value(&self, value: &mut Value) {
        if let Some(name) = value.get_mut("name") {
            self.redact_string_value(name);
        }
        if let Some(arguments) = value.get_mut("arguments") {
            self.redact_arguments_value(arguments);
        }
    }

    /// Redact a tool/function `arguments` string.
    ///
    /// When the string parses as JSON, only its decoded string values are
    /// redacted and the document re-serialized,
    /// so JSON escapes such as `\u0040` cannot carry content past redaction.
    /// Re-serialization is semantically transparent to the tool client, which
    /// parses the arguments as JSON. Matches carried in structurally
    /// unrewritable positions — decoded object keys and numeric scalars — are
    /// deliberately left in place for the residual re-scan to fail closed on;
    /// raw string replacement over the serialized document would instead
    /// rename keys or turn a numeric document into non-JSON placeholder text
    /// and erase the evidence that re-scan needs. A non-JSON arguments string
    /// is plain text and is redacted directly.
    fn redact_arguments_value(&self, value: &mut Value) {
        let Some(text) = value.as_str() else {
            return;
        };
        let Ok(mut decoded) = serde_json::from_str::<Value>(text) else {
            self.redact_string_value(value);
            return;
        };
        let original = decoded.clone();
        redact_json_strings(
            &mut decoded,
            &self.pii_patterns,
            &self.blocked_phrases,
            false,
        );
        if decoded != original
            && let Ok(rewritten) = serde_json::to_string(&decoded)
        {
            *value = Value::String(rewritten);
        }
    }

    /// `ScanMode::All` raw string redaction with tool/function argument
    /// documents handled structurally.
    ///
    /// To the generic raw pass (`redact_json_strings`) a serialized argument
    /// document is just another string value, so it would rewrite a match in
    /// a decoded object key or numeric scalar into a renamed key or non-JSON
    /// placeholder text — and erase the evidence the residual re-scan needs
    /// to fail closed on. Argument strings therefore first get the decoded
    /// value-safe redaction (`redact_arguments_value`) and are then shielded
    /// from the raw pass; argument positions holding non-string values keep
    /// today's raw pass behavior. Both visits see the same positions in the
    /// same order because shielding substitutes `Value::Null` without changing
    /// the surrounding structure.
    fn redact_all_strings_with_argument_shield(&self, json: &mut Value) {
        let mut shielded: Vec<Option<Value>> = Vec::new();
        for_each_argument_value(json, &mut |value| {
            self.redact_arguments_value(value);
            let arguments = if value.is_string() {
                Some(value.take())
            } else {
                None
            };
            shielded.push(arguments);
        });
        redact_json_strings(json, &self.pii_patterns, &self.blocked_phrases, true);
        let mut restored = shielded.into_iter();
        for_each_argument_value(json, &mut |value| {
            if let Some(Some(arguments)) = restored.next() {
                *value = arguments;
            }
        });
    }

    fn redact_message_like(&self, value: &mut Value) {
        if let Some(content) = value.get_mut("content") {
            self.redact_content_value(content);
        }
        if let Some(refusal) = value.get_mut("refusal") {
            self.redact_string_value(refusal);
        }
        if let Some(function_call) = value.get_mut("function_call") {
            self.redact_function_value(function_call);
        }
        if let Some(tool_calls) = value.get_mut("tool_calls").and_then(Value::as_array_mut) {
            for tool_call in tool_calls {
                if let Some(function) = tool_call.get_mut("function") {
                    self.redact_function_value(function);
                }
            }
        }
    }

    /// Redact content in supported AI response JSON shapes.
    fn redact_response_json(&self, json: &mut Value) {
        if let Some(choices) = json.get_mut("choices").and_then(Value::as_array_mut) {
            for choice in choices {
                if let Some(text) = choice.get_mut("text") {
                    self.redact_string_value(text);
                }
                if let Some(message) = choice.get_mut("message") {
                    self.redact_message_like(message);
                }
                if let Some(delta) = choice.get_mut("delta") {
                    self.redact_message_like(delta);
                }
            }
        }

        if let Some(output_text) = json.get_mut("output_text") {
            self.redact_string_value(output_text);
        }
        if let Some(output) = json.get_mut("output").and_then(Value::as_array_mut) {
            for item in output {
                if let Some(name) = item.get_mut("name") {
                    self.redact_string_value(name);
                }
                if let Some(arguments) = item.get_mut("arguments") {
                    self.redact_arguments_value(arguments);
                }
                if let Some(content) = item.get_mut("content") {
                    self.redact_content_value(content);
                }
            }
        }

        // Anthropic: content[].text
        if let Some(content) = json.get_mut("content").and_then(|c| c.as_array_mut()) {
            for block in content.iter_mut() {
                if block.get("type").and_then(|t| t.as_str()) == Some("text")
                    && let Some(text) = block.get("text").and_then(|t| t.as_str())
                {
                    let redacted = self.redact_text(text);
                    if redacted != text {
                        block["text"] = Value::String(redacted);
                    }
                }
            }
        }

        // Google Gemini: candidates[].content.parts[].text
        if let Some(candidates) = json.get_mut("candidates").and_then(Value::as_array_mut) {
            for candidate in candidates {
                if let Some(parts) = candidate
                    .get_mut("content")
                    .and_then(|c| c.get_mut("parts"))
                    .and_then(|p| p.as_array_mut())
                {
                    for part in parts {
                        if let Some(text) = part.get_mut("text") {
                            self.redact_string_value(text);
                        }
                    }
                }
            }
        }
    }

    /// Shared action handler for detected PII/blocked content.
    fn mark_rejected(ctx: &mut RequestContext, reason: impl Into<String>) {
        ctx.metadata
            .insert("ai_response_guard_rejected".to_string(), reason.into());
    }

    fn respond_to_detection(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        detected: &[String],
    ) -> PluginResult {
        match self.action {
            GuardAction::Reject => {
                debug!(
                    "ai_response_guard: content detected (types: {:?}), rejecting response",
                    detected
                );
                Self::mark_rejected(ctx, detected.join(","));
                let types_json: Vec<String> = detected
                    .iter()
                    .map(|t| format!("\"{}\"", escape_json_string(t)))
                    .collect();
                PluginResult::Reject {
                    status_code: 502,
                    body: format!(
                        r#"{{"error":"AI response blocked by content guard","detected_types":[{}],"message":"Response contains restricted content that was blocked before delivery."}}"#,
                        types_json.join(","),
                    ),
                    headers: HashMap::new(),
                }
            }
            GuardAction::Warn => {
                warn!(
                    "ai_response_guard: content detected (types: {:?}), passing through (warn mode)",
                    detected
                );
                ctx.metadata
                    .insert("ai_response_guard_detected".to_string(), detected.join(","));
                PluginResult::Continue
            }
            GuardAction::Redact => {
                if !super::response_body_rewrite_allowed(response_status) {
                    debug!(
                        response_status,
                        "ai_response_guard: governed range/delta response cannot be safely redacted; rejecting"
                    );
                    Self::mark_rejected(ctx, detected.join(","));
                    let types_json: Vec<String> = detected
                        .iter()
                        .map(|t| format!("\"{}\"", escape_json_string(t)))
                        .collect();
                    return PluginResult::Reject {
                        status_code: 502,
                        body: format!(
                            r#"{{"error":"AI response blocked by content guard","detected_types":[{}],"message":"Response contains restricted content that could not be redacted before delivery."}}"#,
                            types_json.join(","),
                        ),
                        headers: HashMap::new(),
                    };
                }
                ctx.metadata
                    .insert("ai_response_guard_redacted".to_string(), detected.join(","));
                // `Continue` here is a PROMISE that the producer phase will
                // install a redacted replacement, not a decision to deliver
                // these bytes. Record the promise in typed request state so a
                // producer that returns `None` — refused ceiling, refused
                // scratch, a representation this plugin's rewriter cannot
                // address — cannot silently become "unchanged" and forward the
                // original detected body (GHSA-pwcm-6rh8-f2gh). The instance
                // discharges its own entry when it installs bytes;
                // `on_final_response_body` rejects anything still outstanding.
                ctx.ai_response_guard_pending_redactions
                    .insert(self.instance_id, detected.join(","));
                if ctx.finalized_response_replay {
                    ctx.ai_response_guard_replay_redactions
                        .insert(self.instance_id);
                }
                PluginResult::Continue
            }
        }
    }

    fn respond_to_uninspectable(
        &self,
        ctx: &mut RequestContext,
        reason: &'static str,
        message: &'static str,
    ) -> PluginResult {
        let must_reject = self.require_json
            || !self.required_fields.is_empty()
            || self.action != GuardAction::Warn;
        if must_reject {
            Self::mark_rejected(ctx, reason);
            PluginResult::Reject {
                status_code: 502,
                body: format!(
                    r#"{{"error":"AI response guard could not safely inspect the response","reason":"{}"}}"#,
                    escape_json_string(message)
                ),
                headers: HashMap::new(),
            }
        } else {
            ctx.metadata
                .insert("ai_response_guard_warning".to_string(), reason.to_string());
            PluginResult::Continue
        }
    }

    /// Check max completion length constraint.
    ///
    /// `max_completion_length` is documented and configured in **characters**
    /// (Unicode scalar values), so the measurement uses `chars().count()`
    /// rather than `str::len()` (UTF-8 bytes). Counting bytes would trip the
    /// guard early for multibyte completions (CJK, emoji, accented Latin),
    /// rejecting or warning before the operator-configured character limit.
    fn check_completion_length<S: AsRef<str>>(&self, texts: &[S]) -> Option<String> {
        if self.max_completion_length == 0 {
            return None;
        }
        for text in texts {
            let char_len = text.as_ref().chars().count();
            if char_len > self.max_completion_length {
                return Some(format!(
                    "Completion length {} exceeds maximum {}",
                    char_len, self.max_completion_length
                ));
            }
        }
        None
    }

    /// Extract and concatenate completion texts from parsed SSE frames.
    ///
    /// Handles the streaming formats:
    /// - OpenAI: `choices[].delta.content` keyed by choice `index`, plus
    ///   legacy `function_call` name/argument deltas and `delta.refusal`
    /// - OpenAI Responses: reassembler deltas plus `response.refusal.delta`
    /// - Anthropic: `content_block_delta` events with `delta.text` keyed by block `index`
    /// - Gemini: `candidates[].content.parts[].text` keyed by candidate position
    ///
    /// Returns one accumulated `String` per choice/block index, ordered by
    /// index (BTreeMap keeps output deterministic across runs). Accumulated
    /// tool/function argument strings additionally contribute their decoded
    /// JSON tokens so escapes cannot hide content from detection.
    fn extract_sse_completion_texts(&self, frames: &[Value]) -> Vec<String> {
        let mut reassembler = SseReassembler::default();
        let mut provider_texts: std::collections::BTreeMap<(u8, usize), String> =
            std::collections::BTreeMap::new();

        for frame in frames {
            // Shared OpenAI chat/completions + Responses API reassembly covers
            // prose, tool/function names and arguments, and Responses deltas.
            reassembler.push_frame(frame);

            // Legacy Chat Completions streamed `function_call` before the
            // indexed `tool_calls` shape. Keep name and arguments in separate
            // accumulators so neither field can hide a cross-frame match.
            // Chat refusal deltas (`delta.refusal`) are client-visible text
            // and accumulate the same way.
            if let Some(choices) = frame.get("choices").and_then(Value::as_array) {
                for (position, choice) in choices.iter().enumerate() {
                    let index = choice
                        .get("index")
                        .and_then(Value::as_u64)
                        .and_then(|value| usize::try_from(value).ok())
                        .unwrap_or(position);
                    if let Some(function_call) = choice
                        .get("delta")
                        .and_then(|delta| delta.get("function_call"))
                    {
                        if let Some(name) = function_call.get("name").and_then(Value::as_str) {
                            provider_texts.entry((2, index)).or_default().push_str(name);
                        }
                        if let Some(arguments) =
                            function_call.get("arguments").and_then(Value::as_str)
                        {
                            provider_texts
                                .entry((3, index))
                                .or_default()
                                .push_str(arguments);
                        }
                    }
                    if let Some(refusal) = choice
                        .get("delta")
                        .and_then(|delta| delta.get("refusal"))
                        .and_then(Value::as_str)
                    {
                        provider_texts
                            .entry((4, index))
                            .or_default()
                            .push_str(refusal);
                    }
                }
            }

            // Responses API refusal deltas (`response.refusal.delta`) carry a
            // client-visible refusal string outside the reassembler's coverage.
            if frame
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|event_type| event_type.ends_with("refusal.delta"))
                && let Some(delta) = frame.get("delta").and_then(Value::as_str)
            {
                let index = frame
                    .get("output_index")
                    .and_then(Value::as_u64)
                    .and_then(|value| usize::try_from(value).ok())
                    .unwrap_or(0);
                provider_texts
                    .entry((5, index))
                    .or_default()
                    .push_str(delta);
            }

            // Anthropic streaming: type=content_block_delta, delta.text
            if frame.get("type").and_then(|t| t.as_str()) == Some("content_block_delta") {
                let index = frame.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as usize;
                if let Some(text) = frame
                    .get("delta")
                    .and_then(|d| d.get("text"))
                    .and_then(|t| t.as_str())
                {
                    provider_texts.entry((0, index)).or_default().push_str(text);
                }
            }

            // Gemini: candidates[].content.parts[].text
            if let Some(candidates) = frame.get("candidates").and_then(|c| c.as_array()) {
                for (idx, candidate) in candidates.iter().enumerate() {
                    if let Some(parts) = candidate
                        .get("content")
                        .and_then(|c| c.get("parts"))
                        .and_then(|p| p.as_array())
                    {
                        for part in parts {
                            if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                                provider_texts.entry((1, idx)).or_default().push_str(text);
                            }
                        }
                    }
                }
            }
        }

        let mut texts: Vec<String> = Vec::new();
        for sse_text in reassembler.into_texts() {
            if matches!(
                sse_text.kind,
                SseTextKind::ChatToolArguments | SseTextKind::ResponsesArguments
            ) {
                append_decoded_argument_texts(&sse_text.text, &mut texts);
            }
            texts.push(sse_text.text);
        }
        for ((kind, _), text) in provider_texts {
            // Kind 3 accumulates legacy `function_call.arguments`, which is
            // nested JSON like the reassembler's tool-call arguments.
            if kind == 3 {
                append_decoded_argument_texts(&text, &mut texts);
            }
            texts.push(text);
        }
        texts
    }

    /// Redact content fields in a single parsed SSE frame.
    fn redact_sse_frame(&self, frame: &mut Value) {
        if let Some(choices) = frame.get_mut("choices").and_then(Value::as_array_mut) {
            for choice in choices {
                if let Some(text) = choice.get_mut("text") {
                    self.redact_string_value(text);
                }
                if let Some(delta) = choice.get_mut("delta") {
                    self.redact_message_like(delta);
                }
            }
        }

        let (is_responses_delta, is_responses_arguments_delta) = frame
            .get("type")
            .and_then(Value::as_str)
            .map(|event_type| {
                (
                    event_type.ends_with("output_text.delta")
                        || event_type.ends_with("function_call_arguments.delta")
                        || event_type.ends_with("refusal.delta"),
                    event_type.ends_with("function_call_arguments.delta"),
                )
            })
            .unwrap_or((false, false));
        if is_responses_delta && let Some(delta) = frame.get_mut("delta") {
            if is_responses_arguments_delta {
                self.redact_arguments_value(delta);
            } else {
                self.redact_string_value(delta);
            }
        }

        // Anthropic streaming: content_block_delta
        if frame.get("type").and_then(|t| t.as_str()) == Some("content_block_delta")
            && let Some(text) = frame
                .get("delta")
                .and_then(|d| d.get("text"))
                .and_then(|t| t.as_str())
        {
            let redacted = self.redact_text(text);
            if redacted != text {
                frame["delta"]["text"] = Value::String(redacted);
            }
        }

        // Gemini: candidates[].content.parts[].text
        if let Some(candidates) = frame.get_mut("candidates").and_then(Value::as_array_mut) {
            for candidate in candidates {
                if let Some(parts) = candidate
                    .get_mut("content")
                    .and_then(|c| c.get_mut("parts"))
                    .and_then(|p| p.as_array_mut())
                {
                    for part in parts {
                        if let Some(text) = part.get_mut("text") {
                            self.redact_string_value(text);
                        }
                    }
                }
            }
        }
    }

    /// Rewrite one SSE event's JSON `data:` payload into `output`, or report
    /// that the event is unchanged. `None` is construction refusal.
    fn redact_sse_event(
        &self,
        output: &mut crate::proxy::response_buffer_budget::BoundedResponseBodySink,
        lines: &[&str],
    ) -> Option<bool> {
        rewrite_sse_json_event_into(output, lines, |json| {
            if self.scan_mode == ScanMode::All {
                self.redact_all_strings_with_argument_shield(json);
            } else {
                self.redact_sse_frame(json);
            }
        })
    }

    /// Redact an SSE response body, modifying complete SSE events while
    /// preserving the overall SSE framing. Returns `None` when no frame was
    /// modified (zero-copy happy path).
    ///
    /// Rewritten `data:` lines preserve their original CR/LF terminator so
    /// CRLF-encoded streams round-trip without mixing line endings. Frame JSON
    /// is reserialized compactly by `serde_json::to_writer` into the bounded
    /// sink, which may alter whitespace within a frame — clients consuming SSE
    /// byte-for-byte should not depend on inner-frame formatting.
    fn redact_sse_body(&self, body: &[u8], ceiling: usize) -> Option<Vec<u8>> {
        let body_str = std::str::from_utf8(body).ok()?;

        // Fast-skip the common "redact mode but no PII in the stream" case.
        // Scan-all mode unions decoded frame strings (so JSON escapes cannot hide
        // content) with a raw-body pass (so cross-token/contextual patterns and
        // unparseable `data:` payloads are not skipped here while the
        // reject/warn detection path would have flagged them).
        let has_match = if self.scan_mode == ScanMode::All {
            let frames = parse_sse_data_frames(body);
            !self
                .detect_matches_in_decoded_sse_frames(&frames, Some(body_str))
                .is_empty()
        } else {
            let frames = parse_sse_data_frames(body);
            let accumulated = self.extract_sse_completion_texts(&frames);
            let refs: Vec<&str> = accumulated.iter().map(String::as_str).collect();
            !self.detect_matches(&refs).is_empty()
        };
        if !has_match {
            return None;
        }

        // Assembled eventwise through the ceiling-bounded sink, so the rewritten
        // stream is never materialised in full before the bound applies
        // (GHSA-pwcm-6rh8-f2gh). Each event is framed/serialized directly into
        // that sink — never as a complete would-be event `String` beside it.
        let (output, modified) = rewrite_sse_events_bounded(body_str, ceiling, |output, lines| {
            self.redact_sse_event(output, lines)
        })?;

        if modified { Some(output) } else { None }
    }

    // ───────────────────────── native gRPC inspection ─────────────────────────

    /// Resolve the gRPC method path used for enrollment lookup.
    ///
    /// Prefers the finalized `grpc_full_method` published by
    /// `grpc_method_router` (which reflects a method rewrite applied before
    /// dispatch) and falls back to the canonical request path. Backends never
    /// echo `:path` in a response, so the request is the only correct source.
    fn grpc_method_path(ctx: &RequestContext) -> Cow<'_, str> {
        match ctx.metadata.get("grpc_full_method") {
            Some(method) if method.starts_with('/') => Cow::Borrowed(method.as_str()),
            Some(method) => {
                let mut path = String::with_capacity(method.len() + 1);
                path.push('/');
                path.push_str(method);
                Cow::Owned(path)
            }
            None => Cow::Borrowed(ctx.path.as_str()),
        }
    }

    /// Whether a configured gRPC contract governs this request's response.
    ///
    /// This is the single gate for the buffering vote, the inspection hook, and
    /// the redaction transform, so a method the operator never enrolled is
    /// never pulled onto the buffered path and never inspected opportunistically.
    fn grpc_inspection_applies(&self, ctx: &RequestContext) -> bool {
        let Some(grpc) = self.grpc.as_ref() else {
            return false;
        };
        ctx.is_native_grpc_request() && grpc.enrolls(&Self::grpc_method_path(ctx))
    }

    /// Whether this plugin's redaction transform owns this response's bytes.
    ///
    /// Matches the inspection/enrollment gate rather than the response
    /// `Content-Type`: a successfully inspected framed response whose response
    /// type is absent or relabeled must still be rewritten. gRPC-Web
    /// translated responses remain excluded because `grpc_web` re-frames the
    /// body before this transform could run.
    fn grpc_transform_applies(&self, ctx: &RequestContext, _content_type: Option<&str>) -> bool {
        self.needs_body_transform
            && self.grpc_inspection_applies(ctx)
            && !crate::plugins::grpc_web::request_is_grpc_web_translated(ctx)
    }

    /// Inspect a buffered native-gRPC response body for an enrolled method.
    fn inspect_grpc_response(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        let Some(grpc) = self.grpc.as_ref() else {
            return PluginResult::Continue;
        };
        let method_path = Self::grpc_method_path(ctx).into_owned();
        if !grpc.enrolls(&method_path) {
            // Never inspect a method the operator did not enroll: its message
            // type is unknown, so any decode would be a guess.
            return PluginResult::Continue;
        }

        // An enrolled method whose descriptor this node could not load has a
        // policy but no way to apply it, which is exactly the fail-closed case.
        if grpc.dependency_unavailable {
            return self.respond_to_uninspectable(
                ctx,
                "grpc_descriptor_unavailable",
                "configured protobuf descriptor dependency is unavailable",
            );
        }
        let Some(method) = grpc.method(&method_path) else {
            return self.respond_to_uninspectable(
                ctx,
                "grpc_descriptor_unavailable",
                "configured protobuf descriptor dependency is unavailable",
            );
        };

        if body.len() > self.max_scan_bytes {
            return self.respond_to_uninspectable(
                ctx,
                "body_exceeds_max_scan_bytes",
                "response body exceeds max_scan_bytes",
            );
        }
        // Content governance stays scoped to successful responses; a gRPC
        // error is carried by trailers, not by a governed message.
        if !(200..300).contains(&response_status) {
            return PluginResult::Continue;
        }
        // A trailers-only response carries no message to inspect.
        if body.is_empty() {
            return PluginResult::Continue;
        }

        let encoding = grpc_message_encoding(response_headers);
        let scan = match scan_grpc_body(body, method, grpc, encoding, self.max_scan_bytes) {
            Ok(scan) => scan,
            Err(error) => {
                let (reason, detail) = error.describe();
                return self.respond_to_uninspectable(ctx, reason, detail);
            }
        };

        // Length policy covers the ordered aggregate of governed selected
        // strings as well as each fragment, so a limit cannot be split across
        // server-streaming frames.
        let mut length_texts: Vec<&str> = scan.scanned.iter().map(String::as_str).collect();
        if !scan.aggregate.is_empty() {
            length_texts.push(scan.aggregate.as_str());
        }
        if let Some(reason) = self.check_completion_length(&length_texts) {
            match self.action {
                GuardAction::Reject | GuardAction::Redact => {
                    Self::mark_rejected(ctx, reason.clone());
                    return PluginResult::Reject {
                        status_code: 502,
                        body: format!(
                            r#"{{"error":"AI response guard: {}"}}"#,
                            escape_json_string(&reason)
                        ),
                        headers: HashMap::new(),
                    };
                }
                GuardAction::Warn => {
                    ctx.metadata
                        .insert("ai_response_guard_warning".to_string(), reason);
                }
            }
        }

        let detected = self.detect_grpc_matches(&scan);
        if detected.is_empty() {
            return PluginResult::Continue;
        }

        if self.action == GuardAction::Redact {
            if crate::plugins::grpc_web::request_is_grpc_web_translated(ctx) {
                // The gRPC-Web transform re-frames the body before this
                // plugin's transform would run, so a protobuf redaction can
                // never reach the bytes the client receives.
                return self.respond_to_uninspectable(
                    ctx,
                    "grpc_web_translation_blocks_redaction",
                    "gRPC-Web translated responses cannot be redacted in protobuf form",
                );
            }
            // Map keys and matches that exist only across string/frame
            // boundaries are matchable but not rewritable in any one scalar.
            let key_match = !self.detect_matches(&scan.map_keys).is_empty();
            let cross_boundary_only = self.grpc_match_only_across_boundaries(&scan);
            // This preflight builds a COMPLETE would-be client-visible body
            // during INSPECTION, before the transform phase has reserved
            // anything. Building it against nothing would leave a full-size
            // attacker-shaped replacement resident beside the response body with
            // no charge covering it, which is the aggregate-bound bypass this
            // advisory closes. So a window sized to THIS response's retained
            // ceiling is reserved first and released as soon as the preflight is
            // done — the same shape `redact_sse_leaves_residual` uses, and the
            // same documented two-ceiling peak. A budget that cannot admit the
            // window is a REFUSAL, not a licence to build the candidate anyway
            // (GHSA-pwcm-6rh8-f2gh).
            let redaction_verified =
                match crate::proxy::response_buffer_budget::ResponseTransformWindow::open(
                    ctx.retained_response_body_ceiling(),
                ) {
                    Some(window) => {
                        let rewritten = self.redacted_grpc_body(
                            ctx,
                            response_headers,
                            body,
                            window.window_bytes(),
                        );
                        let verified = rewritten.is_some();
                        // The candidate is released BEFORE the window is, so the
                        // charge covers it for its whole lifetime.
                        drop(rewritten);
                        drop(window);
                        verified
                    }
                    None => false,
                };
            if key_match || cross_boundary_only || !redaction_verified {
                debug!(
                    "ai_response_guard: gRPC redaction leaves residual content \
                     (types: {:?}), rejecting response",
                    detected
                );
                let types_json: Vec<String> = detected
                    .iter()
                    .map(|t| format!("\"{}\"", escape_json_string(t)))
                    .collect();
                Self::mark_rejected(ctx, detected.join(","));
                return PluginResult::Reject {
                    status_code: 502,
                    body: format!(
                        r#"{{"error":"AI response blocked by content guard","detected_types":[{}],"message":"Response contains restricted content that could not be redacted before delivery."}}"#,
                        types_json.join(","),
                    ),
                    headers: HashMap::new(),
                };
            }
        }

        self.respond_to_detection(ctx, response_status, &detected)
    }

    /// Detect matches against each governed string and the ordered aggregate of
    /// selected strings (plus matchable-but-unrewritable map keys).
    fn detect_grpc_matches(&self, scan: &GrpcScan) -> Vec<String> {
        let mut candidates: Vec<&str> = scan.scanned.iter().map(String::as_str).collect();
        if !scan.aggregate.is_empty() {
            candidates.push(scan.aggregate.as_str());
        }
        candidates.extend(scan.map_keys.iter().map(String::as_str));
        self.detect_matches(&candidates)
    }

    /// True when detection fires only on the ordered aggregate of selected
    /// strings — a match that cannot be rewritten inside any one scalar.
    fn grpc_match_only_across_boundaries(&self, scan: &GrpcScan) -> bool {
        if scan.aggregate.is_empty() {
            return false;
        }
        let aggregate_hits = self.detect_matches(&[scan.aggregate.as_str()]);
        if aggregate_hits.is_empty() {
            return false;
        }
        self.detect_matches(&scan.scanned).is_empty()
    }

    /// Produce the redacted gRPC wire body, or `None` when the redaction could
    /// not be applied and *verified* end to end.
    ///
    /// Verification is deliberately a full round trip: rewrite, re-encode
    /// (re-compressing frames that arrived compressed), re-parse the produced
    /// wire bytes, re-decode, and re-scan with the same selected-field and
    /// aggregate semantics used at inspection time. Only a body that comes
    /// back clean is returned, so a partial rewrite can never be reported as
    /// redacted.
    fn redacted_grpc_body(
        &self,
        ctx: &RequestContext,
        response_headers: &HashMap<String, String>,
        body: &[u8],
        ceiling: usize,
    ) -> Option<Vec<u8>> {
        let grpc = self.grpc.as_ref()?;
        let method = grpc.method(&Self::grpc_method_path(ctx))?;
        if body.is_empty() || body.len() > self.max_scan_bytes {
            return None;
        }
        let encoding = grpc_message_encoding(response_headers);
        let max_bytes = grpc.max_message_bytes;
        let frames = parse_grpc_frames(
            body,
            encoding,
            max_bytes,
            grpc.max_messages,
            self.max_scan_bytes,
        )
        .ok()?;

        // Frames accumulate into a ceiling-bounded sink, so a redaction that
        // expands the wire representation past what the transform phase reserved
        // is refused WHILE it is being built (GHSA-pwcm-6rh8-f2gh).
        use crate::proxy::response_buffer_budget::BoundedResponseBodySink;
        let mut rewritten = BoundedResponseBodySink::with_ceiling(ceiling);
        let mut changed = false;
        for frame in &frames {
            let payload = frame.payload.as_ref();
            let mut message = DynamicMessage::decode(method.descriptor.clone(), payload).ok()?;
            let mut budget = GrpcWalkBudget::default();
            let mut redact = |text: &str| -> String { self.redact_text(text) };
            let mutated = match method.text_fields.as_deref() {
                None => redact_strings(&mut message, &mut budget, &mut redact),
                Some(paths) => redact_paths(&mut message, paths, &mut budget, &mut redact),
            };
            changed |= mutated.ok()?;
            if !push_reframed_grpc_message(&mut rewritten, &message, frame.compressed, max_bytes) {
                return None;
            }
        }
        if !changed {
            return None;
        }
        let rewritten = rewritten.finish()?;

        // Re-verify against the exact bytes the client would receive, using the
        // same selected-field surface and aggregate matching as inspection.
        let verify_scan =
            scan_grpc_body(&rewritten, method, grpc, encoding, self.max_scan_bytes).ok()?;
        self.detect_grpc_matches(&verify_scan)
            .is_empty()
            .then_some(rewritten)
    }
}

/// True when a response `Content-Type` is native gRPC or gRPC-Web framing.
///
/// Delegates to the shared classifier every sibling AI plugin uses, so this
/// stays aligned with the H1/H2/H3 paths. Allocation-free.
///
/// Native gRPC alone is not enough here: a gRPC-Web response body is the same
/// length-prefixed frame grammar (optionally base64-armored), and it is the
/// representation an `ai_response_guard` on a mixed route actually meets —
/// `grpc_web`'s `after_proxy` relabels every translated response to
/// `application/grpc-web*` before `on_response_body` runs.
fn is_framed_grpc_content_type(content_type: &str) -> bool {
    crate::plugins::utils::body_transform::is_framed_grpc_content_type(content_type)
}

/// Whether these buffered response bytes are gRPC framing rather than the
/// JSON/SSE/text document model this plugin's non-gRPC paths assume.
///
/// The live `content-type` cannot answer this alone. `grpc_web`'s `after_proxy`
/// rewrites it, and an ordinary header rule may relabel or strip it outright, so
/// the resolution mirrors
/// [`crate::plugins::response_representation::effective_response_media_type`]:
/// the live label, then the pristine backend label stamped before any response
/// hook ran, then a total frame parse under the one grammar the client's
/// representation admits. The parse is structural, never a sniff, so a genuine
/// bare JSON document on a gRPC-Web request stays claimed and inspectable.
fn response_is_grpc_framed(ctx: &RequestContext, content_type: Option<&str>, body: &[u8]) -> bool {
    if content_type.is_some_and(is_framed_grpc_content_type) {
        return true;
    }
    if ctx
        .metadata
        .get(crate::proxy::ORIGINAL_RESPONSE_CONTENT_TYPE_METADATA_KEY)
        .map(String::as_str)
        .is_some_and(is_framed_grpc_content_type)
    {
        return true;
    }
    let Some(representation) = crate::plugins::grpc_web::client_grpc_framing_representation(ctx)
    else {
        return false;
    };
    crate::plugins::grpc_web::bytes_are_complete_grpc_frames(body, representation)
}

/// Bounded walk accounting shared by every protobuf traversal.
struct GrpcWalkBudget {
    depth: usize,
    nodes: usize,
}

impl Default for GrpcWalkBudget {
    fn default() -> Self {
        Self {
            depth: 0,
            nodes: GRPC_MAX_MESSAGE_NODES,
        }
    }
}

impl GrpcWalkBudget {
    fn enter(&mut self) -> Result<(), ()> {
        if self.depth >= GRPC_MAX_MESSAGE_DEPTH {
            return Err(());
        }
        self.depth += 1;
        Ok(())
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn charge(&mut self) -> Result<(), ()> {
        if self.nodes == 0 {
            return Err(());
        }
        self.nodes -= 1;
        Ok(())
    }
}

/// Strings harvested from one decoded protobuf message tree when the method
/// does not restrict the scan with `text_fields`.
#[derive(Default)]
struct GrpcStrings {
    /// Every string *value* in the tree.
    texts: Vec<String>,
    /// Every protobuf map key of string type. Matchable, never rewritable —
    /// the same limitation JSON object member names have.
    map_keys: Vec<String>,
}

/// Everything one buffered gRPC response contributed to the scan.
struct GrpcScan {
    /// Strings the configured contract actually scans and may rewrite, in
    /// encounter order across frames.
    scanned: Vec<String>,
    /// Ordered concatenation of [`Self::scanned`]. Detection and length policy
    /// treat this as a second surface so a match or limit split across frames
    /// cannot hide between scalars.
    aggregate: String,
    /// Protobuf map keys governed by this scan. Present only when `text_fields`
    /// is omitted (whole-message governance); detection covers them but
    /// redaction cannot rewrite them. Empty when `text_fields` scopes the scan.
    map_keys: Vec<String>,
}

/// Why a governed gRPC response could not be inspected.
#[derive(Clone, Copy)]
enum GrpcScanError {
    Framing(GrpcFramingError),
    DecodeFailed,
    WalkBudget,
    UnknownFields,
}

impl GrpcScanError {
    fn describe(self) -> (&'static str, &'static str) {
        match self {
            Self::Framing(error) => error.describe(),
            Self::DecodeFailed => (
                "grpc_message_decode_failed",
                "response protobuf message does not match the configured type",
            ),
            Self::WalkBudget => (
                "grpc_message_exceeds_walk_budget",
                "response protobuf message exceeds the inspection walk budget",
            ),
            Self::UnknownFields => (
                "grpc_message_has_unknown_fields",
                "response protobuf message carries fields outside the configured descriptor",
            ),
        }
    }
}

/// Decode every frame of a governed gRPC response and harvest its strings.
///
/// The structural walk always covers the whole message tree — bounding it and
/// proving there are no undecodable unknown fields — even when `text_fields`
/// narrows what is scanned and rewritten. Known extension values are walked
/// exactly like ordinary known fields. When `text_fields` is set, only those
/// selected string scalars are collected; out-of-scope strings and map keys
/// are neither cloned nor fed to detection.
fn scan_grpc_body(
    body: &[u8],
    method: &GrpcMethodInspection,
    grpc: &GrpcInspection,
    encoding: GrpcMessageEncoding,
    max_scan_bytes: usize,
) -> Result<GrpcScan, GrpcScanError> {
    let max_bytes = grpc.max_message_bytes;
    let frames = parse_grpc_frames(body, encoding, max_bytes, grpc.max_messages, max_scan_bytes)
        .map_err(GrpcScanError::Framing)?;

    let mut scanned: Vec<String> = Vec::new();
    let mut map_keys: Vec<String> = Vec::new();
    for frame in &frames {
        let payload = frame.payload.as_ref();
        let message = DynamicMessage::decode(method.descriptor.clone(), payload)
            .map_err(|_| GrpcScanError::DecodeFailed)?;
        match method.text_fields.as_deref() {
            None => {
                let mut strings = GrpcStrings::default();
                let mut budget = GrpcWalkBudget::default();
                collect_strings(&message, &mut strings, &mut budget)
                    .map_err(|_| GrpcScanError::WalkBudget)?;
                let mut unknown_budget = GrpcWalkBudget::default();
                if has_unknown_fields(&message, &mut unknown_budget) {
                    // Unknown fields carry bytes this contract cannot decode, so a
                    // clean scan of the known fields would not be evidence.
                    return Err(GrpcScanError::UnknownFields);
                }
                scanned.extend(strings.texts);
                map_keys.extend(strings.map_keys);
            }
            Some(paths) => {
                // Bound the complete tree without harvesting out-of-scope
                // strings. `text_fields` cannot select map keys, so map-key
                // matches stay out of detection for a scoped enrollment.
                let mut budget = GrpcWalkBudget::default();
                charge_message_tree(&message, &mut budget)
                    .map_err(|_| GrpcScanError::WalkBudget)?;
                let mut unknown_budget = GrpcWalkBudget::default();
                if has_unknown_fields(&message, &mut unknown_budget) {
                    return Err(GrpcScanError::UnknownFields);
                }
                let mut budget = GrpcWalkBudget::default();
                collect_paths(&message, paths, &mut scanned, &mut budget)
                    .map_err(|_| GrpcScanError::WalkBudget)?;
            }
        }
    }

    let aggregate = scanned.concat();
    Ok(GrpcScan {
        scanned,
        aggregate,
        map_keys,
    })
}

/// One parsed gRPC length-prefixed frame with its payload in identity form.
struct GrpcFrame<'a> {
    /// Whether the frame arrived compressed. Preserved so a redacted rewrite
    /// keeps the wire shape the negotiated `grpc-encoding` promises.
    compressed: bool,
    payload: Cow<'a, [u8]>,
}

/// Message encoding negotiated for this response, from `grpc-encoding`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum GrpcMessageEncoding {
    Identity,
    Gzip,
    /// An encoding this plugin cannot decode. Only reachable when a frame
    /// actually sets its compressed flag.
    Unsupported,
}

/// Why a gRPC body could not be framed within the configured bounds.
#[derive(Clone, Copy)]
enum GrpcFramingError {
    Malformed,
    MessageTooLarge,
    DecodedTooLarge,
    TooManyMessages,
    UnsupportedEncoding,
}

impl GrpcFramingError {
    fn describe(self) -> (&'static str, &'static str) {
        match self {
            Self::Malformed => (
                "grpc_framing_malformed",
                "response gRPC framing is malformed or truncated",
            ),
            Self::MessageTooLarge => (
                "grpc_message_too_large",
                "a gRPC message exceeds the configured max_message_bytes",
            ),
            Self::DecodedTooLarge => (
                "grpc_decoded_exceeds_max_scan_bytes",
                "aggregate decoded gRPC payload exceeds max_scan_bytes",
            ),
            Self::TooManyMessages => (
                "grpc_too_many_messages",
                "the gRPC response exceeds the configured max_messages",
            ),
            Self::UnsupportedEncoding => (
                "grpc_unsupported_message_encoding",
                "the gRPC message encoding is not supported",
            ),
        }
    }
}

fn grpc_message_encoding(response_headers: &HashMap<String, String>) -> GrpcMessageEncoding {
    let Some(value) = response_headers.get("grpc-encoding") else {
        return GrpcMessageEncoding::Identity;
    };
    let value = value.trim();
    if value.is_empty() || value.eq_ignore_ascii_case("identity") {
        GrpcMessageEncoding::Identity
    } else if value.eq_ignore_ascii_case("gzip") {
        GrpcMessageEncoding::Gzip
    } else {
        GrpcMessageEncoding::Unsupported
    }
}

/// Parse a buffered gRPC body into its complete length-prefixed frames.
///
/// Every frame must be complete: a truncated trailing frame, a stray trailing
/// byte, or an unrecognized compressed-flag value is malformed rather than
/// "inspect what we have". The per-message ceiling, the frame-count cap, and
/// an aggregate decoded/decompressed payload ceiling (`max_scan_bytes`) are
/// all enforced before any further inspection work.
fn parse_grpc_frames(
    body: &[u8],
    encoding: GrpcMessageEncoding,
    max_message_bytes: usize,
    max_messages: usize,
    max_scan_bytes: usize,
) -> Result<Vec<GrpcFrame<'_>>, GrpcFramingError> {
    let mut frames = Vec::new();
    let mut offset = 0usize;
    let mut decoded_total = 0usize;
    while offset < body.len() {
        if body.len() - offset < 5 {
            return Err(GrpcFramingError::Malformed);
        }
        let flag = body[offset];
        if flag > 1 {
            return Err(GrpcFramingError::Malformed);
        }
        let length = u32::from_be_bytes([
            body[offset + 1],
            body[offset + 2],
            body[offset + 3],
            body[offset + 4],
        ]) as usize;
        offset += 5;
        if length > max_message_bytes {
            return Err(GrpcFramingError::MessageTooLarge);
        }
        if body.len() - offset < length {
            return Err(GrpcFramingError::Malformed);
        }
        let raw = &body[offset..offset + length];
        offset += length;
        if frames.len() >= max_messages {
            return Err(GrpcFramingError::TooManyMessages);
        }
        let payload = if flag == 1 {
            match encoding {
                GrpcMessageEncoding::Gzip => {
                    // Never inflate past what the aggregate `max_scan_bytes`
                    // budget could still admit. Bytes above it are rejected
                    // below no matter what they decompress to, so inflating to
                    // the (independently configurable, potentially much larger)
                    // per-message ceiling first is pure amplification: a small
                    // compressed frame would materialize `max_message_bytes` of
                    // heap only to be discarded.
                    let remaining = max_scan_bytes.saturating_sub(decoded_total);
                    let scan_budget_binds = remaining < max_message_bytes;
                    let inflate_limit = max_message_bytes.min(remaining);
                    match decompress_grpc_gzip(raw, inflate_limit) {
                        Ok(payload) => Cow::Owned(payload),
                        // Attribute the refusal to whichever ceiling actually
                        // bound this frame, so the fail-closed reason stays
                        // truthful.
                        Err(GrpcFramingError::MessageTooLarge) if scan_budget_binds => {
                            return Err(GrpcFramingError::DecodedTooLarge);
                        }
                        Err(error) => return Err(error),
                    }
                }
                GrpcMessageEncoding::Identity | GrpcMessageEncoding::Unsupported => {
                    return Err(GrpcFramingError::UnsupportedEncoding);
                }
            }
        } else {
            Cow::Borrowed(raw)
        };
        decoded_total = decoded_total.saturating_add(payload.len());
        if decoded_total > max_scan_bytes {
            return Err(GrpcFramingError::DecodedTooLarge);
        }
        frames.push(GrpcFrame {
            compressed: flag == 1,
            payload,
        });
    }
    Ok(frames)
}

/// Bounded gzip inflate for one gRPC message. The ceiling is enforced while
/// reading so a compression bomb cannot allocate past it; the caller passes the
/// tighter of the per-message ceiling and the remaining aggregate scan budget,
/// then re-labels the refusal to whichever bound applied. The compressed
/// payload must be exactly one fully consumed gzip member: trailing garbage
/// and concatenated additional members are rejected.
fn decompress_grpc_gzip(
    payload: &[u8],
    max_decompressed_bytes: usize,
) -> Result<Vec<u8>, GrpcFramingError> {
    // Use `bufread::GzDecoder` (not `read::GzDecoder`): the read variant wraps
    // a `BufReader` and may pull past the first member's trailer into its
    // internal buffer, which would make a leftover-slice check miss trailing
    // garbage or a second concatenated member.
    let mut decoder = GzDecoder::new(payload);
    let mut decompressed = Vec::with_capacity(payload.len().min(max_decompressed_bytes));
    let mut buffer = [0u8; 8192];
    loop {
        let read = decoder
            .read(&mut buffer)
            .map_err(|_| GrpcFramingError::Malformed)?;
        if read == 0 {
            break;
        }
        if decompressed.len().saturating_add(read) > max_decompressed_bytes {
            return Err(GrpcFramingError::MessageTooLarge);
        }
        decompressed.extend_from_slice(&buffer[..read]);
    }
    // First member (header + deflate + trailer/CRC) was fully validated.
    // Recover the exact unconsumed input; any remainder is trailing garbage
    // or another concatenated member and must not be silently ignored.
    if !decoder.into_inner().is_empty() {
        return Err(GrpcFramingError::Malformed);
    }
    Ok(decompressed)
}

/// Bytes of the gRPC frame header: one compressed flag plus a 4-byte
/// big-endian message length.
const GRPC_FRAME_HEADER_BYTES: usize = 5;

/// Re-frame one redacted protobuf message directly INTO the bounded output,
/// re-compressing when the source frame was compressed so the response stays
/// consistent with its `grpc-encoding`.
///
/// Every byte is constructed inside a bound. The uncompressed case never builds
/// a payload buffer at all: the encoded length is known before encoding, so the
/// per-message limit is checked first, the room is reserved in the output, and
/// `prost` writes the message straight into it. The compressed case must know
/// the gzip member's length before it can write the frame header, so the payload
/// and its member are materialised — but each inside a sink bounded by the
/// per-message limit and by the room this frame has left, never as an unbounded
/// `Vec` (GHSA-pwcm-6rh8-f2gh).
///
/// `false` means the message could not be framed within those bounds; the caller
/// abandons the whole redaction rather than emitting a partial wire body.
fn push_reframed_grpc_message(
    out: &mut crate::proxy::response_buffer_budget::BoundedResponseBodySink,
    message: &DynamicMessage,
    compress: bool,
    max_bytes: usize,
) -> bool {
    use crate::proxy::response_buffer_budget::BoundedResponseBodySink;

    let encoded_len = message.encoded_len();
    if encoded_len > max_bytes {
        return false;
    }
    let Some(room) = out
        .ceiling()
        .checked_sub(out.len())
        .and_then(|left| left.checked_sub(GRPC_FRAME_HEADER_BYTES))
    else {
        return false;
    };

    if !compress {
        let Ok(length) = u32::try_from(encoded_len) else {
            return false;
        };
        if encoded_len > room {
            return false;
        }
        let mut header = [0u8; GRPC_FRAME_HEADER_BYTES];
        header[1..].copy_from_slice(&length.to_be_bytes());
        if !out.push(&header) {
            return false;
        }
        return out.append_with(encoded_len, |buffer| message.encode(buffer));
    }

    // The compressed branch needs the encoded message before it can be deflated,
    // so the preimage is one MESSAGE (already bounded by `max_bytes` above), not
    // a would-be complete replacement, and it is itself built through a sink
    // sized to exactly that length.
    let mut payload = BoundedResponseBodySink::with_ceiling(encoded_len);
    if !payload.append_with(encoded_len, |buffer| message.encode(buffer)) {
        return false;
    }
    let Some(payload) = payload.finish() else {
        return false;
    };
    let mut compressed = BoundedResponseBodySink::with_ceiling(room);
    {
        let mut encoder = GzEncoder::new(&mut compressed, flate2::Compression::default());
        if encoder.write_all(&payload).is_err() || encoder.finish().is_err() {
            return false;
        }
    }
    let Some(compressed) = compressed.finish() else {
        return false;
    };
    let Ok(length) = u32::try_from(compressed.len()) else {
        return false;
    };
    let mut header = [0u8; GRPC_FRAME_HEADER_BYTES];
    header[0] = 1;
    header[1..].copy_from_slice(&length.to_be_bytes());
    out.push(&header) && out.push(&compressed)
}

/// Collect every string value and string map key reachable from `message`,
/// including known extension values.
fn collect_strings(
    message: &DynamicMessage,
    strings: &mut GrpcStrings,
    budget: &mut GrpcWalkBudget,
) -> Result<(), ()> {
    budget.enter()?;
    for (_, value) in message.fields() {
        collect_value(value, strings, budget)?;
    }
    for (_, value) in message.extensions() {
        collect_value(value, strings, budget)?;
    }
    budget.leave();
    Ok(())
}

fn collect_value(
    value: &ProtobufValue,
    strings: &mut GrpcStrings,
    budget: &mut GrpcWalkBudget,
) -> Result<(), ()> {
    budget.charge()?;
    match value {
        ProtobufValue::String(text) => strings.texts.push(text.clone()),
        ProtobufValue::Message(message) => collect_strings(message, strings, budget)?,
        ProtobufValue::List(items) => {
            for item in items {
                collect_value(item, strings, budget)?;
            }
        }
        ProtobufValue::Map(entries) => {
            for (key, entry) in entries {
                if let MapKey::String(key) = key {
                    strings.map_keys.push(key.clone());
                }
                collect_value(entry, strings, budget)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Charge the walk budget across the whole message tree without collecting
/// string values. Used when `text_fields` already scopes which scalars are
/// harvested, so out-of-scope clones are not paid for just to discard them.
fn charge_message_tree(message: &DynamicMessage, budget: &mut GrpcWalkBudget) -> Result<(), ()> {
    budget.enter()?;
    for (_, value) in message.fields() {
        charge_value(value, budget)?;
    }
    for (_, value) in message.extensions() {
        charge_value(value, budget)?;
    }
    budget.leave();
    Ok(())
}

fn charge_value(value: &ProtobufValue, budget: &mut GrpcWalkBudget) -> Result<(), ()> {
    budget.charge()?;
    match value {
        ProtobufValue::Message(message) => charge_message_tree(message, budget)?,
        ProtobufValue::List(items) => {
            for item in items {
                charge_value(item, budget)?;
            }
        }
        ProtobufValue::Map(entries) => {
            for entry in entries.values() {
                charge_value(entry, budget)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Whether any message in the tree carries fields outside the descriptor.
///
/// Budget exhaustion answers "cannot prove absence", which keeps the caller
/// fail-closed rather than optimistic. Known extension values are recursed
/// exactly like ordinary fields so an unknown nested under an extension cannot
/// hide.
fn has_unknown_fields(message: &DynamicMessage, budget: &mut GrpcWalkBudget) -> bool {
    if budget.enter().is_err() {
        return true;
    }
    if message.unknown_fields().next().is_some() {
        return true;
    }
    for (_, value) in message.fields() {
        if value_has_unknown_fields(value, budget) {
            return true;
        }
    }
    for (_, value) in message.extensions() {
        if value_has_unknown_fields(value, budget) {
            return true;
        }
    }
    budget.leave();
    false
}

fn value_has_unknown_fields(value: &ProtobufValue, budget: &mut GrpcWalkBudget) -> bool {
    if budget.charge().is_err() {
        return true;
    }
    match value {
        ProtobufValue::Message(message) => has_unknown_fields(message, budget),
        ProtobufValue::List(items) => items
            .iter()
            .any(|item| value_has_unknown_fields(item, budget)),
        ProtobufValue::Map(entries) => entries
            .values()
            .any(|entry| value_has_unknown_fields(entry, budget)),
        _ => false,
    }
}

/// Collect only the string values addressed by the configured dotted paths.
fn collect_paths(
    message: &DynamicMessage,
    paths: &[Vec<String>],
    texts: &mut Vec<String>,
    budget: &mut GrpcWalkBudget,
) -> Result<(), ()> {
    for path in paths {
        collect_path(message, path, texts, budget)?;
    }
    Ok(())
}

fn collect_path(
    message: &DynamicMessage,
    path: &[String],
    texts: &mut Vec<String>,
    budget: &mut GrpcWalkBudget,
) -> Result<(), ()> {
    budget.enter()?;
    let Some((segment, rest)) = path.split_first() else {
        budget.leave();
        return Ok(());
    };
    let Some(field) = message.descriptor().get_field_by_name(segment) else {
        budget.leave();
        return Ok(());
    };
    if !message.has_field(&field) {
        budget.leave();
        return Ok(());
    }
    collect_path_value(message.get_field(&field).as_ref(), rest, texts, budget)?;
    budget.leave();
    Ok(())
}

fn collect_path_value(
    value: &ProtobufValue,
    rest: &[String],
    texts: &mut Vec<String>,
    budget: &mut GrpcWalkBudget,
) -> Result<(), ()> {
    budget.charge()?;
    match value {
        ProtobufValue::List(items) => {
            for item in items {
                collect_path_value(item, rest, texts, budget)?;
            }
        }
        ProtobufValue::String(text) if rest.is_empty() => texts.push(text.clone()),
        ProtobufValue::Message(message) if !rest.is_empty() => {
            collect_path(message, rest, texts, budget)?;
        }
        _ => {}
    }
    Ok(())
}

/// Rewrite every string value in the tree, including known extensions.
/// Returns whether anything changed.
fn redact_strings(
    message: &mut DynamicMessage,
    budget: &mut GrpcWalkBudget,
    redact: &mut impl FnMut(&str) -> String,
) -> Result<bool, ()> {
    budget.enter()?;
    let mut changed = false;
    for (_, value) in message.fields_mut() {
        changed |= redact_value(value, budget, redact)?;
    }
    for (_, value) in message.extensions_mut() {
        changed |= redact_value(value, budget, redact)?;
    }
    budget.leave();
    Ok(changed)
}

fn redact_value(
    value: &mut ProtobufValue,
    budget: &mut GrpcWalkBudget,
    redact: &mut impl FnMut(&str) -> String,
) -> Result<bool, ()> {
    budget.charge()?;
    let mut changed = false;
    match value {
        ProtobufValue::String(text) => {
            let replacement = redact(text.as_str());
            if &replacement != text {
                *text = replacement;
                changed = true;
            }
        }
        ProtobufValue::Message(message) => {
            changed |= redact_strings(message, budget, redact)?;
        }
        ProtobufValue::List(items) => {
            for item in items {
                changed |= redact_value(item, budget, redact)?;
            }
        }
        ProtobufValue::Map(entries) => {
            for entry in entries.values_mut() {
                changed |= redact_value(entry, budget, redact)?;
            }
        }
        _ => {}
    }
    Ok(changed)
}

/// Rewrite only the string values addressed by the configured dotted paths.
fn redact_paths(
    message: &mut DynamicMessage,
    paths: &[Vec<String>],
    budget: &mut GrpcWalkBudget,
    redact: &mut impl FnMut(&str) -> String,
) -> Result<bool, ()> {
    let mut changed = false;
    for path in paths {
        changed |= redact_path(message, path, budget, redact)?;
    }
    Ok(changed)
}

fn redact_path(
    message: &mut DynamicMessage,
    path: &[String],
    budget: &mut GrpcWalkBudget,
    redact: &mut impl FnMut(&str) -> String,
) -> Result<bool, ()> {
    budget.enter()?;
    let Some((segment, rest)) = path.split_first() else {
        budget.leave();
        return Ok(false);
    };
    let Some(field) = message.descriptor().get_field_by_name(segment) else {
        budget.leave();
        return Ok(false);
    };
    if !message.has_field(&field) {
        budget.leave();
        return Ok(false);
    }
    let changed = redact_path_value(message.get_field_mut(&field), rest, budget, redact)?;
    budget.leave();
    Ok(changed)
}

fn redact_path_value(
    value: &mut ProtobufValue,
    rest: &[String],
    budget: &mut GrpcWalkBudget,
    redact: &mut impl FnMut(&str) -> String,
) -> Result<bool, ()> {
    budget.charge()?;
    let mut changed = false;
    match value {
        ProtobufValue::List(items) => {
            for item in items {
                changed |= redact_path_value(item, rest, budget, redact)?;
            }
        }
        ProtobufValue::String(text) if rest.is_empty() => {
            let replacement = redact(text.as_str());
            if &replacement != text {
                *text = replacement;
                changed = true;
            }
        }
        ProtobufValue::Message(message) if !rest.is_empty() => {
            changed |= redact_path(message, rest, budget, redact)?;
        }
        _ => {}
    }
    Ok(changed)
}

/// Parse the `grpc` config block. `Ok(None)` means no gRPC inspection at all.
fn parse_grpc_shape(config: &Value) -> Result<Option<GrpcShape>, String> {
    let Some(grpc) = config.get("grpc") else {
        return Ok(None);
    };
    if !grpc.is_object() {
        return Err("ai_response_guard: 'grpc' must be an object".to_string());
    }
    reject_unknown_keys(grpc, AI_RESPONSE_GUARD_GRPC_CONFIG_KEYS, "grpc")?;

    let descriptor_path = optional_string(grpc, "descriptor_path")?
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .ok_or_else(|| {
            "ai_response_guard: 'grpc.descriptor_path' is required and must be a \
             non-empty string"
                .to_string()
        })?
        .to_string();

    let max_message_bytes = optional_positive_usize(grpc, "max_message_bytes")?
        .unwrap_or(DEFAULT_GRPC_MAX_MESSAGE_BYTES);
    let max_messages =
        optional_positive_usize(grpc, "max_messages")?.unwrap_or(DEFAULT_GRPC_MAX_MESSAGES);

    let Some(method_configs) = grpc.get("methods").and_then(Value::as_object) else {
        return Err(
            "ai_response_guard: 'grpc.methods' is required and must be an object".to_string(),
        );
    };
    if method_configs.is_empty() {
        return Err(
            "ai_response_guard: 'grpc.methods' must configure at least one method".to_string(),
        );
    }

    let mut methods: HashMap<String, GrpcMethodShape> = HashMap::new();
    for (method_path, method_config) in method_configs {
        let normalized = normalize_grpc_method_path(method_path)?;
        if !method_config.is_object() {
            return Err("ai_response_guard: a 'grpc.methods' entry must be an object".to_string());
        }
        reject_unknown_keys(
            method_config,
            AI_RESPONSE_GUARD_GRPC_METHOD_KEYS,
            "grpc.methods",
        )?;
        let response_type = optional_string(method_config, "response_type")?
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                "ai_response_guard: a 'grpc.methods' entry requires a non-empty \
                 'response_type'"
                    .to_string()
            })?
            .to_string();
        let text_fields = parse_grpc_text_fields(method_config)?;
        let shape = GrpcMethodShape {
            response_type,
            text_fields,
        };
        if methods.insert(normalized, shape).is_some() {
            return Err(
                "ai_response_guard: a 'grpc.methods' method path is configured more than once"
                    .to_string(),
            );
        }
    }

    Ok(Some(GrpcShape {
        descriptor_path,
        methods,
        max_message_bytes,
        max_messages,
    }))
}

/// Normalize a configured method key to the `/package.Service/Method` form the
/// request path and `grpc_full_method` metadata both resolve to.
///
/// Every dotted service segment and the method identifier must be a real
/// protobuf/gRPC identifier (`[A-Za-z_][A-Za-z0-9_]*`). Whitespace,
/// percent/query syntax, empty segments, invalid leading characters, and
/// extra slashes are rejected. An optional leading slash is normalized; a
/// duplicate after normalization is rejected by the caller.
fn normalize_grpc_method_path(method_path: &str) -> Result<String, String> {
    let trimmed = method_path.trim();
    if trimmed.is_empty() {
        return Err(
            "ai_response_guard: a 'grpc.methods' key must be a non-empty method path".to_string(),
        );
    }
    // Reject whitespace interior to the path (trim only clears the edges) and
    // any percent/query/fragment syntax that is not part of a gRPC method path.
    if trimmed
        .chars()
        .any(|ch| ch.is_whitespace() || matches!(ch, '%' | '?' | '#' | '&' | '=' | '+' | ';'))
    {
        return Err(
            "ai_response_guard: a 'grpc.methods' key must be a '/package.Service/Method' path"
                .to_string(),
        );
    }
    let normalized = if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    };
    let rest = &normalized[1..];
    let Some((service, method_name)) = rest.split_once('/') else {
        return Err(
            "ai_response_guard: a 'grpc.methods' key must be a '/package.Service/Method' path"
                .to_string(),
        );
    };
    if service.is_empty()
        || method_name.is_empty()
        || method_name.contains('/')
        || !is_valid_grpc_service(service)
        || !is_valid_grpc_identifier(method_name)
    {
        return Err(
            "ai_response_guard: a 'grpc.methods' key must be a '/package.Service/Method' path"
                .to_string(),
        );
    }
    Ok(normalized)
}

fn is_valid_grpc_service(service: &str) -> bool {
    service
        .split('.')
        .all(|segment| !segment.is_empty() && is_valid_grpc_identifier(segment))
}

fn is_valid_grpc_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }
    chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

/// Parse and pre-split the optional `text_fields` dotted paths.
fn parse_grpc_text_fields(method_config: &Value) -> Result<Option<Vec<Vec<String>>>, String> {
    let Some(fields) = optional_string_vec(method_config, "text_fields")? else {
        return Ok(None);
    };
    if fields.is_empty() {
        return Err(
            "ai_response_guard: 'grpc.methods' 'text_fields' must not be empty".to_string(),
        );
    }
    let mut parsed = Vec::with_capacity(fields.len());
    let mut seen = HashSet::with_capacity(fields.len());
    for field in &fields {
        let segments: Vec<String> = field
            .split('.')
            .map(|part| part.trim().to_string())
            .collect();
        if segments.iter().any(String::is_empty) {
            return Err(
                "ai_response_guard: a 'grpc.methods' 'text_fields' entry must be a dotted \
                 field path with non-empty segments"
                    .to_string(),
            );
        }
        if segments.len() > GRPC_MAX_MESSAGE_DEPTH {
            return Err(
                "ai_response_guard: a 'grpc.methods' 'text_fields' path exceeds the maximum \
                 nesting depth"
                    .to_string(),
            );
        }
        // Compare the normalized dotted form so `"a.b"` and `" a.b "` collide
        // without echoing the configured path value into the diagnostic.
        let normalized = segments.join(".");
        if !seen.insert(normalized) {
            return Err(
                "ai_response_guard: a 'grpc.methods' 'text_fields' path is configured more \
                 than once"
                    .to_string(),
            );
        }
        parsed.push(segments);
    }
    Ok(Some(parsed))
}

/// The configured descriptor path, for mode-aware file dependency validation.
pub(crate) fn grpc_descriptor_path(config: &Value) -> Result<Option<String>, String> {
    Ok(parse_grpc_shape(config)?.map(|shape| shape.descriptor_path))
}

/// Load a `FileDescriptorSet` from disk. The boolean distinguishes
/// "absent/unreadable" (true) from "present but not a descriptor set" (false).
fn load_grpc_descriptor_pool_inner(path: &str) -> Result<DescriptorPool, (bool, String)> {
    let bytes = std::fs::read(path).map_err(|_| {
        (
            true,
            "ai_response_guard: failed to read protobuf descriptor file".to_string(),
        )
    })?;
    DescriptorPool::decode(bytes.as_slice()).map_err(|_| {
        (
            false,
            "ai_response_guard: failed to parse protobuf descriptor".to_string(),
        )
    })
}

/// Resolve every enrolled method against the pool, rejecting an unknown
/// response message type or a `text_fields` path that is not a string field.
fn resolve_grpc_shape(
    shape: &GrpcShape,
    pool: &DescriptorPool,
) -> Result<HashMap<String, GrpcMethodInspection>, String> {
    let mut resolved = HashMap::with_capacity(shape.methods.len());
    for (method_path, method) in &shape.methods {
        let descriptor = pool
            .get_message_by_name(&method.response_type)
            .ok_or_else(|| {
                "ai_response_guard: a 'grpc.methods' 'response_type' was not found in the \
                 descriptor"
                    .to_string()
            })?;
        if let Some(paths) = method.text_fields.as_ref() {
            for path in paths {
                resolve_text_field_path(&descriptor, path)?;
            }
        }
        let inspection = GrpcMethodInspection {
            descriptor,
            text_fields: method.text_fields.clone(),
        };
        resolved.insert(method_path.clone(), inspection);
    }
    Ok(resolved)
}

/// Verify a dotted path addresses a string field, walking singular/repeated
/// message fields on the way. Map fields are not addressable: their keys are
/// not rewritable, so an operator must not be able to claim coverage of one.
fn resolve_text_field_path(root: &MessageDescriptor, path: &[String]) -> Result<(), String> {
    let mut current = root.clone();
    for (index, segment) in path.iter().enumerate() {
        let Some(field) = current.get_field_by_name(segment) else {
            return Err(
                "ai_response_guard: a 'grpc.methods' 'text_fields' path names a field that \
                 is not in the descriptor"
                    .to_string(),
            );
        };
        if field.is_map() {
            return Err(
                "ai_response_guard: a 'grpc.methods' 'text_fields' path may not traverse a \
                 map field"
                    .to_string(),
            );
        }
        let last = index + 1 == path.len();
        match field.kind() {
            Kind::String if last => return Ok(()),
            Kind::Message(next) if !last => current = next,
            _ => {
                return Err(
                    "ai_response_guard: a 'grpc.methods' 'text_fields' path must end at a \
                     string field"
                        .to_string(),
                );
            }
        }
    }
    Err("ai_response_guard: a 'grpc.methods' 'text_fields' path must not be empty".to_string())
}

/// Validate the `grpc` block against an already-loaded descriptor pool.
pub(crate) fn validate_grpc_descriptor_config(
    config: &Value,
    pool: &DescriptorPool,
) -> Result<(), String> {
    match parse_grpc_shape(config)? {
        Some(shape) => resolve_grpc_shape(&shape, pool).map(|_| ()),
        None => Ok(()),
    }
}

/// Build the runtime gRPC inspection contract.
///
/// A readable-but-invalid descriptor rejects the candidate configuration, so
/// the last known-good plugin generation stays in place. A descriptor that is
/// simply not present on this node keeps the enrollment set — governed methods
/// then fail closed at request time — instead of silently un-enrolling them.
fn load_grpc_inspection(
    config: &Value,
    mode: DescriptorLoadMode,
) -> Result<Option<GrpcInspection>, String> {
    let Some(shape) = parse_grpc_shape(config)? else {
        return Ok(None);
    };
    let enrolled_methods: HashSet<String> = shape.methods.keys().cloned().collect();
    let unresolved = GrpcInspection {
        methods: HashMap::new(),
        enrolled_methods: enrolled_methods.clone(),
        max_message_bytes: shape.max_message_bytes,
        max_messages: shape.max_messages,
        dependency_unavailable: true,
    };

    if matches!(mode, DescriptorLoadMode::ShapeOnly) {
        return Ok(Some(unresolved));
    }

    let pool = match load_grpc_descriptor_pool_inner(&shape.descriptor_path) {
        Ok(pool) => pool,
        Err((true, _)) => {
            warn!(
                plugin = "ai_response_guard",
                "Protobuf descriptor dependency is unavailable; enrolled gRPC methods fail closed"
            );
            return Ok(Some(unresolved));
        }
        Err((false, message)) => return Err(message),
    };

    Ok(Some(GrpcInspection {
        methods: resolve_grpc_shape(&shape, &pool)?,
        enrolled_methods,
        max_message_bytes: shape.max_message_bytes,
        max_messages: shape.max_messages,
        dependency_unavailable: false,
    }))
}

#[async_trait]
impl Plugin for AiResponseGuard {
    fn name(&self) -> &str {
        "ai_response_guard"
    }

    fn priority(&self) -> u16 {
        super::priority::AI_RESPONSE_GUARD
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        // Native gRPC is in scope only through the explicit `grpc` enrollment
        // block. Without it the plugin stays HTTP-only rather than advertising
        // inert gRPC enforcement or forcing protobuf responses to buffer.
        if self.grpc.is_some() {
            super::HTTP_GRPC_PROTOCOLS
        } else {
            super::HTTP_ONLY_PROTOCOLS
        }
    }

    fn requires_response_body_buffering(&self) -> bool {
        self.has_validation_rules
    }

    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        // A native-gRPC response is buffered only for a method the operator
        // enrolled: an un-enrolled method has no decodable contract, so pinning
        // it to the buffered path would cost streaming for no enforcement.
        if ctx.is_native_grpc_request() {
            return self.has_validation_rules && self.grpc_inspection_applies(ctx);
        }
        // Client-controlled streaming intent is not response evidence. Buffer
        // conservatively until the pristine backend Content-Type is known.
        self.has_validation_rules
    }

    fn may_release_response_body_under_retries(&self, ctx: &RequestContext) -> bool {
        // An enrolled native-gRPC method is governed by framing and descriptor,
        // never by a backend-controlled response media-type label.
        self.should_buffer_response_body(ctx) && !ctx.is_native_grpc_request()
    }

    fn should_release_response_body_under_retries(
        &self,
        ctx: &RequestContext,
        _response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        self.should_buffer_response_body(ctx)
            && !ctx.is_native_grpc_request()
            && original_response_is_event_stream(ctx, response_headers)
    }

    fn should_release_response_body_before_content_type_rewrite(
        &self,
        ctx: &RequestContext,
        _response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        self.should_buffer_response_body(ctx)
            && !ctx.is_native_grpc_request()
            && original_response_is_event_stream(ctx, response_headers)
    }

    fn should_buffer_response_body_for_content_type(
        &self,
        ctx: &RequestContext,
        content_type: Option<&str>,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        self.should_buffer_response_body(ctx)
            && (ctx.is_native_grpc_request()
                || !content_type.is_some_and(is_text_event_stream_media_type))
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !ctx.is_native_grpc_request()
            && self.should_buffer_response_body(ctx)
            && original_response_is_event_stream(ctx, response_headers)
        {
            // This plugin's buffered SSE parser cannot safely decide an
            // unbounded stream before any bytes are committed. Reject for every
            // enforcing/redacting policy; warn-only configurations retain their
            // documented pass-through posture and record the explicit skip.
            return self.respond_to_uninspectable(
                ctx,
                "streaming_response_requires_bounded_inspection",
                "event-stream responses cannot be fully inspected before delivery",
            );
        }
        PluginResult::Continue
    }

    async fn on_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &mut HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Native gRPC framing has its own descriptor-based contract; the
        // JSON/SSE/text document model below never applies to it.
        if ctx.is_native_grpc_request() {
            return self.inspect_grpc_response(ctx, response_status, response_headers, body);
        }

        // Enforce the aggregate scan/work bound before the successful-response
        // content gate. Buffered non-2xx error bodies still reach the transform
        // phase, so returning before this check would let a large raw body evade
        // the configured fail-closed/warn disposition and reach a redaction
        // regex pass outside the bound.
        if body.len() > self.max_scan_bytes {
            debug!(
                body_size = body.len(),
                max_scan_bytes = self.max_scan_bytes,
                "ai_response_guard: rejecting or warning on oversized governed response"
            );
            return self.respond_to_uninspectable(
                ctx,
                "body_exceeds_max_scan_bytes",
                "response body exceeds max_scan_bytes",
            );
        }

        // Content governance remains scoped to successful responses. The size
        // policy above is representation-independent and applies to every
        // buffered status.
        if !(200..300).contains(&response_status) {
            return PluginResult::Continue;
        }

        let content_type = response_headers
            .get("content-type")
            .map(|s| s.as_str())
            .unwrap_or("");

        let is_sse = is_text_event_stream_media_type(content_type);
        let is_json = is_json_content_type(content_type);

        if body.is_empty() {
            if self.require_json || !self.required_fields.is_empty() {
                return self.respond_to_uninspectable(
                    ctx,
                    "empty_response_body",
                    "response body is empty",
                );
            }
            return PluginResult::Continue;
        }

        // A gRPC-framed response reaching the JSON/SSE/text model belongs to a
        // request that is not native gRPC (a native one returned above), so the
        // descriptor contract cannot name a message type for it and
        // `transform_response_body` declines these bytes. Scanning length-
        // prefixed frames as a raw text document would let `scan_mode: all`
        // report a redaction the transform can never apply; fail closed for
        // enforcing actions instead, exactly as content mode already does.
        //
        // gRPC-Web is the same grammar and the same hazard, and it is what a
        // browser client on a mixed route actually sends: its request flavor is
        // `Plain`, so it never reaches `inspect_grpc_response` above, and
        // `grpc_web`'s `after_proxy` has already relabeled the response to
        // `application/grpc-web*` — a native-gRPC media-type test alone would
        // let those frames through to the text redactor.
        if response_is_grpc_framed(ctx, Some(content_type), body) {
            return self.respond_to_uninspectable(
                ctx,
                "grpc_framed_response_requires_grpc_contract",
                "gRPC-framed responses are only inspectable through the grpc enrollment contract",
            );
        }

        // --- SSE path: parse frames, extract accumulated texts, detect ---
        if is_sse {
            if self.require_json || !self.required_fields.is_empty() {
                return self.respond_to_uninspectable(
                    ctx,
                    "sse_cannot_satisfy_json_structure",
                    "SSE is not a single JSON response",
                );
            }
            let parsed = parse_sse_data_frames_checked(body);
            if !parsed.fully_parsed {
                return self.respond_to_uninspectable(
                    ctx,
                    "uninspectable_sse",
                    "SSE contains malformed, non-JSON, or non-UTF-8 data",
                );
            }
            let frames = parsed.frames;
            if frames.is_empty() && self.scan_mode != ScanMode::All {
                return PluginResult::Continue;
            }

            let accumulated = self.extract_sse_completion_texts(&frames);

            // Check max completion length on accumulated text
            if self.max_completion_length > 0 {
                let refs: Vec<&str> = accumulated.iter().map(|s| s.as_str()).collect();
                if let Some(reason) = self.check_completion_length(&refs) {
                    match self.action {
                        GuardAction::Reject | GuardAction::Redact => {
                            Self::mark_rejected(ctx, reason.clone());
                            return PluginResult::Reject {
                                status_code: 502,
                                body: format!(
                                    r#"{{"error":"AI response guard: {}"}}"#,
                                    escape_json_string(&reason)
                                ),
                                headers: HashMap::new(),
                            };
                        }
                        GuardAction::Warn => {
                            ctx.metadata
                                .insert("ai_response_guard_warning".to_string(), reason);
                        }
                    }
                }
            }

            let detected = if self.scan_mode == ScanMode::All {
                self.detect_matches_in_decoded_sse_frames(&frames, std::str::from_utf8(body).ok())
            } else {
                let refs: Vec<&str> = accumulated.iter().map(|s| s.as_str()).collect();
                self.detect_matches(&refs)
            };

            if detected.is_empty() {
                return PluginResult::Continue;
            }

            let retained_ceiling = ctx.retained_response_body_ceiling();
            if self.action == GuardAction::Redact
                && self.redact_sse_leaves_residual(body, retained_ceiling)
            {
                debug!(
                    "ai_response_guard: redact leaves residual SSE content (types: {:?}), rejecting response",
                    detected
                );
                let types_json: Vec<String> = detected
                    .iter()
                    .map(|t| format!("\"{}\"", escape_json_string(t)))
                    .collect();
                Self::mark_rejected(ctx, detected.join(","));
                return PluginResult::Reject {
                    status_code: 502,
                    body: format!(
                        r#"{{"error":"AI response blocked by content guard","detected_types":[{}],"message":"Response contains restricted content that could not be redacted before delivery."}}"#,
                        types_json.join(","),
                    ),
                    headers: HashMap::new(),
                };
            }

            return self.respond_to_detection(ctx, response_status, &detected);
        }

        // Scan-all can safely inspect arbitrary UTF-8 representations as raw
        // text. Structured content mode has no completion mapping for them, so
        // enforcing actions fail closed instead of silently passing through.
        if !is_json && !self.require_json && self.required_fields.is_empty() {
            if self.scan_mode == ScanMode::All {
                let Ok(text) = std::str::from_utf8(body) else {
                    return self.respond_to_uninspectable(
                        ctx,
                        "non_utf8_response",
                        "response body is not valid UTF-8",
                    );
                };
                if let Some(reason) = self.check_completion_length(&[text]) {
                    match self.action {
                        GuardAction::Reject | GuardAction::Redact => {
                            Self::mark_rejected(ctx, reason.clone());
                            return PluginResult::Reject {
                                status_code: 502,
                                body: format!(
                                    r#"{{"error":"AI response guard: {}"}}"#,
                                    escape_json_string(&reason)
                                ),
                                headers: HashMap::new(),
                            };
                        }
                        GuardAction::Warn => {
                            ctx.metadata
                                .insert("ai_response_guard_warning".to_string(), reason);
                        }
                    }
                }
                let detected = self.detect_matches(&[text]);
                return if detected.is_empty() {
                    PluginResult::Continue
                } else {
                    self.respond_to_detection(ctx, response_status, &detected)
                };
            }
            return self.respond_to_uninspectable(
                ctx,
                "unsupported_response_content_type",
                "response content type is not inspectable in content mode",
            );
        }

        // --- JSON path ---

        // Parse JSON
        let json: Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(_) => {
                return self.respond_to_uninspectable(
                    ctx,
                    "invalid_json",
                    "response body is not valid JSON",
                );
            }
        };

        // Check required fields
        for field in &self.required_fields {
            if json.get(field.as_str()).is_none() {
                Self::mark_rejected(ctx, format!("missing_required_field:{field}"));
                return PluginResult::Reject {
                    status_code: 502,
                    body: format!(
                        r#"{{"error":"AI response missing required field: \"{}\""}}"#,
                        escape_json_string(field)
                    ),
                    headers: HashMap::new(),
                };
            }
        }

        // Pattern detection in scan-all is handled separately below, but the
        // completion-length rule is independent of scan mode and must still
        // inspect supported completion/tool fields.
        let texts = if self.scan_mode == ScanMode::Content || self.max_completion_length > 0 {
            self.extract_completion_texts(&json)
        } else {
            Vec::new()
        };

        // Check max completion length
        if !texts.is_empty()
            && let Some(reason) = self.check_completion_length(&texts)
        {
            match self.action {
                GuardAction::Reject | GuardAction::Redact => {
                    Self::mark_rejected(ctx, reason.clone());
                    return PluginResult::Reject {
                        status_code: 502,
                        body: format!(
                            r#"{{"error":"AI response guard: {}"}}"#,
                            escape_json_string(&reason)
                        ),
                        headers: HashMap::new(),
                    };
                }
                GuardAction::Warn => {
                    ctx.metadata
                        .insert("ai_response_guard_warning".to_string(), reason);
                }
            }
        }

        // Detect PII and blocked content
        let detected = if self.scan_mode == ScanMode::All {
            self.detect_matches_in_decoded_json(&json, std::str::from_utf8(body).ok())
        } else {
            self.detect_matches(&texts)
        };

        if detected.is_empty() {
            return PluginResult::Continue;
        }

        // Redact mode can detect PII the redactor cannot rewrite — in scan-all,
        // object keys, numeric scalars, cross-token custom patterns, and
        // duplicate-key values; in content mode, matches that exist only across
        // adjacent content-array parts and decoded tool-argument keys/numbers.
        // Forwarding such a body while reporting it `redacted` would leak PII,
        // so fail closed (reject) when redaction would leave residual
        // detections rather than emit false "redacted" telemetry. Bodies whose
        // PII is fully rewritable fall through to the normal redact path below.
        //
        // Both residual scans build a COMPLETE redacted candidate (a cloned
        // document tree, and in scan-all its serialized form) during INSPECTION,
        // where no producer phase has reserved anything. That candidate is
        // upstream-shaped and the same order of size as the response, so it is
        // charged like any other retained allocation: a window sized to this
        // response's retained ceiling is reserved before the candidate exists
        // and released as soon as the scan is done, keeping the peak at the
        // documented two ceilings. A budget that cannot admit the window is a
        // refusal, and a refusal is residual — fail closed rather than build the
        // candidate anyway (GHSA-pwcm-6rh8-f2gh).
        let leaves_residual = self.action == GuardAction::Redact
            && match crate::proxy::response_buffer_budget::ResponseTransformWindow::open(
                ctx.retained_response_body_ceiling(),
            ) {
                Some(window) => {
                    let residual = if self.scan_mode == ScanMode::All {
                        self.redact_leaves_residual(&json)
                    } else {
                        self.content_redact_leaves_residual(&json)
                    };
                    drop(window);
                    residual
                }
                None => true,
            };
        if leaves_residual {
            debug!(
                "ai_response_guard: redact leaves residual content (types: {:?}), rejecting response",
                detected
            );
            let types_json: Vec<String> = detected
                .iter()
                .map(|t| format!("\"{}\"", escape_json_string(t)))
                .collect();
            Self::mark_rejected(ctx, detected.join(","));
            return PluginResult::Reject {
                status_code: 502,
                body: format!(
                    r#"{{"error":"AI response blocked by content guard","detected_types":[{}],"message":"Response contains restricted content that could not be redacted before delivery."}}"#,
                    types_json.join(","),
                ),
                headers: HashMap::new(),
            };
        }

        self.respond_to_detection(ctx, response_status, &detected)
    }

    async fn transform_response_body_with_context(
        &self,
        ctx: &mut RequestContext,
        body: &[u8],
        content_type: Option<&str>,
        response_headers: &HashMap<String, String>,
    ) -> crate::plugins::ResponseBodyTransformOutcome {
        // Protobuf redaction needs the request's gRPC method to select the
        // message descriptor, which only the context carries.
        // Every replacement this plugin produces is built inside a
        // materialisation bounded by THIS response's retained ceiling — the same
        // size as the window the transform phase reserved before invoking it —
        // so an amplifying redaction is refused during construction rather than
        // after a larger buffer is resident (GHSA-pwcm-6rh8-f2gh).
        let ceiling = ctx.retained_response_body_ceiling();
        if self.grpc_transform_applies(ctx, content_type) {
            let replacement = crate::plugins::ResponseBodyTransformOutcome::from_optional_replacement(
                self.redacted_grpc_body(ctx, response_headers, body, ceiling),
            );
            return self.discharge_pending_redaction(ctx, replacement);
        }
        // A gRPC or gRPC-Web response body is length-prefixed protobuf framing
        // — or the base64 armoring of it — whatever the response `Content-Type`
        // claims. The JSON/SSE/text rewriter below cannot address that
        // representation, and its `scan_fields: all` branch would regex-rewrite
        // raw frame bytes whenever they happen to be valid UTF-8, changing a
        // payload's length without its 5-byte prefix and corrupting the wire.
        //
        // The request flavor alone cannot gate this: a gRPC-Web request is
        // `HttpFlavor::Plain`, so keying on `is_native_grpc_request()` would
        // leave every browser gRPC client — translated by `grpc_web` (which
        // re-frames at priority 260, before this transform) or passed through
        // to a gRPC-Web backend — exposed to the text redactor. Only the
        // descriptor contract above may rewrite these bytes; when it does not
        // apply, `on_response_body` has already failed closed under the same
        // predicate for anything it detected, so deliver them unchanged.
        if ctx.is_native_grpc_request() || response_is_grpc_framed(ctx, content_type, body) {
            return crate::plugins::ResponseBodyTransformOutcome::Unchanged;
        }
        let replacement = crate::plugins::ResponseBodyTransformOutcome::from_optional_replacement(
            self.redacted_response_body(body, content_type, ceiling),
        );
        self.discharge_pending_redaction(ctx, replacement)
    }

    /// Context-free entry point. Without a request context there is no
    /// route-effective ceiling, so it falls back to the process fail-closed
    /// retained ceiling — still finite, just looser than the per-response one
    /// production uses through the hook above.
    async fn transform_response_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        _response_headers: &HashMap<String, String>,
    ) -> crate::plugins::ResponseBodyTransformOutcome {
        crate::plugins::ResponseBodyTransformOutcome::from_optional_replacement(
            self.redacted_response_body(
                body,
                content_type,
                crate::proxy::response_buffer_budget::buffered_response_body_ceiling(0),
            ),
        )
    }

    fn requires_replay_response_body_transform(&self, ctx: &RequestContext) -> bool {
        ctx.ai_response_guard_replay_redactions
            .contains(&self.instance_id)
    }

    /// The final verification seam for a promised redaction.
    ///
    /// A `redact` detection returns `Continue` from inspection and relies on the
    /// producer phase to install the replacement. Every way that can fail —
    /// a refused retained ceiling, a refused scratch pass, a serialization
    /// error, a representation the rewriter declines — surfaces as `None`, which
    /// the shared transform loop reads as "unchanged". This hook runs after
    /// every transform over the bytes the client would actually receive, so an
    /// undischarged promise here means the original detected body is still in
    /// flight and must be replaced by a rejection rather than delivered
    /// (GHSA-pwcm-6rh8-f2gh).
    ///
    /// The gateway's own capacity terminal is not affected: when the transform
    /// phase installs it, the response is already replaced and this hook is not
    /// reached at all.
    async fn on_final_response_body(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
        _body: &[u8],
    ) -> PluginResult {
        let Some(detected) = ctx
            .ai_response_guard_pending_redactions
            .remove(&self.instance_id)
        else {
            return PluginResult::Continue;
        };
        warn!(
            "ai_response_guard: detected content was not redacted before delivery (types: {}), rejecting response",
            detected
        );
        Self::mark_rejected(ctx, detected.clone());
        let types_json: Vec<String> = detected
            .split(',')
            .filter(|name| !name.is_empty())
            .map(|name| format!("\"{}\"", escape_json_string(name)))
            .collect();
        PluginResult::Reject {
            status_code: 502,
            body: format!(
                r#"{{"error":"AI response blocked by content guard","detected_types":[{}],"message":"Response contains restricted content that could not be redacted before delivery."}}"#,
                types_json.join(","),
            ),
            headers: HashMap::new(),
        }
    }

    fn on_response_body_transformed(
        &self,
        _ctx: &mut RequestContext,
        response_headers: &mut HashMap<String, String>,
    ) {
        // These values describe the upstream representation and become stale
        // whenever redaction changes the client-visible bytes. The proxy calls
        // this hook only after a transform returns `Some`, so clean bodies keep
        // their validators.
        response_headers.retain(|key, _| {
            !RESPONSE_VALIDATORS
                .iter()
                .any(|header| key.eq_ignore_ascii_case(header))
        });
    }
}

impl AiResponseGuard {
    /// Clear this instance's promised-redaction marker when — and only when — a
    /// replacement was actually produced.
    ///
    /// [`crate::plugins::ResponseBodyTransformOutcome::Unchanged`] (and
    /// capacity refusal) leaves the marker outstanding, so
    /// `on_final_response_body` turns it into a rejection instead of letting
    /// the original detected body be forwarded as "unchanged".
    fn discharge_pending_redaction(
        &self,
        ctx: &mut RequestContext,
        replacement: crate::plugins::ResponseBodyTransformOutcome,
    ) -> crate::plugins::ResponseBodyTransformOutcome {
        if matches!(
            replacement,
            crate::plugins::ResponseBodyTransformOutcome::Replaced(_)
        ) {
            ctx.ai_response_guard_pending_redactions
                .remove(&self.instance_id);
        }
        replacement
    }

    /// The single ceiling-bounded materialisation point for this plugin's
    /// JSON / SSE / text replacement bodies.
    fn redacted_response_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        ceiling: usize,
    ) -> Option<Vec<u8>> {
        if !self.needs_body_transform {
            return None;
        }

        // Native gRPC and gRPC-Web bodies are only ever rewritten through the
        // context-carrying entry point above, which knows the method contract.
        if content_type.is_some_and(is_framed_grpc_content_type) {
            return None;
        }

        // This check intentionally precedes content-type dispatch and UTF-8
        // conversion. Raw non-JSON bodies (including non-2xx error text skipped
        // by content inspection) must never enter regex redaction above the
        // configured aggregate scan/work limit.
        if body.len() > self.max_scan_bytes {
            return None;
        }

        if let Some(ct) = content_type {
            if is_text_event_stream_media_type(ct) {
                let redacted = self.redact_sse_body(body, ceiling)?;
                return (!self.sse_body_has_residual(&redacted)).then_some(redacted);
            }
            if !is_json_content_type(ct) {
                if self.scan_mode != ScanMode::All {
                    return None;
                }
                let text = std::str::from_utf8(body).ok()?;
                let redacted = self.redact_text_bounded(text, ceiling)?;
                if redacted == text.as_bytes() {
                    return None;
                }
                return Some(redacted);
            }
        }

        let mut json: Value = match serde_json::from_slice(body) {
            Ok(json) => json,
            Err(_) if self.scan_mode == ScanMode::All => {
                let text = std::str::from_utf8(body).ok()?;
                let redacted = self.redact_text_bounded(text, ceiling)?;
                if redacted == text.as_bytes() {
                    return None;
                }
                return Some(redacted);
            }
            Err(_) => return None,
        };

        if self.scan_mode == ScanMode::All {
            if self
                .detect_matches_in_decoded_json(&json, std::str::from_utf8(body).ok())
                .is_empty()
            {
                return None;
            }
            // `on_response_body` rejects this case in the normal pipeline.
            // Keep the transform independently representation-safe as well:
            // never mutate decoded keys, numbers, duplicate members, or other
            // matches the value-only redactor cannot rewrite.
            if self.redact_leaves_residual(&json) {
                return None;
            }
            self.redact_all_strings_with_argument_shield(&mut json);
        } else {
            let texts = self.extract_completion_texts(&json);
            let has_match = !self.detect_matches(&texts).is_empty();
            if !has_match {
                return None;
            }
            if self.content_redact_leaves_residual(&json) {
                return None;
            }
            self.redact_response_json(&mut json);
        }

        crate::proxy::response_buffer_budget::bounded_json_vec(&json, ceiling)
    }
}

/// One `replace_all` pass with a LITERAL replacement, written through `sink`.
///
/// Equivalent to `regex.replace_all(text, NoExpand(placeholder))`: `replace_all`
/// iterates the same non-overlapping match sequence `find_iter` yields, and a
/// `NoExpand` replacement is emitted verbatim with no capture-group expansion.
/// The difference is only that the result is written incrementally instead of
/// being returned as a complete `String` (GHSA-pwcm-6rh8-f2gh).
fn write_pattern_replaced(
    sink: &mut crate::proxy::response_buffer_budget::BoundedResponseBodySink,
    regex: &Regex,
    placeholder: &str,
    text: &str,
) -> bool {
    let bytes = text.as_bytes();
    let mut last = 0;
    for matched in regex.find_iter(text) {
        if !sink.push(&bytes[last..matched.start()]) || !sink.push(placeholder.as_bytes()) {
            return false;
        }
        last = matched.end();
    }
    sink.push(&bytes[last..])
}

/// Blank scalar values under the root response/event keys whose values are
/// protocol metadata rather than model-authored content. The same carve-out is
/// used by buffered JSON and buffered SSE residual scans.
fn blank_top_level_structural_scalars(value: &mut Value) {
    if let Value::Object(map) = value {
        for (key, value) in map.iter_mut() {
            if STRUCTURAL_KEYS.contains(&key.as_str()) && (value.is_string() || value.is_number()) {
                *value = Value::String(String::new());
            }
        }
    }
}

/// Rewrite one SSE event's JSON `data:` payload straight into `output`.
///
/// Returns:
/// - `Some(false)` when the event is unchanged (nothing written; caller copies
///   the original lines);
/// - `Some(true)` when the rewritten event was framed/serialized into `output`;
/// - `None` when construction was refused (overflow, serialization failure).
///
/// The rewritten JSON and event framing are written THROUGH the ceiling-aware
/// sink from the first byte — never as a complete would-be event `String`
/// beside it (GHSA-pwcm-6rh8-f2gh). Placeholder expansion and JSON escaping
/// that amplify past the ceiling are therefore refused DURING construction.
fn rewrite_sse_json_event_into(
    output: &mut crate::proxy::response_buffer_budget::BoundedResponseBodySink,
    lines: &[&str],
    mutate: impl FnOnce(&mut Value),
) -> Option<bool> {
    let mut data_lines = Vec::new();
    let mut payloads = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let content = line
            .strip_suffix("\r\n")
            .or_else(|| line.strip_suffix('\n'))
            .unwrap_or(line);
        if let Some(data) = content
            .strip_prefix("data: ")
            .or_else(|| content.strip_prefix("data:"))
        {
            data_lines.push(idx);
            payloads.push(data);
        }
    }
    if payloads.is_empty() {
        return Some(false);
    }

    let joined = payloads.join("\n");
    let trimmed = joined.trim();
    if trimmed.is_empty() || trimmed == "[DONE]" {
        return Some(false);
    }
    let Ok(mut json) = serde_json::from_str::<Value>(trimmed) else {
        // Unparseable data payloads are left untouched, matching the unbounded
        // rewriter and the historical no-op semantics for non-JSON frames.
        return Some(false);
    };
    let original = json.clone();
    mutate(&mut json);
    if json == original {
        return Some(false);
    }

    let first_data_line = data_lines[0];
    for (idx, line) in lines.iter().enumerate() {
        if idx == first_data_line {
            let ending: &[u8] = if line.ends_with("\r\n") {
                b"\r\n"
            } else if line.ends_with('\n') {
                b"\n"
            } else {
                b""
            };
            if !output.push(b"data: ") {
                return None;
            }
            // Serialize the rewritten frame directly into the sink. An amplifying
            // rewrite (placeholder expansion, JSON escaping) stops at the ceiling
            // instead of materialising a complete over-budget event first.
            if serde_json::to_writer(&mut *output, &json).is_err() {
                return None;
            }
            if !ending.is_empty() && !output.push(ending) {
                return None;
            }
        } else if data_lines.binary_search(&idx).is_err() && !output.push(line.as_bytes()) {
            return None;
        }
    }
    Some(true)
}

/// Apply an event-level rewrite across a buffered SSE body while preserving
/// event order, non-data fields, separators, and LF/CRLF framing.
fn rewrite_sse_events<'a>(
    body: &'a str,
    mut rewrite_event: impl FnMut(&[&'a str]) -> Option<String>,
) -> (String, bool) {
    let mut output = String::with_capacity(body.len());
    let mut event_lines: Vec<&'a str> = Vec::new();
    for line in body.split_inclusive('\n') {
        event_lines.push(line);
        let content = line
            .strip_suffix("\r\n")
            .or_else(|| line.strip_suffix('\n'))
            .unwrap_or(line);
        if content.is_empty() {
            if let Some(rewritten) = rewrite_event(&event_lines) {
                output.push_str(&rewritten);
            } else {
                for original in &event_lines {
                    output.push_str(original);
                }
            }
            event_lines.clear();
        }
    }
    if !event_lines.is_empty() {
        if let Some(rewritten) = rewrite_event(&event_lines) {
            output.push_str(&rewritten);
        } else {
            for original in &event_lines {
                output.push_str(original);
            }
        }
    }

    let modified = output != body;
    (output, modified)
}

/// Ceiling-bounded SSE rewrite: each event is serialized/framed into the sink
/// from the first output byte.
///
/// The client-visible replacement is assembled one event at a time, so the only
/// full-size representation alive at any moment is the bounded output itself —
/// never a complete rewritten event `String` that a bounded copy would measure
/// afterwards (GHSA-pwcm-6rh8-f2gh). Per-event parse state is still derived from
/// the already-charged input and is bounded by one event of that input.
///
/// `rewrite_event` returns:
/// - `Some(false)` when the event is unchanged (caller copies original lines);
/// - `Some(true)` when the rewriter already wrote the replacement into `output`;
/// - `None` when construction was refused.
///
/// `modified` is true when at least one event was rewritten.
///
/// `None` means a write was refused; the caller must leave the response
/// unchanged / fail closed per its own contract.
fn rewrite_sse_events_bounded<'a>(
    body: &'a str,
    ceiling: usize,
    mut rewrite_event: impl FnMut(
        &mut crate::proxy::response_buffer_budget::BoundedResponseBodySink,
        &[&'a str],
    ) -> Option<bool>,
) -> Option<(Vec<u8>, bool)> {
    use crate::proxy::response_buffer_budget::BoundedResponseBodySink;

    fn flush_event(
        output: &mut BoundedResponseBodySink,
        modified: &mut bool,
        event_lines: &[&str],
        rewritten: Option<bool>,
    ) -> bool {
        match rewritten {
            Some(true) => {
                *modified = true;
                true
            }
            Some(false) => {
                for original in event_lines {
                    if !output.push(original.as_bytes()) {
                        return false;
                    }
                }
                true
            }
            None => false,
        }
    }

    let mut output = BoundedResponseBodySink::with_ceiling(ceiling);
    let mut modified = false;
    let mut event_lines: Vec<&'a str> = Vec::new();
    for line in body.split_inclusive('\n') {
        event_lines.push(line);
        let content = line
            .strip_suffix("\r\n")
            .or_else(|| line.strip_suffix('\n'))
            .unwrap_or(line);
        if content.is_empty() {
            let rewritten = rewrite_event(&mut output, &event_lines);
            if !flush_event(&mut output, &mut modified, &event_lines, rewritten) {
                return None;
            }
            event_lines.clear();
        }
    }
    if !event_lines.is_empty() {
        let rewritten = rewrite_event(&mut output, &event_lines);
        if !flush_event(&mut output, &mut modified, &event_lines, rewritten) {
            return None;
        }
    }

    Some((output.finish()?, modified))
}

/// Return the byte offset immediately after a JSON string beginning at
/// `start`. The containing payload has already passed `serde_json` parsing;
/// `None` still fails the residual check closed rather than guessing at spans.
fn json_string_end(bytes: &[u8], start: usize) -> Option<usize> {
    if bytes.get(start) != Some(&b'"') {
        return None;
    }
    let mut index = start + 1;
    while let Some(byte) = bytes.get(index) {
        match byte {
            b'\\' => index = index.checked_add(2)?,
            b'"' => return index.checked_add(1),
            _ => index += 1,
        }
    }
    None
}

fn skip_json_whitespace(bytes: &[u8], mut index: usize) -> usize {
    while bytes
        .get(index)
        .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
    {
        index += 1;
    }
    index
}

/// Return the byte offset immediately after one JSON value. The caller only
/// asks for values in a payload already parsed by `serde_json`.
fn json_value_end(bytes: &[u8], start: usize) -> Option<usize> {
    match bytes.get(start)? {
        b'"' => json_string_end(bytes, start),
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut index = start;
            while let Some(byte) = bytes.get(index) {
                match byte {
                    b'"' => index = json_string_end(bytes, index)?,
                    b'{' | b'[' => {
                        depth = depth.checked_add(1)?;
                        index += 1;
                    }
                    b'}' | b']' => {
                        depth = depth.checked_sub(1)?;
                        index += 1;
                        if depth == 0 {
                            return Some(index);
                        }
                    }
                    _ => index += 1,
                }
            }
            None
        }
        _ => {
            let mut index = start;
            while bytes.get(index).is_some_and(|byte| {
                !matches!(byte, b' ' | b'\n' | b'\r' | b'\t' | b',' | b'}' | b']')
            }) {
                index += 1;
            }
            (index > start).then_some(index)
        }
    }
}

/// Locate exact byte spans of string/number values held by structural keys in
/// the root JSON object. Scanning the original serialization preserves
/// contextual whitespace for the residual raw pass. For duplicate object
/// members, a scalar is maskable only when it is the last occurrence of its
/// structural key, matching the `serde_json::Value` that redaction actually
/// inspected. A later non-scalar leaves no maskable span for that key, so no
/// overwritten duplicate value is hidden from residual detection.
fn top_level_structural_scalar_spans(
    raw: &str,
    json: &Value,
) -> Option<[Option<std::ops::Range<usize>>; STRUCTURAL_KEY_COUNT]> {
    if !json.is_object() {
        return Some(std::array::from_fn(|_| None));
    }

    let bytes = raw.as_bytes();
    let mut index = skip_json_whitespace(bytes, 0);
    if bytes.get(index) != Some(&b'{') {
        return None;
    }
    index += 1;
    // One slot per known structural key records the scalar span from its last
    // root-object occurrence. A later non-scalar explicitly clears the slot:
    // serde retains that later value, so no earlier scalar was inspected by
    // the structural redactor and none may be hidden from the raw pass. The
    // fixed array avoids per-key strings and heap growth on the response path.
    let mut last_scalar_spans: [Option<std::ops::Range<usize>>; STRUCTURAL_KEY_COUNT] =
        std::array::from_fn(|_| None);

    loop {
        index = skip_json_whitespace(bytes, index);
        if bytes.get(index) == Some(&b'}') {
            break;
        }

        let key_start = index;
        let key_end = json_string_end(bytes, key_start)?;
        let raw_key = raw.get(key_start..key_end)?;
        let key: Cow<'_, str> = if raw_key.as_bytes().contains(&b'\\') {
            Cow::Owned(serde_json::from_str::<String>(raw_key).ok()?)
        } else {
            Cow::Borrowed(raw_key.get(1..raw_key.len().checked_sub(1)?)?)
        };

        index = skip_json_whitespace(bytes, key_end);
        if bytes.get(index) != Some(&b':') {
            return None;
        }
        index = skip_json_whitespace(bytes, index + 1);
        let value_start = index;
        let value_end = json_value_end(bytes, value_start)?;

        if let Some(key_index) = STRUCTURAL_KEYS
            .iter()
            .position(|structural| *structural == key.as_ref())
        {
            last_scalar_spans[key_index] = match bytes.get(value_start) {
                Some(b'"' | b'-' | b'0'..=b'9') => Some(value_start..value_end),
                _ => None,
            };
        }

        index = skip_json_whitespace(bytes, value_end);
        match bytes.get(index) {
            Some(b',') => index += 1,
            Some(b'}') => break,
            _ => return None,
        }
    }

    Some(last_scalar_spans)
}

/// Mask top-level structural scalar bytes in one SSE event without otherwise
/// changing its data fields, duplicate JSON members, whitespace, or framing.
fn mask_sse_event_structural_scalars(lines: &[&str]) -> Result<Option<String>, ()> {
    let mut fragments = vec![None; lines.len()];
    let mut payloads = Vec::new();
    let mut joined_len = 0usize;

    for (line_index, line) in lines.iter().enumerate() {
        let content = line
            .strip_suffix("\r\n")
            .or_else(|| line.strip_suffix('\n'))
            .unwrap_or(line);
        let payload_start = if content.starts_with("data: ") {
            6
        } else if content.starts_with("data:") {
            5
        } else {
            continue;
        };
        let payload = content.get(payload_start..).ok_or(())?;
        if !payloads.is_empty() {
            joined_len = joined_len.checked_add(1).ok_or(())?;
        }
        fragments[line_index] = Some((payload_start, joined_len, payload.len()));
        joined_len = joined_len.checked_add(payload.len()).ok_or(())?;
        payloads.push(payload);
    }

    if payloads.is_empty() {
        return Ok(None);
    }
    let joined = payloads.join("\n");
    let trimmed = joined.trim();
    if trimmed.is_empty() || trimmed == "[DONE]" {
        return Ok(None);
    }
    let json = serde_json::from_str::<Value>(trimmed).map_err(|_| ())?;
    let spans = top_level_structural_scalar_spans(&joined, &json).ok_or(())?;
    if spans.iter().all(Option::is_none) {
        return Ok(None);
    }

    // One byte per joined payload byte, bounded by the already-enforced
    // `max_scan_bytes`. Keeping a flat mask makes this O(body + spans), even
    // for attacker-controlled events with many data lines or root members.
    let mut mask = vec![false; joined.len()];
    for span in spans.into_iter().flatten() {
        let bytes = joined.as_bytes();
        let (start, end) = if span.end > span.start + 1
            && bytes.get(span.start) == Some(&b'"')
            && bytes.get(span.end - 1) == Some(&b'"')
        {
            (span.start + 1, span.end - 1)
        } else {
            (span.start, span.end)
        };
        mask.get_mut(start..end).ok_or(())?.fill(true);
    }

    let mut output = String::with_capacity(lines.iter().map(|line| line.len()).sum());
    for (line_index, line) in lines.iter().enumerate() {
        let Some((payload_start, joined_start, payload_len)) = fragments[line_index] else {
            output.push_str(line);
            continue;
        };
        let mut bytes = line.as_bytes().to_vec();
        for offset in 0..payload_len {
            if mask.get(joined_start + offset).copied().ok_or(())? {
                *bytes.get_mut(payload_start + offset).ok_or(())? = b' ';
            }
        }
        output.push_str(std::str::from_utf8(&bytes).map_err(|_| ())?);
    }
    Ok(Some(output))
}

/// Mask structural scalar spans across a complete buffered SSE body. Any
/// unexpected parse or offset failure returns `None` so enforcement fails
/// closed instead of scanning an incomplete sanitized representation.
fn mask_sse_top_level_structural_scalars(body: &str) -> Option<String> {
    let mut failed = false;
    let (output, _) = rewrite_sse_events(body, |lines| {
        match mask_sse_event_structural_scalars(lines) {
            Ok(rewritten) => rewritten,
            Err(()) => {
                failed = true;
                None
            }
        }
    });
    (!failed).then_some(output)
}

/// Collect every decoded JSON token for `ScanMode::All` detection so the
/// decoded walker matches the coverage of the original raw-body scan.
///
/// Serde has already resolved `\uXXXX` and other JSON string escapes here, so
/// detection sees the same text the client will receive after parsing — the
/// coverage gap issue #1720 closed.
///
/// Collected, mirroring the raw-body scan this supplements:
/// - String values (borrowed `&str`).
/// - Object keys (borrowed `&str`) — e.g. `{"a@b.com":"ok"}`, whose key the raw
///   scan caught but a values-only walk would drop.
/// - Numeric scalars, stringified to owned `String` — e.g. a numeric SSN
///   `{"ssn":123456789}` or credit-card number, which a `&str`-only walk cannot
///   see. Numbers are the load-bearing scalar case for PII.
///
/// Booleans and null are intentionally skipped: their canonical forms
/// (`true`/`false`/`null`) carry no PII, so collecting them would only add
/// noise. The walker yields `Cow<str>` (`Borrowed` for strings/keys, `Owned`
/// for stringified numbers) so number text is included without allocating for
/// the common string case.
fn collect_decoded_json_strings<'a>(value: &'a Value, texts: &mut Vec<Cow<'a, str>>) {
    match value {
        Value::String(text) => texts.push(Cow::Borrowed(text.as_str())),
        Value::Number(n) => texts.push(Cow::Owned(n.to_string())),
        Value::Array(items) => {
            for item in items {
                collect_decoded_json_strings(item, texts);
            }
        }
        Value::Object(map) => {
            for (key, value) in map {
                // Scan object KEYS too, not just values: in `ScanMode::All` the
                // previous raw-body scan covered the whole serialized body
                // (including field names), so a blocked phrase / PII pattern in a
                // key like `{"user@example.com": "ok"}` must still be detected.
                texts.push(Cow::Borrowed(key.as_str()));
                collect_decoded_json_strings(value, texts);
            }
        }
        // Bool / Null carry no PII; deliberately dropped.
        _ => {}
    }
}

fn collect_string_value<'a>(value: Option<&'a Value>, texts: &mut Vec<Cow<'a, str>>) {
    if let Some(text) = value.and_then(Value::as_str) {
        texts.push(Cow::Borrowed(text));
    }
}

/// Client-visible text carried by one content-array part: ordinary `text`
/// parts and OpenAI Responses refusal parts shaped
/// `{"type":"refusal","refusal":"..."}`. Parts carrying neither are not
/// text-bearing.
fn content_part_text(part: &Value) -> Option<&str> {
    part.get("text")
        .and_then(Value::as_str)
        .or_else(|| part.get("refusal").and_then(Value::as_str))
}

/// Push each run of adjacent text-bearing parts as one joined fragment so
/// detection and length limits see the logical completion a client renders —
/// a match or length overflow split across adjacent parts cannot hide at part
/// boundaries. A non-text part (e.g. an image) breaks adjacency. Single-part
/// runs stay borrowed; only multi-part runs allocate.
fn push_joined_adjacent_texts<'a>(
    parts: impl Iterator<Item = Option<&'a str>>,
    texts: &mut Vec<Cow<'a, str>>,
) {
    let mut run: Vec<&'a str> = Vec::new();
    for part in parts {
        match part {
            Some(text) => run.push(text),
            None => flush_joined_text_run(&mut run, texts),
        }
    }
    flush_joined_text_run(&mut run, texts);
}

fn flush_joined_text_run<'a>(run: &mut Vec<&'a str>, texts: &mut Vec<Cow<'a, str>>) {
    if run.len() == 1 {
        texts.push(Cow::Borrowed(run[0]));
    } else if !run.is_empty() {
        texts.push(Cow::Owned(run.concat()));
    }
    run.clear();
}

fn collect_content_value<'a>(value: Option<&'a Value>, texts: &mut Vec<Cow<'a, str>>) {
    let Some(value) = value else {
        return;
    };
    if let Some(text) = value.as_str() {
        texts.push(Cow::Borrowed(text));
        return;
    }
    if let Some(parts) = value.as_array() {
        push_joined_adjacent_texts(parts.iter().map(content_part_text), texts);
    }
}

/// Tool/function `arguments` are a JSON document serialized into a string, so
/// scanning only the raw string lets JSON escapes (e.g. `\u0040` for `@`) hide
/// content the tool client will decode. Push the raw string and, when it
/// parses, every decoded token of the nested document — one bounded parse
/// under serde's recursion limit; deeper nested strings are not re-descended.
fn collect_argument_value<'a>(value: Option<&'a Value>, texts: &mut Vec<Cow<'a, str>>) {
    let Some(text) = value.and_then(Value::as_str) else {
        return;
    };
    texts.push(Cow::Borrowed(text));
    if let Ok(decoded) = serde_json::from_str::<Value>(text) {
        let mut decoded_texts: Vec<Cow<'_, str>> = Vec::new();
        collect_decoded_json_strings(&decoded, &mut decoded_texts);
        texts.extend(
            decoded_texts
                .into_iter()
                .map(|token| Cow::Owned(token.into_owned())),
        );
    }
}

/// String-accumulator variant of [`collect_argument_value`] for the SSE path,
/// which reassembles arguments across frames into owned `String`s first.
fn append_decoded_argument_texts(arguments: &str, texts: &mut Vec<String>) {
    if let Ok(decoded) = serde_json::from_str::<Value>(arguments) {
        let mut decoded_texts: Vec<Cow<'_, str>> = Vec::new();
        collect_decoded_json_strings(&decoded, &mut decoded_texts);
        texts.extend(decoded_texts.into_iter().map(Cow::into_owned));
    }
}

/// Collect decoded tool/function-argument tokens for the supported response
/// shapes, so `ScanMode::All` detection keeps parity with content mode: the
/// decoded-token and raw-body passes only ever see the serialized argument
/// string, in which JSON escapes still hide content until the nested document
/// is parsed.
fn collect_decoded_argument_tokens<'a>(json: &'a Value, texts: &mut Vec<Cow<'a, str>>) {
    if let Some(choices) = json.get("choices").and_then(Value::as_array) {
        for choice in choices {
            for container in [choice.get("message"), choice.get("delta")]
                .into_iter()
                .flatten()
            {
                if let Some(function_call) = container.get("function_call") {
                    collect_argument_value(function_call.get("arguments"), texts);
                }
                if let Some(tool_calls) = container.get("tool_calls").and_then(Value::as_array) {
                    for tool_call in tool_calls {
                        if let Some(function) = tool_call.get("function") {
                            collect_argument_value(function.get("arguments"), texts);
                        }
                    }
                }
            }
        }
    }
    if let Some(output) = json.get("output").and_then(Value::as_array) {
        for item in output {
            collect_argument_value(item.get("arguments"), texts);
        }
    }
    if json
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|event_type| event_type.ends_with("function_call_arguments.delta"))
    {
        collect_argument_value(json.get("delta"), texts);
    }
}

/// Visit every tool/function argument value in the supported buffered and SSE
/// response shapes. The traversal is deliberately shared by scan-all
/// redaction's shield/restore passes so both passes observe identical positions
/// without changing the surrounding arrays or objects.
fn for_each_argument_value(json: &mut Value, visitor: &mut impl FnMut(&mut Value)) {
    if let Some(choices) = json.get_mut("choices").and_then(Value::as_array_mut) {
        for choice in choices {
            for container_key in ["message", "delta"] {
                let Some(container) = choice.get_mut(container_key) else {
                    continue;
                };
                if let Some(arguments) = container
                    .get_mut("function_call")
                    .and_then(|function| function.get_mut("arguments"))
                {
                    visitor(arguments);
                }
                if let Some(tool_calls) = container
                    .get_mut("tool_calls")
                    .and_then(Value::as_array_mut)
                {
                    for tool_call in tool_calls {
                        if let Some(arguments) = tool_call
                            .get_mut("function")
                            .and_then(|function| function.get_mut("arguments"))
                        {
                            visitor(arguments);
                        }
                    }
                }
            }
        }
    }

    if let Some(output) = json.get_mut("output").and_then(Value::as_array_mut) {
        for item in output {
            if let Some(arguments) = item.get_mut("arguments") {
                visitor(arguments);
            }
        }
    }

    if json
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|event_type| event_type.ends_with("function_call_arguments.delta"))
        && let Some(delta) = json.get_mut("delta")
    {
        visitor(delta);
    }
}

fn collect_function_value<'a>(value: Option<&'a Value>, texts: &mut Vec<Cow<'a, str>>) {
    let Some(value) = value else {
        return;
    };
    collect_string_value(value.get("name"), texts);
    collect_argument_value(value.get("arguments"), texts);
}

fn reject_unknown_keys(value: &Value, allowed: &[&str], path: &str) -> Result<(), String> {
    let Some(object) = value.as_object() else {
        return Ok(());
    };
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(format!("ai_response_guard: unknown field '{path}.{key}'"));
    }
    Ok(())
}

fn optional_string<'a>(config: &'a Value, field: &'static str) -> Result<Option<&'a str>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_str()
        .map(Some)
        .ok_or_else(|| format!("ai_response_guard: '{field}' must be a string"))
}

fn optional_array<'a>(
    config: &'a Value,
    field: &'static str,
) -> Result<Option<&'a Vec<Value>>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_array()
        .map(Some)
        .ok_or_else(|| format!("ai_response_guard: '{field}' must be an array"))
}

fn optional_string_vec(config: &Value, field: &'static str) -> Result<Option<Vec<String>>, String> {
    let Some(values) = optional_array(config, field)? else {
        return Ok(None);
    };
    let mut out = Vec::with_capacity(values.len());
    for (idx, value) in values.iter().enumerate() {
        let Some(value) = value.as_str() else {
            return Err(format!(
                "ai_response_guard: '{field}[{idx}]' must be a string"
            ));
        };
        out.push(value.to_string());
    }
    Ok(Some(out))
}

fn optional_bool(config: &Value, field: &'static str) -> Result<Option<bool>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| format!("ai_response_guard: '{field}' must be a boolean"))
}

fn optional_positive_usize(config: &Value, field: &'static str) -> Result<Option<usize>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(value) = value.as_u64() else {
        return Err(format!(
            "ai_response_guard: '{field}' must be an integer greater than zero"
        ));
    };
    if value == 0 {
        return Err(format!(
            "ai_response_guard: '{field}' must be greater than zero"
        ));
    }
    usize::try_from(value)
        .map(Some)
        .map_err(|_| format!("ai_response_guard: '{field}' is too large for this platform"))
}

fn optional_usize(config: &Value, field: &'static str) -> Result<Option<usize>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(value) = value.as_u64() else {
        return Err(format!(
            "ai_response_guard: '{field}' must be an unsigned integer"
        ));
    };
    usize::try_from(value)
        .map(Some)
        .map_err(|_| format!("ai_response_guard: '{field}' is too large for this platform"))
}

fn required_non_empty_string<'a>(
    value: &'a Value,
    list_field: &'static str,
    idx: usize,
    field: &'static str,
) -> Result<&'a str, String> {
    let Some(value) = value.get(field) else {
        return Err(format!(
            "ai_response_guard: '{list_field}[{idx}].{field}' is required"
        ));
    };
    let Some(value) = value.as_str() else {
        return Err(format!(
            "ai_response_guard: '{list_field}[{idx}].{field}' must be a string"
        ));
    };
    if value.is_empty() {
        return Err(format!(
            "ai_response_guard: '{list_field}[{idx}].{field}' must not be empty"
        ));
    }
    Ok(value)
}

/// Recursively redact matches in all string values within a JSON Value.
///
/// `STRUCTURAL_KEYS` (IDs, timestamps, model names, roles, token counts, etc.)
/// exists to protect *top-level* response fields whose scalar values may
/// incidentally match a PII regex (e.g. a `model` name or a dotted-quad-looking
/// `id`) from being corrupted. That protection is applied ONLY to a scalar
/// string held directly by a structural key at the top level of the body.
/// Below the top level, those same key names are author-controllable hiding
/// spots, so PII nested under them — e.g. `{"choices":[{"message":{"type":
/// "<PII>"}}]}` or `{"id":{"note":"<PII>"}}` — is still redacted. The walker
/// also always recurses into nested objects and arrays even under a top-level
/// structural key, so PII cannot be hidden by wrapping it in a container.
/// Without this, redaction was fail-open on the response side: PII was reported
/// as detected (`ai_response_guard_redacted` set) but forwarded to the client
/// unredacted purely because of attacker/model-controlled JSON structure.
///
/// Placeholders are wrapped in `regex::NoExpand` so `$`-sequences in them are
/// emitted literally rather than interpreted as capture-group references.
///
/// `top_level` is true only for the root object's direct fields.
fn redact_json_strings(
    value: &mut Value,
    pii_patterns: &[ContentPattern],
    blocked_phrases: &[ContentPattern],
    top_level: bool,
) {
    match value {
        Value::String(s) => {
            let mut result = s.clone();
            for pattern in pii_patterns.iter().chain(blocked_phrases.iter()) {
                result = pattern
                    .regex
                    .replace_all(&result, NoExpand(pattern.placeholder.as_str()))
                    .to_string();
            }
            if result != *s {
                *s = result;
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                redact_json_strings(item, pii_patterns, blocked_phrases, false);
            }
        }
        Value::Object(map) => {
            for (k, val) in map.iter_mut() {
                // Preserve only top-level structural scalar strings (model
                // name, IDs, roles, token counts). Always recurse into nested
                // objects/arrays, and never skip nested occurrences of these
                // key names, so PII cannot hide under a structural key.
                if top_level && STRUCTURAL_KEYS.contains(&k.as_str()) && val.is_string() {
                    continue;
                }
                redact_json_strings(val, pii_patterns, blocked_phrases, false);
            }
        }
        _ => {}
    }
}

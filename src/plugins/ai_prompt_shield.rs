//! AI Prompt Shield Plugin
//!
//! Scans AI/LLM request bodies for PII (personally identifiable information)
//! patterns and either rejects the request, redacts the PII, or logs a warning.
//!
//! Built-in patterns: SSN, credit card, email, US phone, API keys, AWS keys,
//! IPv4 addresses, and IBAN. Custom regex patterns can be added via config.

use async_trait::async_trait;
use regex::{Regex, RegexSet};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use tracing::{debug, warn};

use super::utils::body_transform::is_json_content_type;
use super::{Plugin, PluginResult, RequestContext};

/// JSON object keys that are structural metadata (model names, IDs, roles,
/// etc.) and must never be redacted, even in `ScanMode::All`. Protects
/// values that may incidentally match PII regexes.
const STRUCTURAL_KEYS: &[&str] = &[
    "model",
    "id",
    "object",
    "role",
    "type",
    "created",
    "stream",
    "temperature",
    "top_p",
    "max_tokens",
    "max_output_tokens",
    "max_completion_tokens",
    "tool_call_id",
];

/// Top-level request fields that carry prompt text in non-`messages` LLM
/// request shapes. Scanned in `ScanMode::Content` in addition to
/// `messages[].content`: OpenAI legacy completions use `prompt`, the
/// Responses API and embeddings use `input`, OpenAI Responses uses
/// `instructions`, and Anthropic carries a top-level `system` string. Each may
/// be a string, an array of strings, or an array of `{type:"text", text:"..."}`
/// parts.
const CONTENT_SCAN_FIELDS: &[&str] = &["prompt", "input", "instructions", "system"];

/// Action to take when PII is detected.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ShieldAction {
    Reject,
    Redact,
    Warn,
}

/// How to scan the request body.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ScanMode {
    /// Only scan `content` fields within the `messages` array.
    Content,
    /// Scan the entire request body as text.
    All,
}

/// A named regex pattern for PII detection.
#[derive(Debug)]
struct PiiPattern {
    name: String,
    regex: Regex,
    /// Pre-rendered redaction placeholder for this pattern, with `{type}`
    /// already substituted with `name`. Built once at config-load time so
    /// `redact_text` does not re-render the template per pattern per call.
    placeholder: String,
}

pub struct AiPromptShield {
    action: ShieldAction,
    patterns: Vec<PiiPattern>,
    /// All patterns compiled into a single DFA for O(text_len) detection
    /// regardless of pattern count. Indices align with `patterns`.
    detection_set: RegexSet,
    scan_mode: ScanMode,
    exclude_roles: HashSet<String>,
    max_scan_bytes: usize,
    /// True when action is Redact — enables transform_request_body.
    needs_body_transform: bool,
    /// True when the plugin has valid patterns and may need to inspect bodies.
    requires_request_body: bool,
}

/// Built-in PII pattern definitions.
fn builtin_pattern(name: &str) -> Option<&'static str> {
    match name {
        "ssn" => Some(r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b"),
        "credit_card" => Some(
            r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{0,4}\b",
        ),
        "email" => Some(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "phone_us" => Some(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        "api_key" => Some(r"\b(?:sk|pk|api|key|token|secret|password)[-_]?[A-Za-z0-9]{20,}\b"),
        "aws_key" => Some(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "ip_address" => Some(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
        "iban" => Some(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?\d{0,16})\b"),
        _ => None,
    }
}

impl AiPromptShield {
    pub fn new(config: &Value) -> Result<Self, String> {
        if !config.is_object() {
            return Err("ai_prompt_shield: config must be an object".to_string());
        }

        let action = match optional_string(config, "action")?.unwrap_or("reject") {
            "reject" => ShieldAction::Reject,
            "redact" => ShieldAction::Redact,
            "warn" => ShieldAction::Warn,
            other => {
                return Err(format!(
                    "ai_prompt_shield: 'action' must be one of 'reject', 'redact', or 'warn', got: {other:?}"
                ));
            }
        };

        let scan_mode = match optional_string(config, "scan_fields")?.unwrap_or("content") {
            "content" => ScanMode::Content,
            "all" => ScanMode::All,
            other => {
                return Err(format!(
                    "ai_prompt_shield: 'scan_fields' must be one of 'content' or 'all', got: {other:?}"
                ));
            }
        };

        let exclude_roles: HashSet<String> =
            optional_string_array(config, "exclude_roles")?.unwrap_or_default();

        let redaction_template =
            optional_string(config, "redaction_placeholder")?.unwrap_or("[REDACTED:{type}]");

        let max_scan_bytes =
            optional_positive_usize(config, "max_scan_bytes")?.unwrap_or(1_048_576);

        // Build pattern list from config
        let pattern_names: Vec<String> =
            optional_string_vec(config, "patterns")?.unwrap_or_else(|| {
                vec![
                    "ssn".to_string(),
                    "credit_card".to_string(),
                    "api_key".to_string(),
                    "aws_key".to_string(),
                ]
            });

        let mut patterns: Vec<PiiPattern> = Vec::new();

        // Add built-in patterns. Compile failures and unknown names are
        // fatal so the operator gets a clear error instead of silently
        // losing PII coverage.
        for name in &pattern_names {
            if let Some(regex_str) = builtin_pattern(name) {
                match Regex::new(regex_str) {
                    Ok(regex) => {
                        let placeholder = redaction_template.replace("{type}", name);
                        patterns.push(PiiPattern {
                            name: name.clone(),
                            regex,
                            placeholder,
                        });
                    }
                    Err(e) => {
                        return Err(format!(
                            "ai_prompt_shield: failed to compile built-in pattern '{}': {}",
                            name, e,
                        ));
                    }
                }
            } else {
                return Err(format!(
                    "ai_prompt_shield: unknown built-in pattern '{}'",
                    name,
                ));
            }
        }

        // Add custom patterns
        if let Some(custom) = optional_array(config, "custom_patterns")? {
            for entry in custom {
                let name = entry["name"]
                    .as_str()
                    .ok_or("ai_prompt_shield: custom_patterns entries require string 'name'")?;
                let regex_str = entry["regex"]
                    .as_str()
                    .ok_or("ai_prompt_shield: custom_patterns entries require string 'regex'")?;
                match Regex::new(regex_str) {
                    Ok(regex) => {
                        let placeholder = redaction_template.replace("{type}", name);
                        patterns.push(PiiPattern {
                            name: name.to_string(),
                            regex,
                            placeholder,
                        });
                    }
                    Err(e) => {
                        return Err(format!(
                            "ai_prompt_shield: failed to compile custom pattern '{}': {}",
                            name, e,
                        ));
                    }
                }
            }
        }

        if patterns.is_empty() {
            return Err(
                "ai_prompt_shield: no valid patterns configured — plugin will have no effect"
                    .to_string(),
            );
        }

        let needs_body_transform = action == ShieldAction::Redact;
        let requires_request_body = !patterns.is_empty();

        // Build a single combined RegexSet for O(text_len) detection.
        // Each pattern was already validated above (compiled as a Regex), so
        // RegexSet construction will not fail for pattern syntax — but we
        // propagate any error defensively.
        let detection_set =
            RegexSet::new(patterns.iter().map(|p| p.regex.as_str())).map_err(|e| {
                format!(
                    "ai_prompt_shield: failed to build detection RegexSet: {}",
                    e
                )
            })?;

        Ok(Self {
            action,
            patterns,
            detection_set,
            scan_mode,
            exclude_roles,
            max_scan_bytes,
            needs_body_transform,
            requires_request_body,
        })
    }

    /// Extract text segments to scan from the request body.
    fn extract_scan_text<'a>(&self, json: &'a Value) -> Vec<&'a str> {
        match self.scan_mode {
            ScanMode::All => {
                // We can't get &str from Value for the whole body easily,
                // so we'll handle this differently in the caller.
                vec![]
            }
            ScanMode::Content => {
                let mut texts = Vec::new();
                if let Some(messages) = json.get("messages").and_then(|v| v.as_array()) {
                    for msg in messages {
                        // Skip excluded roles (O(1) HashSet lookup)
                        if let Some(role) = msg.get("role").and_then(|r| r.as_str())
                            && self.exclude_roles.contains(role)
                        {
                            continue;
                        }
                        // String content
                        if let Some(content) = msg.get("content").and_then(|c| c.as_str()) {
                            texts.push(content);
                        }
                        // Array content (multimodal)
                        if let Some(parts) = msg.get("content").and_then(|c| c.as_array()) {
                            for part in parts {
                                if part.get("type").and_then(|t| t.as_str()) == Some("text")
                                    && let Some(text) = part.get("text").and_then(|t| t.as_str())
                                {
                                    texts.push(text);
                                }
                            }
                        }
                    }
                }
                // Many widely-used LLM request shapes do not use a `messages`
                // array: OpenAI legacy completions use `prompt`, the Responses
                // API and embeddings use `input`, and Anthropic carries a
                // top-level `system` string alongside `messages`. Without
                // scanning these, Content mode silently passes PII through on
                // those endpoints. Each field may be a string, an array of
                // strings, or an array of `{type:"text", text:"..."}` parts.
                for field in CONTENT_SCAN_FIELDS {
                    if let Some(value) = json.get(field) {
                        collect_field_text(value, &self.exclude_roles, &mut texts);
                    }
                }
                texts
            }
        }
    }

    /// Detect PII in the given text segments. Returns names of detected pattern types.
    /// Uses a single `RegexSet` DFA pass per text fragment, O(text_len)
    /// regardless of pattern count.
    fn detect_pii(&self, texts: &[&str]) -> Vec<String> {
        if self.patterns.is_empty() {
            return Vec::new();
        }
        let mut hit = vec![false; self.patterns.len()];
        for text in texts {
            for idx in self.detection_set.matches(text).into_iter() {
                hit[idx] = true;
            }
        }
        hit.iter()
            .enumerate()
            .filter_map(|(idx, &h)| {
                if h {
                    self.patterns.get(idx).map(|p| p.name.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Detect PII in a raw string (for "all" scan mode).
    /// Single `RegexSet` DFA pass — O(text_len).
    fn detect_pii_in_str(&self, text: &str) -> Vec<String> {
        if self.patterns.is_empty() {
            return Vec::new();
        }
        self.detection_set
            .matches(text)
            .into_iter()
            .filter_map(|idx| self.patterns.get(idx).map(|p| p.name.clone()))
            .collect()
    }

    /// Parse the body as JSON, apply mode-appropriate redaction, and return
    /// the mutated `Value`. Returns `None` when the body isn't valid JSON,
    /// is over `max_scan_bytes`, or contains no PII to redact (so callers
    /// don't waste serialization on a no-op).
    ///
    /// Shared between `before_proxy` (which uses this to update
    /// `ctx.metadata["request_body"]` so downstream `before_proxy` plugins
    /// see redacted text) and `transform_request_body` (which uses the
    /// returned `Value` to rewrite the wire body on the backend dispatch
    /// path). Keeping the two paths in lockstep guarantees both see the
    /// same redacted bytes regardless of which path actually runs.
    fn apply_redaction_in_place(&self, body: &str) -> Option<Value> {
        if body.len() > self.max_scan_bytes {
            return None;
        }
        let mut json: Value = serde_json::from_str(body).ok()?;

        if self.scan_mode == ScanMode::All {
            // Single DFA pass to short-circuit when no pattern matches.
            if !self.detection_set.is_match(body) {
                return None;
            }
            // Run structured redaction first on known prompt-content
            // fields (messages[].content) so recognized chat-completion
            // shapes are handled with the correct template. Then run the
            // recursive walker to cover any PII in sibling fields
            // (metadata, tool arguments, custom top-level strings) that
            // the structured redactor doesn't touch. The recursive walker
            // preserves only TOP-LEVEL structural scalar values (model
            // names, IDs, request parameters) so they remain untouched
            // while PII hidden under nested structural keys is still
            // redacted. Running structured first is safe because its
            // [REDACTED:...] placeholders do not match any PII regex on the
            // subsequent recursive pass.
            let has_known_messages = json
                .get("messages")
                .and_then(|m| m.as_array())
                .is_some_and(|arr| !arr.is_empty());
            if has_known_messages {
                self.redact_body(&mut json);
            }
            redact_json_strings(&mut json, &self.patterns, true);
            return Some(json);
        }

        // Content mode: only redact within messages
        let texts = self.extract_scan_text(&json);
        if self.detect_pii(&texts).is_empty() {
            return None;
        }
        self.redact_body(&mut json);
        Some(json)
    }

    /// Apply redaction to message content fields in the JSON body.
    fn redact_body(&self, json: &mut Value) {
        if let Some(messages) = json.get_mut("messages").and_then(|v| v.as_array_mut()) {
            for msg in messages.iter_mut() {
                // Skip excluded roles (O(1) HashSet lookup)
                if let Some(role) = msg.get("role").and_then(|r| r.as_str())
                    && self.exclude_roles.contains(role)
                {
                    continue;
                }

                // String content
                if let Some(content) = msg.get("content").and_then(|c| c.as_str()) {
                    let redacted = self.redact_text(content);
                    if redacted != content {
                        msg["content"] = Value::String(redacted);
                    }
                }

                // Array content (multimodal)
                if let Some(parts) = msg.get_mut("content").and_then(|c| c.as_array_mut()) {
                    for part in parts.iter_mut() {
                        if part.get("type").and_then(|t| t.as_str()) == Some("text")
                            && let Some(text) = part.get("text").and_then(|t| t.as_str())
                        {
                            let redacted = self.redact_text(text);
                            if redacted != text {
                                part["text"] = Value::String(redacted);
                            }
                        }
                    }
                }
            }
        }

        // Redact the same non-`messages` prompt fields scanned by
        // `extract_scan_text` so Content-mode detection and redaction stay
        // symmetric — otherwise PII in `prompt`/`input`/`system` would be
        // reported as redacted but forwarded unredacted (a fail-open bypass).
        for field in CONTENT_SCAN_FIELDS {
            if let Some(value) = json.get_mut(field) {
                redact_field_text(value, &self.exclude_roles, &|text| self.redact_text(text));
            }
        }
    }

    /// Replace all PII pattern matches in the text with the redaction placeholder.
    /// Placeholders are pre-rendered at construction time so each call is one
    /// `replace_all` per pattern, with no template formatting on the hot path.
    fn redact_text(&self, text: &str) -> String {
        let mut result = text.to_string();
        for pattern in &self.patterns {
            result = pattern
                .regex
                .replace_all(&result, pattern.placeholder.as_str())
                .to_string();
        }
        result
    }
}

#[async_trait]
impl Plugin for AiPromptShield {
    fn name(&self) -> &str {
        "ai_prompt_shield"
    }

    fn priority(&self) -> u16 {
        super::priority::AI_PROMPT_SHIELD
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_GRPC_PROTOCOLS
    }

    fn modifies_request_body(&self) -> bool {
        self.needs_body_transform
    }

    fn requires_request_body_before_before_proxy(&self) -> bool {
        self.requires_request_body
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        self.requires_request_body
            && ctx.method == "POST"
            && ctx
                .headers
                .get("content-type")
                .is_some_and(|ct| is_json_content_type(ct))
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Only process POST requests
        if ctx.method != "POST" {
            return PluginResult::Continue;
        }

        // Check content-type
        let content_type = headers
            .get("content-type")
            .map(|s| s.as_str())
            .unwrap_or("");
        if !is_json_content_type(content_type) {
            return PluginResult::Continue;
        }

        // Get request body
        let body = match ctx.metadata.get("request_body") {
            Some(b) if !b.is_empty() => b.as_str(),
            _ => return PluginResult::Continue,
        };

        // Size limit check
        if body.len() > self.max_scan_bytes {
            debug!(
                "ai_prompt_shield: body size {} exceeds max_scan_bytes {}, skipping",
                body.len(),
                self.max_scan_bytes
            );
            return PluginResult::Continue;
        }

        // Detect PII and (in non-scan-all mode) capture streaming intent from
        // the same parsed JSON. Scan-all mode operates on the raw body string,
        // so a full JSON parse just to read `stream` would be pure overhead —
        // gate it behind a cheap byte-level substring check first.
        //
        // The streaming flag is captured before mutating `ctx.metadata`
        // because `body` borrows from `ctx.metadata.get("request_body")`.
        let (detected, is_streaming_request) = if self.scan_mode == ScanMode::All {
            let detected = self.detect_pii_in_str(body);
            let is_streaming = body.contains("\"stream\"")
                && serde_json::from_str::<Value>(body)
                    .ok()
                    .and_then(|json| json.get("stream").and_then(|s| s.as_bool()))
                    == Some(true);
            (detected, is_streaming)
        } else {
            match serde_json::from_str::<Value>(body) {
                Ok(json) => {
                    let is_streaming = json.get("stream").and_then(|s| s.as_bool()) == Some(true);
                    let texts = self.extract_scan_text(&json);
                    (self.detect_pii(&texts), is_streaming)
                }
                Err(_) => return PluginResult::Continue,
            }
        };

        // `body` borrow released — safe to mutate ctx.metadata now.
        if is_streaming_request {
            ctx.metadata
                .insert("ai_request_streaming".to_string(), "true".to_string());
        }

        if detected.is_empty() {
            return PluginResult::Continue;
        }

        match self.action {
            ShieldAction::Reject => {
                debug!(
                    "ai_prompt_shield: PII detected (types: {:?}), rejecting request",
                    detected
                );
                PluginResult::Reject {
                    status_code: 400,
                    body: serde_json::json!({
                        "error": "PII detected in request",
                        "detected_types": detected,
                        "message": "Request blocked: potential PII detected. Remove sensitive data before sending to AI provider."
                    })
                    .to_string(),
                    headers: HashMap::new(),
                }
            }
            ShieldAction::Warn => {
                warn!(
                    "ai_prompt_shield: PII detected (types: {:?}), passing through (warn mode)",
                    detected
                );
                ctx.metadata
                    .insert("ai_shield_warnings".to_string(), detected.join(","));
                PluginResult::Continue
            }
            ShieldAction::Redact => {
                // Materialize the redacted body NOW (not just in
                // `transform_request_body`) so we can overwrite
                // `ctx.metadata["request_body"]`. Downstream `before_proxy`
                // plugins read the buffered body from that metadata key
                // and act on its contents — most importantly,
                // `ai_federation` (priority 2985) consumes the body as-is
                // to dispatch a direct provider request and then returns
                // `RejectBinary`. `RejectBinary` short-circuits the
                // backend dispatch path entirely, so
                // `transform_request_body` never runs and the un-redacted
                // bytes would otherwise be forwarded to the AI provider.
                // Updating the metadata here ensures every downstream
                // consumer — whether they reach the backend dispatch path
                // or terminate the request from another `before_proxy`
                // plugin — sees the redacted form.
                //
                // Re-fetch the body as an owned `String` rather than
                // reusing the earlier `&str` borrow on `ctx.metadata`:
                // the borrow checker can't see that the existing borrow
                // ends before the upcoming mutations, and cloning the
                // body once on this path is cheap relative to the JSON
                // parse + regex walk we're about to do.
                //
                // `transform_request_body` still runs on the normal
                // backend dispatch path and re-applies the same redaction
                // to the wire body. The double walk is cheap because
                // `[REDACTED:...]` placeholders don't match any PII
                // pattern, so the second pass is a no-op on already
                // redacted strings.
                let original_body = ctx
                    .metadata
                    .get("request_body")
                    .cloned()
                    .unwrap_or_default();
                let redacted_body = self
                    .apply_redaction_in_place(&original_body)
                    .and_then(|json| serde_json::to_string(&json).ok());

                ctx.metadata
                    .insert("ai_shield_redacted".to_string(), detected.join(","));
                if let Some(serialized) = redacted_body {
                    ctx.metadata.insert("request_body".to_string(), serialized);
                }

                PluginResult::Continue
            }
        }
    }

    async fn transform_request_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        _request_headers: &std::collections::HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        if self.action != ShieldAction::Redact {
            return None;
        }

        // Only transform JSON
        if let Some(ct) = content_type
            && !is_json_content_type(ct)
        {
            return None;
        }

        if body.len() > self.max_scan_bytes {
            return None;
        }

        let body_str = std::str::from_utf8(body).ok()?;
        let json = self.apply_redaction_in_place(body_str)?;
        serde_json::to_vec(&json).ok()
    }
}

fn optional_string<'a>(config: &'a Value, field: &'static str) -> Result<Option<&'a str>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_str()
        .map(Some)
        .ok_or_else(|| format!("ai_prompt_shield: '{field}' must be a string"))
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
        .ok_or_else(|| format!("ai_prompt_shield: '{field}' must be an array"))
}

fn optional_string_vec(config: &Value, field: &'static str) -> Result<Option<Vec<String>>, String> {
    let Some(values) = optional_array(config, field)? else {
        return Ok(None);
    };
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let Some(value) = value.as_str() else {
            return Err(format!(
                "ai_prompt_shield: '{field}' must contain only strings"
            ));
        };
        out.push(value.to_string());
    }
    Ok(Some(out))
}

fn optional_string_array(
    config: &Value,
    field: &'static str,
) -> Result<Option<HashSet<String>>, String> {
    optional_string_vec(config, field)
        .map(|values| values.map(|values| values.into_iter().collect()))
}

fn optional_positive_usize(config: &Value, field: &'static str) -> Result<Option<usize>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(value) = value.as_u64() else {
        return Err(format!(
            "ai_prompt_shield: '{field}' must be an integer greater than zero"
        ));
    };
    if value == 0 {
        return Err(format!(
            "ai_prompt_shield: '{field}' must be greater than zero"
        ));
    }
    usize::try_from(value)
        .map(Some)
        .map_err(|_| format!("ai_prompt_shield: '{field}' is too large for this platform"))
}

/// Collect scannable prompt text from a top-level LLM field that may be a
/// string, an array of strings, or an array of `{type:"text", text:"..."}`
/// content parts (e.g. `prompt`, `input`, `system`). Pushes borrowed `&str`
/// slices onto `texts`. Non-text array entries are ignored.
/// Text content-part `type` values across the major LLM APIs. The OpenAI Chat
/// API and Anthropic Messages API use `text`; the OpenAI Responses API uses
/// `input_text` (request) and `output_text` (response).
fn is_text_content_part_type(part_type: &str) -> bool {
    matches!(part_type, "text" | "input_text" | "output_text")
}

/// Collect scannable text from a top-level LLM content field
/// (`prompt`/`input`/`instructions`/`system`). Handles a plain string, an array
/// of strings, an array of `{type: text|input_text|output_text, text}` content
/// parts, and the structured OpenAI Responses `input` shape — an array of
/// message objects `{role, content: <string | array of parts>}` — by recursing
/// into each message's `content`.
fn collect_field_text<'a>(
    value: &'a Value,
    exclude_roles: &HashSet<String>,
    texts: &mut Vec<&'a str>,
) {
    match value {
        Value::String(s) => texts.push(s.as_str()),
        Value::Array(items) => {
            for item in items {
                match item {
                    Value::String(s) => texts.push(s.as_str()),
                    Value::Object(obj) => {
                        if obj
                            .get("type")
                            .and_then(|t| t.as_str())
                            .is_some_and(is_text_content_part_type)
                        {
                            if let Some(text) = obj.get("text").and_then(|t| t.as_str()) {
                                texts.push(text);
                            }
                        } else if let Some(content) = obj.get("content") {
                            if obj
                                .get("role")
                                .and_then(|r| r.as_str())
                                .is_some_and(|role| exclude_roles.contains(role))
                            {
                                continue;
                            }
                            // Message object `{role, content}` (structured
                            // Responses `input`): scan its content.
                            collect_field_text(content, exclude_roles, texts);
                        }
                    }
                    _ => {}
                }
            }
        }
        // A field that is itself a single message object `{role, content}`.
        Value::Object(obj) => {
            if let Some(content) = obj.get("content") {
                if obj
                    .get("role")
                    .and_then(|r| r.as_str())
                    .is_some_and(|role| exclude_roles.contains(role))
                {
                    return;
                }
                collect_field_text(content, exclude_roles, texts);
            }
        }
        _ => {}
    }
}

/// Redact PII in a top-level LLM field that may be a string, an array of
/// strings, or an array of `{type:"text", text:"..."}` content parts (e.g.
/// `prompt`, `input`, `instructions`, `system`). Mirrors `collect_field_text`
/// so detection and redaction stay symmetric — anything scanned for PII is
/// also rewritten.
fn redact_field_text(
    value: &mut Value,
    exclude_roles: &HashSet<String>,
    redact: &impl Fn(&str) -> String,
) {
    match value {
        Value::String(s) => {
            let redacted = redact(s);
            if redacted != *s {
                *s = redacted;
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                match item {
                    Value::String(s) => {
                        let redacted = redact(s);
                        if redacted != *s {
                            *s = redacted;
                        }
                    }
                    Value::Object(obj) => {
                        if obj
                            .get("type")
                            .and_then(|t| t.as_str())
                            .is_some_and(is_text_content_part_type)
                        {
                            if let Some(text) = obj.get("text").and_then(|t| t.as_str()) {
                                let redacted = redact(text);
                                if redacted != text {
                                    obj.insert("text".to_string(), Value::String(redacted));
                                }
                            }
                        } else if obj
                            .get("role")
                            .and_then(|r| r.as_str())
                            .is_some_and(|role| exclude_roles.contains(role))
                        {
                            continue;
                        } else if let Some(content) = obj.get_mut("content") {
                            redact_field_text(content, exclude_roles, redact);
                        }
                    }
                    _ => {}
                }
            }
        }
        Value::Object(obj) => {
            let excluded = obj
                .get("role")
                .and_then(|r| r.as_str())
                .is_some_and(|role| exclude_roles.contains(role));
            if !excluded && let Some(content) = obj.get_mut("content") {
                redact_field_text(content, exclude_roles, redact);
            }
        }
        _ => {}
    }
}

/// Recursively redact PII in all string values within a JSON Value.
///
/// `STRUCTURAL_KEYS` (model name, IDs, roles, request parameters) exists to
/// protect *top-level* request fields whose scalar values may incidentally
/// match a PII regex (e.g. a `model` name or an `id`) from being corrupted.
/// That protection is applied ONLY to a scalar string held directly by a
/// structural key at the top level of the body. Below the top level, those
/// same key names are attacker-controllable hiding spots, so PII nested under
/// them — e.g. `{"metadata":{"type":"<PII>"}}` or `{"id":{"note":"<PII>"}}` —
/// is still redacted. The walker also always recurses into nested objects and
/// arrays even under a top-level structural key, so PII cannot be hidden by
/// wrapping it in a container. Without this, redaction was fail-open: PII was
/// reported as detected but forwarded to the provider unredacted purely
/// because of attacker-controlled JSON structure.
///
/// `top_level` is true only for the root object's direct fields.
fn redact_json_strings(value: &mut Value, patterns: &[PiiPattern], top_level: bool) {
    match value {
        Value::String(s) => {
            let mut result = s.clone();
            for pattern in patterns {
                result = pattern
                    .regex
                    .replace_all(&result, pattern.placeholder.as_str())
                    .to_string();
            }
            if result != *s {
                *s = result;
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                redact_json_strings(item, patterns, false);
            }
        }
        Value::Object(map) => {
            for (k, val) in map.iter_mut() {
                // Preserve only top-level structural scalar strings (the
                // model name, IDs, roles, and request parameters an operator
                // legitimately sends). Always recurse into nested
                // objects/arrays, and never skip nested occurrences of these
                // key names, so PII cannot hide under a structural key.
                if top_level && STRUCTURAL_KEYS.contains(&k.as_str()) && val.is_string() {
                    continue;
                }
                redact_json_strings(val, patterns, false);
            }
        }
        _ => {}
    }
}

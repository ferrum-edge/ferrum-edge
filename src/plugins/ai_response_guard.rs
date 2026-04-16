//! AI Response Guard Plugin
//!
//! Validates and filters LLM response content before it reaches the client.
//! Complements `ai_prompt_shield` (which guards inputs) by providing output-side
//! guardrails including PII detection in responses, keyword/phrase blocklists,
//! and response format validation.
//!
//! Built-in PII patterns: SSN, credit card, email, US phone, API keys, AWS keys,
//! IPv4 addresses, and IBAN (shared with ai_prompt_shield).
//!
//! Actions: reject (return error to client), redact (replace matches with placeholders),
//! or warn (add metadata/headers but pass through).

use async_trait::async_trait;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use tracing::{debug, warn};

use super::{Plugin, PluginResult, RequestContext};

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
}

/// How to scan the response body.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ScanMode {
    /// Only scan LLM completion content fields (choices[].message.content, choices[].delta.content).
    Content,
    /// Scan the entire response body as text.
    All,
}

pub struct AiResponseGuard {
    action: GuardAction,
    pii_patterns: Vec<ContentPattern>,
    blocked_phrases: Vec<ContentPattern>,
    scan_mode: ScanMode,
    max_scan_bytes: usize,
    redaction_template: String,
    /// True when action is Redact — enables transform_response_body.
    needs_body_transform: bool,
    /// True when the plugin has patterns configured.
    has_patterns: bool,
    /// Optional: require response to be valid JSON.
    require_json: bool,
    /// Optional: required top-level JSON fields.
    required_fields: Vec<String>,
    /// Maximum allowed completion length in characters (0 = unlimited).
    max_completion_length: usize,
}

/// Built-in PII pattern definitions (shared with ai_prompt_shield).
fn builtin_pii_pattern(name: &str) -> Option<&'static str> {
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

impl AiResponseGuard {
    pub fn new(config: &Value) -> Result<Self, String> {
        let action = match config["action"].as_str().unwrap_or("reject") {
            "redact" => GuardAction::Redact,
            "warn" => GuardAction::Warn,
            _ => GuardAction::Reject,
        };

        let scan_mode = if config["scan_fields"].as_str().unwrap_or("content") == "all" {
            ScanMode::All
        } else {
            ScanMode::Content
        };

        let redaction_template = config["redaction_placeholder"]
            .as_str()
            .unwrap_or("[REDACTED:{type}]")
            .to_string();

        let max_scan_bytes = config["max_scan_bytes"].as_u64().unwrap_or(1_048_576) as usize;

        // Build PII pattern list
        let pii_pattern_names: Vec<String> = config["pii_patterns"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let mut pii_patterns: Vec<ContentPattern> = Vec::new();

        for name in &pii_pattern_names {
            if let Some(regex_str) = builtin_pii_pattern(name) {
                match Regex::new(regex_str) {
                    Ok(regex) => pii_patterns.push(ContentPattern {
                        name: format!("pii:{}", name),
                        regex,
                    }),
                    Err(e) => {
                        warn!(
                            "ai_response_guard: failed to compile built-in PII pattern '{}': {}",
                            name, e,
                        );
                    }
                }
            } else {
                warn!(
                    "ai_response_guard: unknown built-in PII pattern '{}', skipping",
                    name,
                );
            }
        }

        // Add custom PII patterns
        if let Some(custom) = config["custom_pii_patterns"].as_array() {
            for entry in custom {
                let name = match entry["name"].as_str() {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                let regex_str = match entry["regex"].as_str() {
                    Some(r) => r,
                    None => continue,
                };
                match Regex::new(regex_str) {
                    Ok(regex) => pii_patterns.push(ContentPattern {
                        name: format!("pii:{}", name),
                        regex,
                    }),
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
        if let Some(phrases) = config["blocked_phrases"].as_array() {
            for (i, phrase) in phrases.iter().enumerate() {
                let phrase_str = match phrase.as_str() {
                    Some(p) => p,
                    None => continue,
                };
                // Treat as case-insensitive literal match
                let escaped = regex::escape(phrase_str);
                match Regex::new(&format!("(?i){}", escaped)) {
                    Ok(regex) => blocked_phrases.push(ContentPattern {
                        name: format!("blocked_phrase:{}", phrase_str),
                        regex,
                    }),
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
        if let Some(patterns) = config["blocked_patterns"].as_array() {
            for entry in patterns {
                let name = match entry["name"].as_str() {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                let regex_str = match entry["regex"].as_str() {
                    Some(r) => r,
                    None => continue,
                };
                match Regex::new(regex_str) {
                    Ok(regex) => blocked_phrases.push(ContentPattern { name, regex }),
                    Err(e) => {
                        return Err(format!(
                            "ai_response_guard: failed to compile blocked pattern '{}': {}",
                            name, e,
                        ));
                    }
                }
            }
        }

        let require_json = config["require_json"].as_bool().unwrap_or(false);

        let required_fields: Vec<String> = config["required_fields"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let max_completion_length = config["max_completion_length"].as_u64().unwrap_or(0) as usize;

        let has_patterns = !pii_patterns.is_empty()
            || !blocked_phrases.is_empty()
            || require_json
            || !required_fields.is_empty()
            || max_completion_length > 0;

        if !has_patterns {
            return Err(
                "ai_response_guard: no patterns, phrases, or validation rules configured — plugin will have no effect"
                    .to_string(),
            );
        }

        let needs_body_transform = action == GuardAction::Redact
            && (!pii_patterns.is_empty() || !blocked_phrases.is_empty());

        Ok(Self {
            action,
            pii_patterns,
            blocked_phrases,
            scan_mode,
            max_scan_bytes,
            redaction_template,
            needs_body_transform,
            has_patterns,
            require_json,
            required_fields,
            max_completion_length,
        })
    }

    /// Extract completion text from LLM response JSON (OpenAI format).
    fn extract_completion_texts<'a>(&self, json: &'a Value) -> Vec<&'a str> {
        let mut texts = Vec::new();

        // OpenAI / compatible: choices[].message.content
        if let Some(choices) = json.get("choices").and_then(|c| c.as_array()) {
            for choice in choices {
                if let Some(content) = choice
                    .get("message")
                    .and_then(|m| m.get("content"))
                    .and_then(|c| c.as_str())
                {
                    texts.push(content);
                }
                // Streaming delta
                if let Some(content) = choice
                    .get("delta")
                    .and_then(|d| d.get("content"))
                    .and_then(|c| c.as_str())
                {
                    texts.push(content);
                }
            }
        }

        // Anthropic: content[].text
        if let Some(content) = json.get("content").and_then(|c| c.as_array()) {
            for block in content {
                if block.get("type").and_then(|t| t.as_str()) == Some("text")
                    && let Some(text) = block.get("text").and_then(|t| t.as_str())
                {
                    texts.push(text);
                }
            }
        }

        // Google Gemini: candidates[].content.parts[].text
        if let Some(candidates) = json.get("candidates").and_then(|c| c.as_array()) {
            for candidate in candidates {
                if let Some(parts) = candidate
                    .get("content")
                    .and_then(|c| c.get("parts"))
                    .and_then(|p| p.as_array())
                {
                    for part in parts {
                        if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                            texts.push(text);
                        }
                    }
                }
            }
        }

        texts
    }

    /// Detect content matches against all patterns. Returns names of detected matches.
    fn detect_matches(&self, texts: &[&str]) -> Vec<String> {
        let mut detected = Vec::new();
        for pattern in self.pii_patterns.iter().chain(self.blocked_phrases.iter()) {
            for text in texts {
                if pattern.regex.is_match(text) {
                    detected.push(pattern.name.clone());
                    break;
                }
            }
        }
        detected
    }

    /// Detect matches in a raw string (for "all" scan mode).
    fn detect_matches_in_str(&self, text: &str) -> Vec<String> {
        let mut detected = Vec::new();
        for pattern in self.pii_patterns.iter().chain(self.blocked_phrases.iter()) {
            if pattern.regex.is_match(text) {
                detected.push(pattern.name.clone());
            }
        }
        detected
    }

    /// Replace all pattern matches with the redaction placeholder.
    fn redact_text(&self, text: &str) -> String {
        let mut result = text.to_string();
        for pattern in self.pii_patterns.iter().chain(self.blocked_phrases.iter()) {
            let placeholder = self.redaction_template.replace("{type}", &pattern.name);
            result = pattern
                .regex
                .replace_all(&result, placeholder.as_str())
                .to_string();
        }
        result
    }

    /// Redact content in LLM response JSON.
    fn redact_response_json(&self, json: &mut Value) {
        // OpenAI / compatible: choices[].message.content
        if let Some(choices) = json.get_mut("choices").and_then(|c| c.as_array_mut()) {
            for choice in choices.iter_mut() {
                if let Some(content) = choice
                    .get("message")
                    .and_then(|m| m.get("content"))
                    .and_then(|c| c.as_str())
                {
                    let redacted = self.redact_text(content);
                    if redacted != content {
                        choice["message"]["content"] = Value::String(redacted);
                    }
                }
                if let Some(content) = choice
                    .get("delta")
                    .and_then(|d| d.get("content"))
                    .and_then(|c| c.as_str())
                {
                    let redacted = self.redact_text(content);
                    if redacted != content {
                        choice["delta"]["content"] = Value::String(redacted);
                    }
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
        if let Some(candidates) = json.get_mut("candidates").and_then(|c| c.as_array_mut()) {
            for candidate in candidates.iter_mut() {
                if let Some(parts) = candidate
                    .get_mut("content")
                    .and_then(|c| c.get_mut("parts"))
                    .and_then(|p| p.as_array_mut())
                {
                    for part in parts.iter_mut() {
                        if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                            let redacted = self.redact_text(text);
                            if redacted != text {
                                part["text"] = Value::String(redacted);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Check max completion length constraint.
    fn check_completion_length(&self, texts: &[&str]) -> Option<String> {
        if self.max_completion_length == 0 {
            return None;
        }
        for text in texts {
            if text.len() > self.max_completion_length {
                return Some(format!(
                    "Completion length {} exceeds maximum {}",
                    text.len(),
                    self.max_completion_length
                ));
            }
        }
        None
    }
}

/// Escape special characters for safe JSON string interpolation.
fn escape_json_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
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
        super::HTTP_GRPC_PROTOCOLS
    }

    fn requires_response_body_buffering(&self) -> bool {
        self.has_patterns
    }

    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        // Only buffer for POST requests — AI/LLM responses to inspect.
        // Method-only check covers multipart uploads that return JSON responses.
        self.has_patterns && ctx.method == "POST"
    }

    async fn on_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Only inspect successful responses
        if !(200..300).contains(&response_status) {
            return PluginResult::Continue;
        }

        let content_type = response_headers
            .get("content-type")
            .map(|s| s.as_str())
            .unwrap_or("");

        if !content_type.contains("json") {
            return PluginResult::Continue;
        }

        if body.is_empty() || body.len() > self.max_scan_bytes {
            if body.len() > self.max_scan_bytes {
                debug!(
                    "ai_response_guard: body size {} exceeds max_scan_bytes {}, skipping",
                    body.len(),
                    self.max_scan_bytes
                );
            }
            return PluginResult::Continue;
        }

        // Parse JSON
        let json: Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(_) => {
                if self.require_json {
                    return PluginResult::Reject {
                        status_code: 502,
                        body: r#"{"error":"AI response is not valid JSON"}"#.to_string(),
                        headers: HashMap::new(),
                    };
                }
                return PluginResult::Continue;
            }
        };

        // Check required fields
        for field in &self.required_fields {
            if json.get(field.as_str()).is_none() {
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

        // Extract completion texts
        let texts = if self.scan_mode == ScanMode::All {
            Vec::new() // handled separately below
        } else {
            self.extract_completion_texts(&json)
        };

        // Check max completion length
        if !texts.is_empty()
            && let Some(reason) = self.check_completion_length(&texts)
        {
            match self.action {
                GuardAction::Reject => {
                    return PluginResult::Reject {
                        status_code: 502,
                        body: format!(
                            r#"{{"error":"AI response guard: {}"}}"#,
                            escape_json_string(&reason)
                        ),
                        headers: HashMap::new(),
                    };
                }
                GuardAction::Warn | GuardAction::Redact => {
                    ctx.metadata
                        .insert("ai_response_guard_warning".to_string(), reason);
                }
            }
        }

        // Detect PII and blocked content
        let detected = if self.scan_mode == ScanMode::All {
            let body_str = match std::str::from_utf8(body) {
                Ok(s) => s,
                Err(_) => return PluginResult::Continue,
            };
            self.detect_matches_in_str(body_str)
        } else {
            self.detect_matches(&texts)
        };

        if detected.is_empty() {
            return PluginResult::Continue;
        }

        match self.action {
            GuardAction::Reject => {
                debug!(
                    "ai_response_guard: content detected (types: {:?}), rejecting response",
                    detected
                );
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
                // Detection done — actual redaction happens in transform_response_body.
                ctx.metadata
                    .insert("ai_response_guard_redacted".to_string(), detected.join(","));
                PluginResult::Continue
            }
        }
    }

    async fn transform_response_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        _response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        if !self.needs_body_transform {
            return None;
        }

        if let Some(ct) = content_type
            && !ct.contains("json")
        {
            return None;
        }

        if body.len() > self.max_scan_bytes {
            return None;
        }

        let mut json: Value = serde_json::from_slice(body).ok()?;

        if self.scan_mode == ScanMode::All {
            let body_str = std::str::from_utf8(body).ok()?;
            let has_match = self
                .pii_patterns
                .iter()
                .chain(self.blocked_phrases.iter())
                .any(|p| p.regex.is_match(body_str));
            if !has_match {
                return None;
            }
            redact_json_strings(
                &mut json,
                &self.pii_patterns,
                &self.blocked_phrases,
                &self.redaction_template,
            );
        } else {
            let texts = self.extract_completion_texts(&json);
            let has_match = !self.detect_matches(&texts).is_empty();
            if !has_match {
                return None;
            }
            self.redact_response_json(&mut json);
        }

        serde_json::to_vec(&json).ok()
    }
}

/// Recursively redact matches in all string values within a JSON Value.
fn redact_json_strings(
    value: &mut Value,
    pii_patterns: &[ContentPattern],
    blocked_phrases: &[ContentPattern],
    template: &str,
) {
    match value {
        Value::String(s) => {
            let mut result = s.clone();
            for pattern in pii_patterns.iter().chain(blocked_phrases.iter()) {
                let placeholder = template.replace("{type}", &pattern.name);
                result = pattern
                    .regex
                    .replace_all(&result, placeholder.as_str())
                    .to_string();
            }
            if result != *s {
                *s = result;
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                redact_json_strings(item, pii_patterns, blocked_phrases, template);
            }
        }
        Value::Object(map) => {
            for val in map.values_mut() {
                redact_json_strings(val, pii_patterns, blocked_phrases, template);
            }
        }
        _ => {}
    }
}

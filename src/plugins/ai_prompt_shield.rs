//! AI Prompt Shield Plugin
//!
//! Scans AI/LLM request bodies for PII (personally identifiable information)
//! patterns and either rejects the request, redacts the PII, or logs a warning.
//!
//! Built-in patterns: SSN, credit card, email, US phone, API keys, AWS keys,
//! IPv4 addresses, and IBAN. Custom regex patterns can be added via config.

use async_trait::async_trait;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use tracing::{debug, warn};

use super::{Plugin, PluginResult, RequestContext};

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
}

pub struct AiPromptShield {
    action: ShieldAction,
    patterns: Vec<PiiPattern>,
    scan_mode: ScanMode,
    exclude_roles: Vec<String>,
    redaction_template: String,
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
        let action = match config["action"].as_str().unwrap_or("reject") {
            "redact" => ShieldAction::Redact,
            "warn" => ShieldAction::Warn,
            _ => ShieldAction::Reject,
        };

        let scan_mode = if config["scan_fields"].as_str().unwrap_or("content") == "all" {
            ScanMode::All
        } else {
            ScanMode::Content
        };

        let exclude_roles: Vec<String> = config["exclude_roles"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let redaction_template = config["redaction_placeholder"]
            .as_str()
            .unwrap_or("[REDACTED:{type}]")
            .to_string();

        let max_scan_bytes = config["max_scan_bytes"].as_u64().unwrap_or(1_048_576) as usize;

        // Build pattern list from config
        let pattern_names: Vec<String> = config["patterns"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_else(|| {
                vec![
                    "ssn".to_string(),
                    "credit_card".to_string(),
                    "api_key".to_string(),
                    "aws_key".to_string(),
                ]
            });

        let mut patterns: Vec<PiiPattern> = Vec::new();

        // Add built-in patterns
        for name in &pattern_names {
            if let Some(regex_str) = builtin_pattern(name) {
                match Regex::new(regex_str) {
                    Ok(regex) => patterns.push(PiiPattern {
                        name: name.clone(),
                        regex,
                    }),
                    Err(e) => {
                        tracing::warn!(
                            "ai_prompt_shield: failed to compile built-in pattern '{}': {}",
                            name,
                            e,
                        );
                    }
                }
            } else {
                tracing::warn!(
                    "ai_prompt_shield: unknown built-in pattern '{}', skipping",
                    name,
                );
            }
        }

        // Add custom patterns
        if let Some(custom) = config["custom_patterns"].as_array() {
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
                    Ok(regex) => patterns.push(PiiPattern { name, regex }),
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

        Ok(Self {
            action,
            patterns,
            scan_mode,
            exclude_roles,
            redaction_template,
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
                        // Skip excluded roles
                        if let Some(role) = msg.get("role").and_then(|r| r.as_str())
                            && self.exclude_roles.iter().any(|r| r == role)
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
                texts
            }
        }
    }

    /// Detect PII in the given text segments. Returns names of detected pattern types.
    fn detect_pii(&self, texts: &[&str]) -> Vec<String> {
        let mut detected = Vec::new();
        for pattern in &self.patterns {
            for text in texts {
                if pattern.regex.is_match(text) {
                    detected.push(pattern.name.clone());
                    break; // One match per pattern is enough
                }
            }
        }
        detected
    }

    /// Detect PII in a raw string (for "all" scan mode).
    fn detect_pii_in_str(&self, text: &str) -> Vec<String> {
        let mut detected = Vec::new();
        for pattern in &self.patterns {
            if pattern.regex.is_match(text) {
                detected.push(pattern.name.clone());
            }
        }
        detected
    }

    /// Apply redaction to message content fields in the JSON body.
    fn redact_body(&self, json: &mut Value) {
        if let Some(messages) = json.get_mut("messages").and_then(|v| v.as_array_mut()) {
            for msg in messages.iter_mut() {
                // Skip excluded roles
                if let Some(role) = msg.get("role").and_then(|r| r.as_str())
                    && self.exclude_roles.iter().any(|r| r == role)
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
    }

    /// Replace all PII pattern matches in the text with the redaction placeholder.
    fn redact_text(&self, text: &str) -> String {
        let mut result = text.to_string();
        for pattern in &self.patterns {
            let placeholder = self.redaction_template.replace("{type}", &pattern.name);
            result = pattern
                .regex
                .replace_all(&result, placeholder.as_str())
                .to_string();
        }
        result
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
                .is_some_and(|ct| ct.to_ascii_lowercase().contains("json"))
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
            .or_else(|| ctx.headers.get("content-type"))
            .map(|s| s.as_str())
            .unwrap_or("");
        if !content_type.contains("json") {
            return PluginResult::Continue;
        }

        // Get request body
        let body = match ctx.metadata.get("request_body") {
            Some(b) if !b.is_empty() => b.clone(),
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

        // Detect PII
        let detected = if self.scan_mode == ScanMode::All {
            self.detect_pii_in_str(&body)
        } else {
            match serde_json::from_str::<Value>(&body) {
                Ok(json) => {
                    let texts = self.extract_scan_text(&json);
                    self.detect_pii(&texts)
                }
                Err(_) => return PluginResult::Continue,
            }
        };

        if detected.is_empty() {
            return PluginResult::Continue;
        }

        match self.action {
            ShieldAction::Reject => {
                debug!(
                    "ai_prompt_shield: PII detected (types: {:?}), rejecting request",
                    detected
                );
                let types_json: Vec<String> = detected
                    .iter()
                    .map(|t| format!("\"{}\"", escape_json_string(t)))
                    .collect();
                PluginResult::Reject {
                    status_code: 400,
                    body: format!(
                        r#"{{"error":"PII detected in request","detected_types":[{}],"message":"Request blocked: potential PII detected. Remove sensitive data before sending to AI provider."}}"#,
                        types_json.join(","),
                    ),
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
                // Detection done — actual redaction happens in transform_request_body.
                // Store detected types for observability.
                ctx.metadata
                    .insert("ai_shield_redacted".to_string(), detected.join(","));
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
            && !ct.contains("json")
        {
            return None;
        }

        if body.len() > self.max_scan_bytes {
            return None;
        }

        let mut json: Value = serde_json::from_slice(body).ok()?;

        if self.scan_mode == ScanMode::All {
            // For "all" mode, redact within all string values in the JSON
            let body_str = std::str::from_utf8(body).ok()?;
            let mut has_pii = false;
            for pattern in &self.patterns {
                if pattern.regex.is_match(body_str) {
                    has_pii = true;
                    break;
                }
            }
            if !has_pii {
                return None;
            }
            // Redact string values throughout the JSON
            redact_json_strings(&mut json, &self.patterns, &self.redaction_template);
            return serde_json::to_vec(&json).ok();
        }

        // Content mode: only redact within messages
        let texts = self.extract_scan_text(&json);
        let has_pii = !self.detect_pii(&texts).is_empty();
        if !has_pii {
            return None;
        }

        self.redact_body(&mut json);
        serde_json::to_vec(&json).ok()
    }
}

/// Recursively redact PII in all string values within a JSON Value.
fn redact_json_strings(value: &mut Value, patterns: &[PiiPattern], template: &str) {
    match value {
        Value::String(s) => {
            let mut result = s.clone();
            for pattern in patterns {
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
                redact_json_strings(item, patterns, template);
            }
        }
        Value::Object(map) => {
            for val in map.values_mut() {
                redact_json_strings(val, patterns, template);
            }
        }
        _ => {}
    }
}

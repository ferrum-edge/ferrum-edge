//! Body Validation Plugin
//!
//! Validates JSON and XML request bodies against schemas before proxying.
//! For JSON, validates against a JSON Schema. For XML, validates that the
//! body is well-formed XML and optionally checks for required elements.
//!
//! The plugin reads the request body from the Content-Type header to
//! determine the validation strategy, then validates the body content
//! from the request.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tracing::debug;

use super::{Plugin, PluginResult, RequestContext};

pub struct BodyValidator {
    /// JSON schema for validation (if configured).
    json_schema: Option<Value>,
    /// Required JSON fields (simple validation without full JSON Schema).
    required_fields: Vec<String>,
    /// Whether to validate XML is well-formed.
    validate_xml: bool,
    /// Required XML elements.
    required_xml_elements: Vec<String>,
    /// Content types to validate (empty = validate all).
    content_types: Vec<String>,
}

impl BodyValidator {
    pub fn new(config: &Value) -> Self {
        let json_schema = config.get("json_schema").cloned();

        let required_fields = config["required_fields"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let validate_xml = config["validate_xml"].as_bool().unwrap_or(false);

        let required_xml_elements = config["required_xml_elements"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let content_types = config["content_types"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                    .collect()
            })
            .unwrap_or_else(|| {
                vec![
                    "application/json".to_string(),
                    "application/xml".to_string(),
                    "text/xml".to_string(),
                ]
            });

        Self {
            json_schema,
            required_fields,
            validate_xml,
            required_xml_elements,
            content_types,
        }
    }

    fn validate_json_body(&self, body: &str) -> Result<(), String> {
        // Parse as JSON
        let parsed: Value =
            serde_json::from_str(body).map_err(|e| format!("Invalid JSON: {}", e))?;

        // Check required fields
        if let Value::Object(map) = &parsed {
            for field in &self.required_fields {
                if !map.contains_key(field) {
                    return Err(format!("Missing required field: {}", field));
                }
            }
        } else if !self.required_fields.is_empty() {
            return Err("Request body must be a JSON object".to_string());
        }

        // Validate against JSON Schema if provided
        if let Some(schema) = &self.json_schema {
            self.validate_against_schema(&parsed, schema)?;
        }

        Ok(())
    }

    fn validate_against_schema(&self, data: &Value, schema: &Value) -> Result<(), String> {
        // Simple JSON Schema validation (type checking, required, properties)
        if let Some(schema_type) = schema.get("type").and_then(|t| t.as_str()) {
            let type_valid = match schema_type {
                "object" => data.is_object(),
                "array" => data.is_array(),
                "string" => data.is_string(),
                "number" => data.is_number(),
                "integer" => data.is_i64() || data.is_u64(),
                "boolean" => data.is_boolean(),
                "null" => data.is_null(),
                _ => true,
            };
            if !type_valid {
                return Err(format!(
                    "Expected type '{}', got '{}'",
                    schema_type,
                    json_type_name(data)
                ));
            }
        }

        // Check required properties
        if let (Some(required), Some(data_obj)) = (
            schema.get("required").and_then(|r| r.as_array()),
            data.as_object(),
        ) {
            for req in required {
                if let Some(field_name) = req.as_str()
                    && !data_obj.contains_key(field_name)
                {
                    return Err(format!("Missing required property: {}", field_name));
                }
            }
        }

        // Validate properties
        if let (Some(props), Some(data_obj)) = (
            schema.get("properties").and_then(|p| p.as_object()),
            data.as_object(),
        ) {
            for (key, prop_schema) in props {
                if let Some(value) = data_obj.get(key) {
                    self.validate_against_schema(value, prop_schema)?;
                }
            }
        }

        Ok(())
    }

    fn validate_xml_body(&self, body: &str) -> Result<(), String> {
        // Basic well-formedness check: must start with < and have matching tags
        let trimmed = body.trim();
        if trimmed.is_empty() {
            return Err("Empty XML body".to_string());
        }
        if !trimmed.starts_with('<') {
            return Err("Invalid XML: must start with '<'".to_string());
        }

        // Check for required elements
        for element in &self.required_xml_elements {
            let open_tag = format!("<{}", element);
            if !trimmed.contains(&open_tag) {
                return Err(format!("Missing required XML element: {}", element));
            }
        }

        // Tag balance check with proper handling of CDATA, comments,
        // processing instructions, and DOCTYPE declarations.
        let bytes = trimmed.as_bytes();
        let len = bytes.len();
        let mut depth: i32 = 0;
        let mut i = 0;

        while i < len {
            if bytes[i] != b'<' {
                i += 1;
                continue;
            }

            // We're at a '<' — determine what kind of construct follows
            let remaining = &bytes[i..];

            // CDATA section: <![CDATA[ ... ]]>
            if remaining.starts_with(b"<![CDATA[") {
                match find_subsequence(&bytes[i + 9..], b"]]>") {
                    Some(end) => {
                        i = i + 9 + end + 3;
                        continue;
                    }
                    None => return Err("Unterminated CDATA section".to_string()),
                }
            }

            // Comment: <!-- ... -->
            if remaining.starts_with(b"<!--") {
                match find_subsequence(&bytes[i + 4..], b"-->") {
                    Some(end) => {
                        i = i + 4 + end + 3;
                        continue;
                    }
                    None => return Err("Unterminated XML comment".to_string()),
                }
            }

            // Processing instruction: <? ... ?>
            if remaining.len() >= 2 && remaining[1] == b'?' {
                match find_subsequence(&bytes[i + 2..], b"?>") {
                    Some(end) => {
                        i = i + 2 + end + 2;
                        continue;
                    }
                    None => return Err("Unterminated processing instruction".to_string()),
                }
            }

            // DOCTYPE declaration: <!DOCTYPE ... >
            if remaining.starts_with(b"<!") {
                // Skip any <! declaration (DOCTYPE, etc.) — find matching >
                match find_byte(&bytes[i + 2..], b'>') {
                    Some(end) => {
                        i = i + 2 + end + 1;
                        continue;
                    }
                    None => return Err("Unterminated declaration".to_string()),
                }
            }

            // Closing tag: </...>
            if remaining.len() >= 2 && remaining[1] == b'/' {
                match find_byte(&bytes[i + 2..], b'>') {
                    Some(end) => {
                        depth -= 1;
                        i = i + 2 + end + 1;
                        continue;
                    }
                    None => return Err("Unterminated closing tag".to_string()),
                }
            }

            // Regular tag: <name ... /> or <name ... >
            match find_byte(&bytes[i + 1..], b'>') {
                Some(end) => {
                    // Check if self-closing (ends with />)
                    let tag_end = i + 1 + end;
                    if tag_end > 0 && bytes[tag_end - 1] == b'/' {
                        // Self-closing tag — no depth change
                    } else {
                        depth += 1;
                    }
                    i = tag_end + 1;
                }
                None => return Err("Unterminated tag".to_string()),
            }
        }

        if depth != 0 {
            return Err(format!("Unbalanced XML tags (depth {})", depth));
        }

        Ok(())
    }
}

/// Find the position of a byte subsequence within a slice.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Find the position of a single byte within a slice.
fn find_byte(haystack: &[u8], needle: u8) -> Option<usize> {
    haystack.iter().position(|&b| b == needle)
}

fn json_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Plugin priority: runs in transform band, before proxying.
pub const BODY_VALIDATOR_PRIORITY: u16 = 2950;

#[async_trait]
impl Plugin for BodyValidator {
    fn name(&self) -> &str {
        "body_validator"
    }

    fn priority(&self) -> u16 {
        BODY_VALIDATOR_PRIORITY
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        _headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Only validate methods that typically have a body
        if matches!(ctx.method.as_str(), "GET" | "HEAD" | "OPTIONS" | "DELETE") {
            return PluginResult::Continue;
        }

        // Check content type
        let content_type = ctx
            .headers
            .get("content-type")
            .cloned()
            .unwrap_or_default()
            .to_lowercase();

        let should_validate = self.content_types.is_empty()
            || self
                .content_types
                .iter()
                .any(|ct| content_type.contains(ct.as_str()));

        if !should_validate {
            return PluginResult::Continue;
        }

        // Get body from metadata (set by proxy handler if body collection is early)
        let body = match ctx.metadata.get("request_body") {
            Some(b) => b.clone(),
            None => {
                // No body available — can't validate
                debug!("body_validator: no request body available for validation");
                return PluginResult::Continue;
            }
        };

        if body.is_empty() {
            return PluginResult::Continue;
        }

        // Determine validation type
        let result = if content_type.contains("json") {
            self.validate_json_body(&body)
        } else if content_type.contains("xml") && self.validate_xml {
            self.validate_xml_body(&body)
        } else {
            Ok(())
        };

        match result {
            Ok(()) => PluginResult::Continue,
            Err(msg) => {
                debug!("body_validator: validation failed: {}", msg);
                let escaped_msg = msg.replace('\\', "\\\\").replace('"', "\\\"");
                PluginResult::Reject {
                    status_code: 400,
                    body: format!(
                        r#"{{"error":"Request body validation failed","details":"{}"}}"#,
                        escaped_msg
                    ),
                    headers: HashMap::new(),
                }
            }
        }
    }
}

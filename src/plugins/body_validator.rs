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
    /// Pre-compiled regexes for JSON Schema `pattern` constraints.
    /// Keyed by the pattern string so lookup is O(1) at request time.
    compiled_patterns: HashMap<String, regex::Regex>,
}

impl BodyValidator {
    pub fn new(config: &Value) -> Self {
        let json_schema = config.get("json_schema").cloned();

        let required_fields: Vec<String> = config["required_fields"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let validate_xml = config["validate_xml"].as_bool().unwrap_or(false);

        let required_xml_elements: Vec<String> = config["required_xml_elements"]
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

        if json_schema.is_none()
            && required_fields.is_empty()
            && !validate_xml
            && required_xml_elements.is_empty()
        {
            tracing::warn!(
                "body_validator: no validation rules configured — set 'json_schema', 'required_fields', 'validate_xml', or 'required_xml_elements'"
            );
        }

        // Pre-compile all regex patterns found in the JSON schema at config load time.
        let mut compiled_patterns = HashMap::new();
        if let Some(ref schema) = json_schema {
            collect_patterns(schema, &mut compiled_patterns);
        }

        Self {
            json_schema,
            required_fields,
            validate_xml,
            required_xml_elements,
            content_types,
            compiled_patterns,
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
        // --- enum constraint (applies to any type) ---
        if let Some(enum_values) = schema.get("enum").and_then(|e| e.as_array())
            && !enum_values.contains(data)
        {
            return Err(format!(
                "Value {} is not one of the allowed enum values",
                data
            ));
        }

        // --- const constraint ---
        if let Some(const_val) = schema.get("const")
            && data != const_val
        {
            return Err(format!("Value must be {}", const_val));
        }

        // --- type checking ---
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

        // --- string constraints ---
        if let Some(s) = data.as_str() {
            if let Some(min) = schema.get("minLength").and_then(|v| v.as_u64())
                && (s.len() as u64) < min
            {
                return Err(format!(
                    "String length {} is less than minLength {}",
                    s.len(),
                    min
                ));
            }
            if let Some(max) = schema.get("maxLength").and_then(|v| v.as_u64())
                && (s.len() as u64) > max
            {
                return Err(format!(
                    "String length {} exceeds maxLength {}",
                    s.len(),
                    max
                ));
            }
            if let Some(pattern) = schema.get("pattern").and_then(|v| v.as_str()) {
                if let Some(re) = self.compiled_patterns.get(pattern) {
                    if !re.is_match(s) {
                        return Err(format!(
                            "String '{}' does not match pattern '{}'",
                            s, pattern
                        ));
                    }
                } else {
                    // Fallback: pattern wasn't found during schema walk (shouldn't happen)
                    match regex::Regex::new(pattern) {
                        Ok(re) => {
                            if !re.is_match(s) {
                                return Err(format!(
                                    "String '{}' does not match pattern '{}'",
                                    s, pattern
                                ));
                            }
                        }
                        Err(e) => {
                            return Err(format!("Invalid regex pattern '{}': {}", pattern, e));
                        }
                    }
                }
            }
            if let Some(format_name) = schema.get("format").and_then(|v| v.as_str()) {
                validate_format(s, format_name)?;
            }
        }

        // --- numeric constraints ---
        if let Some(n) = data.as_f64() {
            if let Some(min) = schema.get("minimum").and_then(|v| v.as_f64())
                && n < min
            {
                return Err(format!("Value {} is less than minimum {}", n, min));
            }
            if let Some(max) = schema.get("maximum").and_then(|v| v.as_f64())
                && n > max
            {
                return Err(format!("Value {} exceeds maximum {}", n, max));
            }
            if let Some(ex_min) = schema.get("exclusiveMinimum").and_then(|v| v.as_f64())
                && n <= ex_min
            {
                return Err(format!(
                    "Value {} must be greater than exclusiveMinimum {}",
                    n, ex_min
                ));
            }
            if let Some(ex_max) = schema.get("exclusiveMaximum").and_then(|v| v.as_f64())
                && n >= ex_max
            {
                return Err(format!(
                    "Value {} must be less than exclusiveMaximum {}",
                    n, ex_max
                ));
            }
            if let Some(multiple) = schema.get("multipleOf").and_then(|v| v.as_f64())
                && multiple != 0.0
                && (n % multiple).abs() > f64::EPSILON
            {
                return Err(format!("Value {} is not a multiple of {}", n, multiple));
            }
        }

        // --- required properties (object) ---
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

        // --- validate object properties ---
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

        // --- additionalProperties ---
        if let Some(data_obj) = data.as_object() {
            let defined_props = schema.get("properties").and_then(|p| p.as_object());
            if let Some(additional) = schema.get("additionalProperties") {
                if additional.as_bool() == Some(false) {
                    if let Some(defined) = defined_props {
                        for key in data_obj.keys() {
                            if !defined.contains_key(key) {
                                return Err(format!(
                                    "Additional property '{}' is not allowed",
                                    key
                                ));
                            }
                        }
                    }
                } else if additional.is_object() {
                    let defined_keys: std::collections::HashSet<&String> = defined_props
                        .map(|d| d.keys().collect())
                        .unwrap_or_default();
                    for (key, value) in data_obj {
                        if !defined_keys.contains(key) {
                            self.validate_against_schema(value, additional)?;
                        }
                    }
                }
            }

            // --- minProperties / maxProperties ---
            if let Some(min) = schema.get("minProperties").and_then(|v| v.as_u64())
                && (data_obj.len() as u64) < min
            {
                return Err(format!(
                    "Object has {} properties, minimum is {}",
                    data_obj.len(),
                    min
                ));
            }
            if let Some(max) = schema.get("maxProperties").and_then(|v| v.as_u64())
                && (data_obj.len() as u64) > max
            {
                return Err(format!(
                    "Object has {} properties, maximum is {}",
                    data_obj.len(),
                    max
                ));
            }
        }

        // --- array constraints ---
        if let Some(arr) = data.as_array() {
            if let Some(items_schema) = schema.get("items") {
                for (i, item) in arr.iter().enumerate() {
                    self.validate_against_schema(item, items_schema)
                        .map_err(|e| format!("Array item [{}]: {}", i, e))?;
                }
            }

            if let Some(min) = schema.get("minItems").and_then(|v| v.as_u64())
                && (arr.len() as u64) < min
            {
                return Err(format!("Array has {} items, minimum is {}", arr.len(), min));
            }
            if let Some(max) = schema.get("maxItems").and_then(|v| v.as_u64())
                && (arr.len() as u64) > max
            {
                return Err(format!("Array has {} items, maximum is {}", arr.len(), max));
            }
            if schema.get("uniqueItems").and_then(|v| v.as_bool()) == Some(true) {
                for i in 0..arr.len() {
                    for j in (i + 1)..arr.len() {
                        if arr[i] == arr[j] {
                            return Err(format!(
                                "Array items at index {} and {} are not unique",
                                i, j
                            ));
                        }
                    }
                }
            }
        }

        // --- composition: allOf, anyOf, oneOf, not ---
        if let Some(all_of) = schema.get("allOf").and_then(|v| v.as_array()) {
            for (i, sub_schema) in all_of.iter().enumerate() {
                self.validate_against_schema(data, sub_schema)
                    .map_err(|e| format!("allOf[{}]: {}", i, e))?;
            }
        }

        if let Some(any_of) = schema.get("anyOf").and_then(|v| v.as_array()) {
            let matched = any_of
                .iter()
                .any(|sub| self.validate_against_schema(data, sub).is_ok());
            if !matched {
                return Err("Value does not match any of the anyOf schemas".to_string());
            }
        }

        if let Some(one_of) = schema.get("oneOf").and_then(|v| v.as_array()) {
            let match_count = one_of
                .iter()
                .filter(|sub| self.validate_against_schema(data, sub).is_ok())
                .count();
            if match_count != 1 {
                return Err(format!(
                    "Value must match exactly one oneOf schema, but matched {}",
                    match_count
                ));
            }
        }

        if let Some(not_schema) = schema.get("not")
            && self.validate_against_schema(data, not_schema).is_ok()
        {
            return Err("Value must not match the 'not' schema".to_string());
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

/// Recursively walk a JSON Schema and pre-compile all `pattern` regex strings.
fn collect_patterns(schema: &Value, patterns: &mut HashMap<String, regex::Regex>) {
    if let Some(pattern) = schema.get("pattern").and_then(|v| v.as_str())
        && !patterns.contains_key(pattern)
    {
        match regex::Regex::new(pattern) {
            Ok(re) => {
                patterns.insert(pattern.to_string(), re);
            }
            Err(e) => {
                tracing::warn!(
                    "body_validator: invalid regex pattern '{}' in schema: {}",
                    pattern,
                    e
                );
            }
        }
    }

    // Recurse into sub-schemas
    if let Some(props) = schema.get("properties").and_then(|p| p.as_object()) {
        for prop_schema in props.values() {
            collect_patterns(prop_schema, patterns);
        }
    }
    if let Some(items) = schema.get("items") {
        collect_patterns(items, patterns);
    }
    if let Some(additional) = schema.get("additionalProperties")
        && additional.is_object()
    {
        collect_patterns(additional, patterns);
    }
    for keyword in &["allOf", "anyOf", "oneOf"] {
        if let Some(arr) = schema.get(*keyword).and_then(|v| v.as_array()) {
            for sub in arr {
                collect_patterns(sub, patterns);
            }
        }
    }
    if let Some(not_schema) = schema.get("not") {
        collect_patterns(not_schema, patterns);
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

/// Validate common string formats (subset of JSON Schema format vocabulary).
fn validate_format(s: &str, format_name: &str) -> Result<(), String> {
    match format_name {
        "email" => {
            // Basic email check: contains exactly one @ with non-empty local and domain parts
            if !s.contains('@')
                || s.starts_with('@')
                || s.ends_with('@')
                || s.matches('@').count() != 1
            {
                return Err(format!("'{}' is not a valid email format", s));
            }
        }
        "ipv4" => {
            if s.parse::<std::net::Ipv4Addr>().is_err() {
                return Err(format!("'{}' is not a valid IPv4 address", s));
            }
        }
        "ipv6" => {
            if s.parse::<std::net::Ipv6Addr>().is_err() {
                return Err(format!("'{}' is not a valid IPv6 address", s));
            }
        }
        "uri" | "uri-reference" => {
            if !s.contains(':') && !s.starts_with('/') && !s.starts_with('#') {
                return Err(format!("'{}' is not a valid URI", s));
            }
        }
        "date-time" => {
            if chrono::DateTime::parse_from_rfc3339(s).is_err() {
                return Err(format!("'{}' is not a valid RFC 3339 date-time", s));
            }
        }
        "date" => {
            if chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").is_err() {
                return Err(format!("'{}' is not a valid date (YYYY-MM-DD)", s));
            }
        }
        "uuid" => {
            if uuid::Uuid::parse_str(s).is_err() {
                return Err(format!("'{}' is not a valid UUID", s));
            }
        }
        _ => {
            // Unknown format — ignore per JSON Schema spec (formats are advisory)
        }
    }
    Ok(())
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

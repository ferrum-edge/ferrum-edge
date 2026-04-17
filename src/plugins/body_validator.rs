//! Body Validation Plugin
//!
//! Validates JSON, XML, and gRPC protobuf request and response bodies against schemas.
//! For JSON, validates against a JSON Schema. For XML, validates that the
//! body is well-formed XML and optionally checks for required elements.
//! For gRPC protobuf, validates against a compiled `FileDescriptorSet`.
//!
//! Request validation for JSON/XML runs in `before_proxy` (rejects with 400).
//! Request validation for protobuf runs in `on_final_request_body` (rejects with 400).
//! Response validation runs in `on_final_response_body` (rejects with 502)
//! and requires response body buffering when configured.

use async_trait::async_trait;
use flate2::read::GzDecoder;
use prost_reflect::{DescriptorPool, DynamicMessage, MessageDescriptor};
use serde_json::Value;
use std::collections::HashMap;
use std::io::Read as _;
use tracing::{debug, warn};

use super::{Plugin, PluginResult, RequestContext};

/// Per-method message type descriptors for protobuf validation.
struct ProtobufMethodEntry {
    request: Option<MessageDescriptor>,
    response: Option<MessageDescriptor>,
}

pub struct BodyValidator {
    // ── Request validation config ──
    /// JSON schema for request body validation (if configured).
    json_schema: Option<Value>,
    /// Required JSON fields (simple validation without full JSON Schema).
    required_fields: Vec<String>,
    /// Whether to validate XML request bodies are well-formed.
    validate_xml: bool,
    /// Required XML elements in request bodies.
    required_xml_elements: Vec<String>,
    /// Content types to validate for requests (empty = validate all).
    content_types: Vec<String>,
    /// Pre-compiled regexes for JSON Schema `pattern` constraints (request).
    compiled_patterns: HashMap<String, regex::Regex>,

    // ── Response validation config ──
    /// JSON schema for response body validation (if configured).
    response_json_schema: Option<Value>,
    /// Required JSON fields in response bodies.
    response_required_fields: Vec<String>,
    /// Whether to validate XML response bodies are well-formed.
    response_validate_xml: bool,
    /// Required XML elements in response bodies.
    response_required_xml_elements: Vec<String>,
    /// Content types to validate for responses.
    response_content_types: Vec<String>,
    /// Pre-compiled regexes for response JSON Schema `pattern` constraints.
    response_compiled_patterns: HashMap<String, regex::Regex>,

    // ── Protobuf validation config ──
    /// Descriptor pool loaded from the compiled `FileDescriptorSet` binary.
    /// Retained so message descriptors remain valid (they borrow from the pool).
    _protobuf_pool: Option<DescriptorPool>,
    /// Default request message descriptor (for methods not in `protobuf_method_messages`).
    protobuf_request_descriptor: Option<MessageDescriptor>,
    /// Default response message descriptor.
    protobuf_response_descriptor: Option<MessageDescriptor>,
    /// Per-method message type overrides keyed by gRPC path (e.g., `/pkg.Svc/Method`).
    protobuf_method_messages: HashMap<String, ProtobufMethodEntry>,
    /// Whether to reject messages with unknown field numbers.
    protobuf_reject_unknown_fields: bool,

    // ── Cached flags ──
    /// Whether any request validation is configured (cached for O(1) checks).
    has_request_validation: bool,
    /// Whether any response validation is configured (cached for O(1) check).
    has_response_validation: bool,
    /// Whether protobuf request validation is configured.
    has_protobuf_request_validation: bool,
    /// Whether protobuf response validation is configured.
    has_protobuf_response_validation: bool,
}

impl BodyValidator {
    pub fn new(config: &Value) -> Result<Self, String> {
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

        // ── Response validation config ──
        let response_json_schema = config.get("response_json_schema").cloned();

        let response_required_fields: Vec<String> = config["response_required_fields"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let response_validate_xml = config["response_validate_xml"].as_bool().unwrap_or(false);

        let response_required_xml_elements: Vec<String> = config["response_required_xml_elements"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let response_content_types = config["response_content_types"]
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

        // ── Protobuf validation config ──
        let (
            protobuf_pool,
            protobuf_request_descriptor,
            protobuf_response_descriptor,
            protobuf_method_messages,
        ) = load_protobuf_config(config);
        let protobuf_reject_unknown_fields = config["protobuf_reject_unknown_fields"]
            .as_bool()
            .unwrap_or(false);

        let has_protobuf_request_validation = protobuf_request_descriptor.is_some()
            || protobuf_method_messages
                .values()
                .any(|e| e.request.is_some());
        let has_protobuf_response_validation = protobuf_response_descriptor.is_some()
            || protobuf_method_messages
                .values()
                .any(|e| e.response.is_some());

        let has_json_xml_request = json_schema.is_some()
            || !required_fields.is_empty()
            || validate_xml
            || !required_xml_elements.is_empty();
        let has_json_xml_response = response_json_schema.is_some()
            || !response_required_fields.is_empty()
            || response_validate_xml
            || !response_required_xml_elements.is_empty();

        let has_request_validation = has_json_xml_request || has_protobuf_request_validation;
        let has_response_validation = has_json_xml_response || has_protobuf_response_validation;

        if !has_request_validation && !has_response_validation {
            return Err(
                "body_validator: no validation rules configured — set 'json_schema', 'required_fields', 'validate_xml', 'required_xml_elements' (request), their 'response_*' equivalents, or 'protobuf_descriptor_path' with message types"
                    .to_string(),
            );
        }

        // Pre-compile all regex patterns found in schemas at config load time.
        let mut compiled_patterns = HashMap::new();
        if let Some(ref schema) = json_schema {
            collect_patterns(schema, &mut compiled_patterns);
        }
        let mut response_compiled_patterns = HashMap::new();
        if let Some(ref schema) = response_json_schema {
            collect_patterns(schema, &mut response_compiled_patterns);
        }

        Ok(Self {
            json_schema,
            required_fields,
            validate_xml,
            required_xml_elements,
            content_types,
            compiled_patterns,
            response_json_schema,
            response_required_fields,
            response_validate_xml,
            response_required_xml_elements,
            response_content_types,
            response_compiled_patterns,
            _protobuf_pool: protobuf_pool,
            protobuf_request_descriptor,
            protobuf_response_descriptor,
            protobuf_method_messages,
            protobuf_reject_unknown_fields,
            has_request_validation,
            has_response_validation,
            has_protobuf_request_validation,
            has_protobuf_response_validation,
        })
    }

    fn validate_json_body(
        &self,
        body: &str,
        required_fields: &[String],
        json_schema: Option<&Value>,
        compiled_patterns: &HashMap<String, regex::Regex>,
    ) -> Result<(), String> {
        // Parse as JSON
        let parsed: Value =
            serde_json::from_str(body).map_err(|e| format!("Invalid JSON: {}", e))?;

        // Check required fields
        if let Value::Object(map) = &parsed {
            for field in required_fields {
                if !map.contains_key(field) {
                    return Err(format!("Missing required field: {}", field));
                }
            }
        } else if !required_fields.is_empty() {
            return Err("Body must be a JSON object".to_string());
        }

        // Validate against JSON Schema if provided
        if let Some(schema) = json_schema {
            Self::validate_against_schema_with(compiled_patterns, &parsed, schema)?;
        }

        Ok(())
    }

    fn validate_against_schema_with(
        compiled_patterns: &HashMap<String, regex::Regex>,
        data: &Value,
        schema: &Value,
    ) -> Result<(), String> {
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
            // JSON Schema specifies minLength/maxLength count Unicode code points,
            // not bytes (RFC 8927 / JSON Schema Validation §6.3).
            let char_count = s.chars().count() as u64;
            if let Some(min) = schema.get("minLength").and_then(|v| v.as_u64())
                && char_count < min
            {
                return Err(format!(
                    "String length {} (code points) is less than minLength {}",
                    char_count, min
                ));
            }
            if let Some(max) = schema.get("maxLength").and_then(|v| v.as_u64())
                && char_count > max
            {
                return Err(format!(
                    "String length {} (code points) exceeds maxLength {}",
                    char_count, max
                ));
            }
            if let Some(pattern) = schema.get("pattern").and_then(|v| v.as_str()) {
                if let Some(re) = compiled_patterns.get(pattern) {
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
                    Self::validate_against_schema_with(compiled_patterns, value, prop_schema)?;
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
                            Self::validate_against_schema_with(
                                compiled_patterns,
                                value,
                                additional,
                            )?;
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
                    Self::validate_against_schema_with(compiled_patterns, item, items_schema)
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
                Self::validate_against_schema_with(compiled_patterns, data, sub_schema)
                    .map_err(|e| format!("allOf[{}]: {}", i, e))?;
            }
        }

        if let Some(any_of) = schema.get("anyOf").and_then(|v| v.as_array()) {
            let matched = any_of.iter().any(|sub| {
                Self::validate_against_schema_with(compiled_patterns, data, sub).is_ok()
            });
            if !matched {
                return Err("Value does not match any of the anyOf schemas".to_string());
            }
        }

        if let Some(one_of) = schema.get("oneOf").and_then(|v| v.as_array()) {
            let match_count = one_of
                .iter()
                .filter(|sub| {
                    Self::validate_against_schema_with(compiled_patterns, data, sub).is_ok()
                })
                .count();
            if match_count != 1 {
                return Err(format!(
                    "Value must match exactly one oneOf schema, but matched {}",
                    match_count
                ));
            }
        }

        if let Some(not_schema) = schema.get("not")
            && Self::validate_against_schema_with(compiled_patterns, data, not_schema).is_ok()
        {
            return Err("Value must not match the 'not' schema".to_string());
        }

        Ok(())
    }

    fn validate_xml_body(body: &str, required_xml_elements: &[String]) -> Result<(), String> {
        // Basic well-formedness check: must start with < and have matching tags
        let trimmed = body.trim();
        if trimmed.is_empty() {
            return Err("Empty XML body".to_string());
        }
        if !trimmed.starts_with('<') {
            return Err("Invalid XML: must start with '<'".to_string());
        }

        // Check for required elements
        for element in required_xml_elements {
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

    /// Validate a gRPC protobuf body (request or response) against a message descriptor.
    ///
    /// The body uses gRPC length-prefixed framing: 1 byte compressed flag + 4 bytes
    /// big-endian u32 message length + protobuf payload bytes.
    fn validate_protobuf_body(
        &self,
        body: &[u8],
        descriptor: &MessageDescriptor,
    ) -> Result<(), String> {
        let payload = parse_grpc_frame(body)?;
        let msg = DynamicMessage::decode(descriptor.clone(), payload.as_slice())
            .map_err(|e| format!("Protobuf decode failed: {}", e))?;
        if self.protobuf_reject_unknown_fields {
            let unknown_count = msg.unknown_fields().count();
            if unknown_count > 0 {
                return Err(format!(
                    "Message contains {} unknown field(s)",
                    unknown_count
                ));
            }
        }
        Ok(())
    }

    /// Look up the request message descriptor for a given gRPC path.
    fn get_request_descriptor(&self, grpc_path: &str) -> Option<&MessageDescriptor> {
        self.protobuf_method_messages
            .get(grpc_path)
            .and_then(|e| e.request.as_ref())
            .or(self.protobuf_request_descriptor.as_ref())
    }

    /// Look up the response message descriptor for a given gRPC path.
    fn get_response_descriptor(&self, grpc_path: &str) -> Option<&MessageDescriptor> {
        self.protobuf_method_messages
            .get(grpc_path)
            .and_then(|e| e.response.as_ref())
            .or(self.protobuf_response_descriptor.as_ref())
    }
}

/// Parse the first gRPC length-prefixed frame and return the protobuf payload bytes.
///
/// Frame format: [1 byte compressed flag] [4 bytes big-endian u32 length] [payload]
///
/// Supports unary RPCs only (single frame per message). For streaming RPCs the body
/// may contain multiple concatenated frames — this function validates only the first
/// frame and rejects trailing data via the length mismatch check.
///
/// When the compressed flag is set (byte 0 == 1), the payload is decompressed using
/// gzip (deflate), which is the standard gRPC compression algorithm. Other compression
/// algorithms (e.g., zstd, snappy) are not supported and will return an error.
fn parse_grpc_frame(body: &[u8]) -> Result<Vec<u8>, String> {
    if body.len() < 5 {
        return Err(format!(
            "gRPC frame too short: {} bytes (minimum 5)",
            body.len()
        ));
    }
    let compressed = body[0];
    let msg_len = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
    let payload = &body[5..];
    if payload.len() != msg_len {
        return Err(format!(
            "gRPC frame length mismatch: header says {} bytes but payload is {} bytes",
            msg_len,
            payload.len()
        ));
    }
    if compressed != 0 {
        // gRPC compression uses gzip (deflate) by default per the gRPC spec.
        let mut decoder = GzDecoder::new(payload);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| format!("Failed to decompress gRPC frame (gzip): {}", e))?;
        Ok(decompressed)
    } else {
        Ok(payload.to_vec())
    }
}

/// Load protobuf validation config from the plugin config JSON.
///
/// Reads `protobuf_descriptor_path`, resolves message types from
/// `protobuf_request_type`, `protobuf_response_type`, and `protobuf_method_messages`.
fn load_protobuf_config(
    config: &Value,
) -> (
    Option<DescriptorPool>,
    Option<MessageDescriptor>,
    Option<MessageDescriptor>,
    HashMap<String, ProtobufMethodEntry>,
) {
    let descriptor_path = match config
        .get("protobuf_descriptor_path")
        .and_then(|v| v.as_str())
    {
        Some(p) => p,
        None => return (None, None, None, HashMap::new()),
    };

    let descriptor_bytes = match std::fs::read(descriptor_path) {
        Ok(b) => b,
        Err(e) => {
            warn!(
                "body_validator: failed to read protobuf descriptor file '{}': {}",
                descriptor_path, e
            );
            return (None, None, None, HashMap::new());
        }
    };

    let pool = match DescriptorPool::decode(descriptor_bytes.as_slice()) {
        Ok(p) => p,
        Err(e) => {
            warn!(
                "body_validator: failed to parse protobuf descriptor '{}': {}",
                descriptor_path, e
            );
            return (None, None, None, HashMap::new());
        }
    };

    let request_desc = config
        .get("protobuf_request_type")
        .and_then(|v| v.as_str())
        .and_then(|name| {
            pool.get_message_by_name(name).or_else(|| {
                warn!(
                    "body_validator: protobuf_request_type '{}' not found in descriptor",
                    name
                );
                None
            })
        });

    let response_desc = config
        .get("protobuf_response_type")
        .and_then(|v| v.as_str())
        .and_then(|name| {
            pool.get_message_by_name(name).or_else(|| {
                warn!(
                    "body_validator: protobuf_response_type '{}' not found in descriptor",
                    name
                );
                None
            })
        });

    let mut method_map = HashMap::new();
    if let Some(methods) = config
        .get("protobuf_method_messages")
        .and_then(|v| v.as_object())
    {
        for (method_path, method_config) in methods {
            let req = method_config
                .get("request")
                .and_then(|v| v.as_str())
                .and_then(|name| {
                    pool.get_message_by_name(name).or_else(|| {
                        warn!(
                            "body_validator: method '{}' request type '{}' not found in descriptor",
                            method_path, name
                        );
                        None
                    })
                });
            let resp = method_config
                .get("response")
                .and_then(|v| v.as_str())
                .and_then(|name| {
                    pool.get_message_by_name(name).or_else(|| {
                        warn!(
                            "body_validator: method '{}' response type '{}' not found in descriptor",
                            method_path, name
                        );
                        None
                    })
                });
            if req.is_some() || resp.is_some() {
                method_map.insert(
                    method_path.clone(),
                    ProtobufMethodEntry {
                        request: req,
                        response: resp,
                    },
                );
            }
        }
    }

    (Some(pool), request_desc, response_desc, method_map)
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
                warn!(
                    "body_validator: invalid regex pattern '{}' in schema: {}",
                    pattern, e
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
        // Basic email check: contains exactly one @ with non-empty local and domain parts
        "email"
            if !s.contains('@')
                || s.starts_with('@')
                || s.ends_with('@')
                || s.matches('@').count() != 1 =>
        {
            return Err(format!("'{}' is not a valid email format", s));
        }
        "ipv4" if s.parse::<std::net::Ipv4Addr>().is_err() => {
            return Err(format!("'{}' is not a valid IPv4 address", s));
        }
        "ipv6" if s.parse::<std::net::Ipv6Addr>().is_err() => {
            return Err(format!("'{}' is not a valid IPv6 address", s));
        }
        "uri" | "uri-reference"
            if !s.contains(':') && !s.starts_with('/') && !s.starts_with('#') =>
        {
            return Err(format!("'{}' is not a valid URI", s));
        }
        "date-time" if chrono::DateTime::parse_from_rfc3339(s).is_err() => {
            return Err(format!("'{}' is not a valid RFC 3339 date-time", s));
        }
        "date" if chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").is_err() => {
            return Err(format!("'{}' is not a valid date (YYYY-MM-DD)", s));
        }
        "uuid" if uuid::Uuid::parse_str(s).is_err() => {
            return Err(format!("'{}' is not a valid UUID", s));
        }
        _ => {
            // Other format names, valid values, or unknown formats — no-op.
            // Per JSON Schema spec, unknown formats are advisory.
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

/// Helper to build a rejection `PluginResult` for protobuf validation failures.
fn protobuf_reject(status_code: u16, direction: &str, msg: &str) -> PluginResult {
    debug!(
        "body_validator: {} protobuf validation failed: {}",
        direction, msg
    );
    let escaped_msg = msg.replace('\\', "\\\\").replace('"', "\\\"");
    PluginResult::Reject {
        status_code,
        body: format!(
            r#"{{"error":"{} body validation failed","details":"{}"}}"#,
            if status_code == 400 {
                "Request"
            } else {
                "Response"
            },
            escaped_msg
        ),
        headers: HashMap::new(),
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

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_GRPC_PROTOCOLS
    }

    fn requires_request_body_before_before_proxy(&self) -> bool {
        // JSON/XML validation reads request_body from metadata in before_proxy.
        // Protobuf validation uses on_final_request_body, but still needs body collected.
        self.has_request_validation
    }

    fn requires_request_body_buffering(&self) -> bool {
        self.has_request_validation
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        if !self.has_request_validation
            || matches!(ctx.method.as_str(), "GET" | "HEAD" | "OPTIONS" | "DELETE")
        {
            return false;
        }

        let content_type = ctx
            .headers
            .get("content-type")
            .map(|value| value.to_lowercase())
            .unwrap_or_default();

        // For gRPC protobuf validation, buffer if content-type is application/grpc
        if self.has_protobuf_request_validation && content_type.starts_with("application/grpc") {
            return true;
        }

        self.content_types.is_empty()
            || self
                .content_types
                .iter()
                .any(|ct| content_type.contains(ct.as_str()))
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Only validate methods that typically have a body
        if matches!(ctx.method.as_str(), "GET" | "HEAD" | "OPTIONS" | "DELETE") {
            return PluginResult::Continue;
        }

        // Check content type
        let content_type = headers
            .get("content-type")
            .cloned()
            .unwrap_or_default()
            .to_lowercase();

        // gRPC protobuf validation is handled in on_final_request_body, not here
        if content_type.starts_with("application/grpc") {
            return PluginResult::Continue;
        }

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
            self.validate_json_body(
                &body,
                &self.required_fields,
                self.json_schema.as_ref(),
                &self.compiled_patterns,
            )
        } else if content_type.contains("xml") && self.validate_xml {
            Self::validate_xml_body(&body, &self.required_xml_elements)
        } else {
            Ok(())
        };

        match result {
            Ok(()) => PluginResult::Continue,
            Err(msg) => {
                debug!("body_validator: request validation failed: {}", msg);
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

    async fn on_final_request_body(
        &self,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        if !self.has_protobuf_request_validation {
            return PluginResult::Continue;
        }

        let content_type = headers
            .get("content-type")
            .map(|v| v.to_lowercase())
            .unwrap_or_default();
        if !content_type.starts_with("application/grpc") {
            return PluginResult::Continue;
        }

        if body.is_empty() {
            return PluginResult::Continue;
        }

        // Resolve gRPC method path from headers (injected by the proxy handler)
        let grpc_path = headers.get(":path").map(|s| s.as_str()).unwrap_or("");
        let descriptor = match self.get_request_descriptor(grpc_path) {
            Some(d) => d,
            None => {
                // No descriptor for this method — skip validation
                debug!(
                    "body_validator: no protobuf request descriptor for method '{}'",
                    grpc_path
                );
                return PluginResult::Continue;
            }
        };

        match self.validate_protobuf_body(body, descriptor) {
            Ok(()) => PluginResult::Continue,
            Err(msg) => protobuf_reject(400, "request", &msg),
        }
    }

    fn requires_response_body_buffering(&self) -> bool {
        self.has_response_validation
    }

    async fn on_final_response_body(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        if !self.has_response_validation {
            return PluginResult::Continue;
        }

        // Determine content type from response headers
        let content_type = response_headers
            .get("content-type")
            .cloned()
            .unwrap_or_default()
            .to_lowercase();

        // gRPC protobuf response validation
        if content_type.starts_with("application/grpc") {
            if !self.has_protobuf_response_validation || body.is_empty() {
                return PluginResult::Continue;
            }
            // For response, use the request path stored in ctx metadata
            // The response headers may contain :path from the original request
            let grpc_path = response_headers
                .get(":path")
                .map(|s| s.as_str())
                .unwrap_or("");
            let descriptor = match self.get_response_descriptor(grpc_path) {
                Some(d) => d,
                None => return PluginResult::Continue,
            };
            // 502 Bad Gateway: the backend returned a response whose protobuf
            // payload does not match the expected schema — i.e., the upstream
            // produced an invalid response, which is the definition of 502.
            return match self.validate_protobuf_body(body, descriptor) {
                Ok(()) => PluginResult::Continue,
                Err(msg) => protobuf_reject(502, "response", &msg),
            };
        }

        let should_validate = self.response_content_types.is_empty()
            || self
                .response_content_types
                .iter()
                .any(|ct| content_type.contains(ct.as_str()));

        if !should_validate {
            return PluginResult::Continue;
        }

        if body.is_empty() {
            return PluginResult::Continue;
        }

        // Convert body bytes to string for validation
        let body_str = match std::str::from_utf8(body) {
            Ok(s) => s,
            Err(_) => {
                debug!("body_validator: response body is not valid UTF-8, skipping validation");
                return PluginResult::Continue;
            }
        };

        // Determine validation type
        let result = if content_type.contains("json") {
            self.validate_json_body(
                body_str,
                &self.response_required_fields,
                self.response_json_schema.as_ref(),
                &self.response_compiled_patterns,
            )
        } else if content_type.contains("xml") && self.response_validate_xml {
            Self::validate_xml_body(body_str, &self.response_required_xml_elements)
        } else {
            Ok(())
        };

        match result {
            Ok(()) => PluginResult::Continue,
            Err(msg) => {
                debug!("body_validator: response validation failed: {}", msg);
                let escaped_msg = msg.replace('\\', "\\\\").replace('"', "\\\"");
                PluginResult::Reject {
                    status_code: 502,
                    body: format!(
                        r#"{{"error":"Response body validation failed","details":"{}"}}"#,
                        escaped_msg
                    ),
                    headers: HashMap::new(),
                }
            }
        }
    }
}

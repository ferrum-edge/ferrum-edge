//! OpenAPI contract validation plugin.
//!
//! Validates JSON request and response bodies against operation schemas
//! extracted from an attached OpenAPI document. All regexes and JSON Schema
//! validators are compiled at plugin construction time; request-time work is
//! limited to operation matching, optional decompression, JSON parsing, and
//! schema validation.

use ahash::AHashMap;
use async_trait::async_trait;
use flate2::read::GzDecoder;
use regex::{Regex, RegexSet};
use serde_json::Value;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use super::{HTTP_ONLY_PROTOCOLS, Plugin, PluginResult, RequestContext};

const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
const DEFAULT_ERROR_TRUNCATE_CHARS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnforcementMode {
    Block,
    LogOnly,
    Disabled,
}

impl EnforcementMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::LogOnly => "log_only",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SchemaDraft {
    Auto,
    Draft7,
    Draft202012,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValidationSide {
    Request,
    Response,
}

struct OperationEntry {
    operation_label: String,
    path_regex: Regex,
    literal_segments: u16,
    request_validators: AHashMap<String, jsonschema::Validator>,
    request_required: bool,
    response_validators: AHashMap<u16, AHashMap<String, jsonschema::Validator>>,
}

impl OperationEntry {
    fn has_request_schema(&self) -> bool {
        !self.request_validators.is_empty()
    }

    fn has_response_schema(&self) -> bool {
        self.response_validators
            .values()
            .any(|validators| !validators.is_empty())
    }

    fn response_validator(
        &self,
        status: u16,
        content_type: Option<&str>,
    ) -> Option<&jsonschema::Validator> {
        self.response_validators
            .get(&status)
            .or_else(|| self.response_validators.get(&0))
            .and_then(|validators| validator_for_content_type(validators, content_type))
    }
}

pub struct OpenapiValidator {
    mode: EnforcementMode,
    validate_request: bool,
    validate_response: bool,
    fail_on_unknown_operation: bool,
    fail_on_missing_response_schema: bool,
    max_body_bytes: usize,
    request_content_types: Vec<String>,
    response_content_types: Vec<String>,
    ops_by_method: AHashMap<String, Vec<OperationEntry>>,
    has_any_request_schema: bool,
    has_any_response_schema: bool,
    bypass_paths: Option<RegexSet>,
    bypass_methods: HashSet<String>,
    bypass_consumers: HashSet<String>,
    bypass_header_present: HashMap<String, Option<String>>,
    request_error_status: u16,
    response_error_status: u16,
    error_content_type: String,
    error_truncate_chars: usize,
}

impl OpenapiValidator {
    pub fn new(config: &Value) -> Result<Self, String> {
        let object = config
            .as_object()
            .ok_or_else(|| "openapi_validator: config must be an object".to_string())?;

        let mode = parse_mode(optional_string(object, "enforcement_mode")?.unwrap_or("block"))?;
        let validate_request = optional_bool(object, "validate_request")?.unwrap_or(true);
        let validate_response = optional_bool(object, "validate_response")?.unwrap_or(true);
        let fail_on_unknown_operation =
            optional_bool(object, "fail_on_unknown_operation")?.unwrap_or(true);
        let fail_on_missing_response_schema =
            optional_bool(object, "fail_on_missing_response_schema")?.unwrap_or(false);
        let max_body_bytes =
            optional_usize(object, "max_body_bytes")?.unwrap_or(DEFAULT_MAX_BODY_BYTES);
        if max_body_bytes == 0 {
            return Err(
                "openapi_validator: 'max_body_bytes' must be greater than zero".to_string(),
            );
        }
        let request_content_types = optional_string_vec(object, "request_content_types")?
            .unwrap_or_else(|| vec!["application/json".to_string()])
            .into_iter()
            .map(|value| normalize_media_type(&value))
            .collect();
        let response_content_types = optional_string_vec(object, "response_content_types")?
            .unwrap_or_else(|| vec!["application/json".to_string()])
            .into_iter()
            .map(|value| normalize_media_type(&value))
            .collect();
        let schema_draft = match optional_string(object, "schema_draft")? {
            Some(value) => parse_schema_draft(value)?,
            None => {
                parse_schema_draft(optional_string(object, "json_schema_draft")?.unwrap_or("auto"))?
            }
        };

        let operations_value = object
            .get("operations")
            .ok_or_else(|| "openapi_validator: 'operations' is required".to_string())?;
        let operations = operations_value
            .as_array()
            .ok_or_else(|| "openapi_validator: 'operations' must be an array".to_string())?;
        if operations.is_empty() {
            return Err("openapi_validator: 'operations' must not be empty".to_string());
        }

        let mut ops_by_method: AHashMap<String, Vec<OperationEntry>> = AHashMap::new();
        let mut has_any_request_schema = false;
        let mut has_any_response_schema = false;
        for (index, operation) in operations.iter().enumerate() {
            let entry = parse_operation(operation, index, schema_draft)?;
            has_any_request_schema |= entry.has_request_schema();
            has_any_response_schema |= entry.has_response_schema();
            let method = operation
                .get("method")
                .and_then(Value::as_str)
                .map(str::to_ascii_uppercase)
                .unwrap_or_default();
            ops_by_method.entry(method).or_default().push(entry);
        }
        for bucket in ops_by_method.values_mut() {
            bucket.sort_by(|left, right| {
                right
                    .literal_segments
                    .cmp(&left.literal_segments)
                    .then_with(|| right.operation_label.len().cmp(&left.operation_label.len()))
            });
        }
        if !has_any_request_schema && !has_any_response_schema && !fail_on_unknown_operation {
            return Err(
                "openapi_validator: no validation rules configured -- provide request or response schemas"
                    .to_string(),
            );
        }

        let bypass = object.get("bypass").and_then(Value::as_object);
        let bypass_paths = parse_regex_set(bypass.and_then(|b| b.get("paths")), "bypass.paths")?;
        let bypass_methods = optional_string_vec_from_object(bypass, "methods")?
            .unwrap_or_default()
            .into_iter()
            .map(|method| method.to_ascii_uppercase())
            .collect();
        let bypass_consumers = optional_string_vec_from_object(bypass, "consumers")?
            .unwrap_or_default()
            .into_iter()
            .collect();
        let bypass_header_present =
            parse_header_present(bypass.and_then(|b| b.get("header_present")))?;

        let error_response = object.get("error_response").and_then(Value::as_object);
        let request_error_status =
            optional_u16_from_object(error_response, "request_status_code")?.unwrap_or(400);
        let response_error_status =
            optional_u16_from_object(error_response, "response_status_code")?.unwrap_or(502);
        validate_status(request_error_status, "error_response.request_status_code")?;
        validate_status(response_error_status, "error_response.response_status_code")?;
        let error_content_type = optional_string_from_object(error_response, "content_type")?
            .unwrap_or_else(|| "application/problem+json".to_string());
        let error_truncate_chars =
            optional_usize(object, "error_truncate_chars")?.unwrap_or(DEFAULT_ERROR_TRUNCATE_CHARS);

        Ok(Self {
            mode,
            validate_request,
            validate_response,
            fail_on_unknown_operation,
            fail_on_missing_response_schema,
            max_body_bytes,
            request_content_types,
            response_content_types,
            ops_by_method,
            has_any_request_schema,
            has_any_response_schema,
            bypass_paths,
            bypass_methods,
            bypass_consumers,
            bypass_header_present,
            request_error_status,
            response_error_status,
            error_content_type,
            error_truncate_chars,
        })
    }

    fn active(&self) -> bool {
        self.mode != EnforcementMode::Disabled
    }

    fn match_operation(&self, method: &str, path: &str) -> Option<&OperationEntry> {
        if let Some(bucket) = self.ops_by_method.get(method) {
            return bucket.iter().find(|op| op.path_regex.is_match(path));
        }
        let upper = method.to_ascii_uppercase();
        self.ops_by_method
            .get(upper.as_str())
            .and_then(|bucket| bucket.iter().find(|op| op.path_regex.is_match(path)))
    }

    fn bypass_reason(&self, ctx: &RequestContext) -> Option<&'static str> {
        if self
            .bypass_paths
            .as_ref()
            .is_some_and(|paths| paths.is_match(&ctx.path))
        {
            return Some("bypass_path");
        }
        if self
            .bypass_methods
            .contains(&ctx.method.to_ascii_uppercase())
        {
            return Some("bypass_method");
        }
        if let Some(identity) = ctx.effective_identity()
            && self.bypass_consumers.contains(identity)
        {
            return Some("bypass_consumer");
        }
        if self.bypass_header_present.iter().any(|(name, expected)| {
            header_value(&ctx.headers, name).is_some_and(|actual| {
                expected
                    .as_deref()
                    .is_none_or(|expected| actual == expected)
            })
        }) {
            return Some("bypass_header");
        }
        None
    }

    fn mark_mode(&self, ctx: &mut RequestContext) {
        ctx.metadata.insert(
            "openapi_validator.mode".to_string(),
            self.mode.as_str().to_string(),
        );
    }

    fn mark_skip(&self, ctx: &mut RequestContext, reason: &'static str) {
        self.mark_mode(ctx);
        ctx.metadata.insert(
            "openapi_validator.skip_reason".to_string(),
            reason.to_string(),
        );
    }

    fn mark_operation(&self, ctx: &mut RequestContext, operation: &OperationEntry) {
        self.mark_mode(ctx);
        ctx.metadata.insert(
            "openapi_validator.matched_operation".to_string(),
            operation.operation_label.clone(),
        );
    }

    fn handle_violation(
        &self,
        ctx: &mut RequestContext,
        side: ValidationSide,
        operation_label: Option<&str>,
        detail: String,
    ) -> PluginResult {
        self.mark_mode(ctx);
        if let Some(label) = operation_label {
            ctx.metadata.insert(
                "openapi_validator.matched_operation".to_string(),
                label.to_string(),
            );
        }

        let detail = truncate_chars(&detail, self.error_truncate_chars);
        let error_key = match side {
            ValidationSide::Request => "openapi_validator.request_error",
            ValidationSide::Response => "openapi_validator.response_error",
        };
        ctx.metadata.insert(error_key.to_string(), detail.clone());

        match self.mode {
            EnforcementMode::Block => {
                let (status_code, action, title) = match side {
                    ValidationSide::Request => (
                        self.request_error_status,
                        "rejected_request",
                        "Request body validation failed",
                    ),
                    ValidationSide::Response => (
                        self.response_error_status,
                        "rejected_response",
                        "Response body validation failed",
                    ),
                };
                ctx.metadata
                    .insert("openapi_validator.action".to_string(), action.to_string());
                PluginResult::Reject {
                    status_code,
                    body: serde_json::json!({
                        "type": "about:blank",
                        "title": title,
                        "status": status_code,
                        "detail": detail,
                        "operation": operation_label,
                    })
                    .to_string(),
                    headers: HashMap::from([(
                        "content-type".to_string(),
                        self.error_content_type.clone(),
                    )]),
                }
            }
            EnforcementMode::LogOnly => {
                let action = match side {
                    ValidationSide::Request => "logged_request_mismatch",
                    ValidationSide::Response => "logged_response_mismatch",
                };
                ctx.metadata
                    .insert("openapi_validator.action".to_string(), action.to_string());
                PluginResult::Continue
            }
            EnforcementMode::Disabled => PluginResult::Continue,
        }
    }

    fn request_validator<'a>(
        &'a self,
        operation: &'a OperationEntry,
        content_type: Option<&str>,
    ) -> Option<&'a jsonschema::Validator> {
        if !content_type_in_scope(&self.request_content_types, content_type) {
            return None;
        }
        validator_for_content_type(&operation.request_validators, content_type)
    }
}

#[async_trait]
impl Plugin for OpenapiValidator {
    fn name(&self) -> &str {
        "openapi_validator"
    }

    fn priority(&self) -> u16 {
        super::priority::OPENAPI_VALIDATOR
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        HTTP_ONLY_PROTOCOLS
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        _headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !self.active() {
            self.mark_mode(ctx);
            return PluginResult::Continue;
        }
        if let Some(reason) = self.bypass_reason(ctx) {
            self.mark_skip(ctx, reason);
            return PluginResult::Continue;
        }
        match self.match_operation(&ctx.method, &ctx.path) {
            Some(operation) => {
                self.mark_operation(ctx, operation);
                PluginResult::Continue
            }
            None if self.fail_on_unknown_operation => self.handle_violation(
                ctx,
                ValidationSide::Request,
                None,
                format!(
                    "No OpenAPI operation matched {} {}",
                    ctx.method.as_str(),
                    ctx.path.as_str()
                ),
            ),
            None => {
                self.mark_skip(ctx, "no_match");
                PluginResult::Continue
            }
        }
    }

    fn requires_request_body_buffering(&self) -> bool {
        self.active() && self.validate_request && self.has_any_request_schema
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        if !self.requires_request_body_buffering()
            || matches!(ctx.method.as_str(), "GET" | "HEAD" | "OPTIONS" | "DELETE")
            || self.bypass_reason(ctx).is_some()
        {
            return false;
        }
        let Some(operation) = self.match_operation(&ctx.method, &ctx.path) else {
            return false;
        };
        if !operation.has_request_schema() {
            return false;
        }
        let content_type = header_value(&ctx.headers, "content-type");
        self.request_validator(operation, content_type).is_some()
    }

    fn needs_final_request_body_context(&self) -> bool {
        true
    }

    async fn on_final_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        if !self.requires_request_body_buffering() {
            return PluginResult::Continue;
        }
        if let Some(reason) = self.bypass_reason(ctx) {
            self.mark_skip(ctx, reason);
            return PluginResult::Continue;
        }
        let Some(operation) = self.match_operation(&ctx.method, &ctx.path) else {
            if self.fail_on_unknown_operation {
                return self.handle_violation(
                    ctx,
                    ValidationSide::Request,
                    None,
                    format!(
                        "No OpenAPI operation matched {} {}",
                        ctx.method.as_str(),
                        ctx.path.as_str()
                    ),
                );
            }
            self.mark_skip(ctx, "no_match");
            return PluginResult::Continue;
        };
        self.mark_operation(ctx, operation);
        if body.is_empty() {
            return if operation.request_required {
                self.handle_violation(
                    ctx,
                    ValidationSide::Request,
                    Some(&operation.operation_label),
                    "Required request body is missing".to_string(),
                )
            } else {
                PluginResult::Continue
            };
        }
        let content_type = header_value(headers, "content-type");
        let Some(validator) = self.request_validator(operation, content_type) else {
            self.mark_skip(ctx, "content_type");
            return PluginResult::Continue;
        };
        let decoded = match decode_body(headers, body, self.max_body_bytes) {
            Ok(body) => body,
            Err(error) => {
                return self.handle_violation(
                    ctx,
                    ValidationSide::Request,
                    Some(&operation.operation_label),
                    error,
                );
            }
        };
        let json: Value = match serde_json::from_slice(decoded.as_ref()) {
            Ok(value) => value,
            Err(error) => {
                return self.handle_violation(
                    ctx,
                    ValidationSide::Request,
                    Some(&operation.operation_label),
                    format!("Invalid JSON body: {error}"),
                );
            }
        };
        match validator.validate(&json) {
            Ok(()) => PluginResult::Continue,
            Err(error) => self.handle_violation(
                ctx,
                ValidationSide::Request,
                Some(&operation.operation_label),
                format_schema_error(&error),
            ),
        }
    }

    fn requires_response_body_buffering(&self) -> bool {
        self.active() && self.validate_response && self.has_any_response_schema
    }

    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        self.requires_response_body_buffering()
            && !super::utils::sse::is_sse_request(ctx)
            && self.bypass_reason(ctx).is_none()
            && self
                .match_operation(&ctx.method, &ctx.path)
                .is_some_and(OperationEntry::has_response_schema)
    }

    async fn on_final_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        if !self.requires_response_body_buffering() {
            return PluginResult::Continue;
        }
        if super::utils::sse::is_sse_request(ctx) {
            self.mark_skip(ctx, "content_type");
            return PluginResult::Continue;
        }
        if let Some(reason) = self.bypass_reason(ctx) {
            self.mark_skip(ctx, reason);
            return PluginResult::Continue;
        }
        let Some(operation) = self.match_operation(&ctx.method, &ctx.path) else {
            if self.fail_on_unknown_operation {
                return self.handle_violation(
                    ctx,
                    ValidationSide::Response,
                    None,
                    format!(
                        "No OpenAPI operation matched {} {}",
                        ctx.method.as_str(),
                        ctx.path.as_str()
                    ),
                );
            }
            self.mark_skip(ctx, "no_match");
            return PluginResult::Continue;
        };
        self.mark_operation(ctx, operation);
        if body.is_empty() {
            return PluginResult::Continue;
        }
        let content_type = header_value(response_headers, "content-type");
        if !content_type_in_scope(&self.response_content_types, content_type) {
            self.mark_skip(ctx, "content_type");
            return PluginResult::Continue;
        }
        let Some(validator) = operation.response_validator(response_status, content_type) else {
            if self.fail_on_missing_response_schema {
                return self.handle_violation(
                    ctx,
                    ValidationSide::Response,
                    Some(&operation.operation_label),
                    format!(
                        "No response schema matched status {} and content type {}",
                        response_status,
                        content_type.unwrap_or("<missing>")
                    ),
                );
            }
            self.mark_skip(ctx, "no_schema");
            return PluginResult::Continue;
        };
        let decoded = match decode_body(response_headers, body, self.max_body_bytes) {
            Ok(body) => body,
            Err(error) => {
                return self.handle_violation(
                    ctx,
                    ValidationSide::Response,
                    Some(&operation.operation_label),
                    error,
                );
            }
        };
        let json: Value = match serde_json::from_slice(decoded.as_ref()) {
            Ok(value) => value,
            Err(error) => {
                return self.handle_violation(
                    ctx,
                    ValidationSide::Response,
                    Some(&operation.operation_label),
                    format!("Invalid JSON body: {error}"),
                );
            }
        };
        match validator.validate(&json) {
            Ok(()) => PluginResult::Continue,
            Err(error) => self.handle_violation(
                ctx,
                ValidationSide::Response,
                Some(&operation.operation_label),
                format_schema_error(&error),
            ),
        }
    }
}

fn parse_operation(
    value: &Value,
    index: usize,
    schema_draft: SchemaDraft,
) -> Result<OperationEntry, String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("openapi_validator: operations[{index}] must be an object"))?;
    let method = optional_string(object, "method")?
        .ok_or_else(|| format!("openapi_validator: operations[{index}].method is required"))?
        .to_ascii_uppercase();
    if method.is_empty() {
        return Err(format!(
            "openapi_validator: operations[{index}].method must not be empty"
        ));
    }
    let path_template = optional_string(object, "path_template")?
        .ok_or_else(|| format!("openapi_validator: operations[{index}].path_template is required"))?
        .to_string();
    let path_regex_raw = optional_string(object, "path_regex")?
        .ok_or_else(|| format!("openapi_validator: operations[{index}].path_regex is required"))?;
    let path_regex = Regex::new(path_regex_raw).map_err(|error| {
        format!("openapi_validator: operations[{index}].path_regex is invalid: {error}")
    })?;
    let operation_label = optional_string(object, "operation_label")?
        .map(str::to_string)
        .unwrap_or_else(|| format!("{method} {path_template}"));
    let request_required = optional_bool_from_object(Some(object), "request_required")?
        .or_else(|| {
            optional_bool_from_object(Some(object), "request_body_required")
                .ok()
                .flatten()
        })
        .unwrap_or(false);
    let request_validators =
        parse_request_validators(object.get("request_body"), index, schema_draft)?;
    let response_validators =
        parse_response_validators(object.get("responses"), index, schema_draft)?;

    Ok(OperationEntry {
        operation_label,
        path_regex,
        literal_segments: literal_segment_count(&path_template),
        request_validators,
        request_required,
        response_validators,
    })
}

fn parse_request_validators(
    value: Option<&Value>,
    operation_index: usize,
    schema_draft: SchemaDraft,
) -> Result<AHashMap<String, jsonschema::Validator>, String> {
    let Some(value) = value else {
        return Ok(AHashMap::new());
    };
    if value.is_null() {
        return Ok(AHashMap::new());
    }
    let object = value.as_object().ok_or_else(|| {
        format!("openapi_validator: operations[{operation_index}].request_body must be an object")
    })?;
    let mut validators = AHashMap::new();
    if let (Some(content_type), Some(schema)) = (
        object.get("content_type").and_then(Value::as_str),
        object.get("schema"),
    ) {
        validators.insert(
            normalize_media_type(content_type),
            compile_schema(schema, schema_draft).map_err(|error| {
                format!(
                    "openapi_validator: operations[{operation_index}].request_body schema for {content_type} is invalid: {error}"
                )
            })?,
        );
        return Ok(validators);
    }
    let content = object
        .get("content")
        .and_then(Value::as_object)
        .unwrap_or(object);
    for (content_type, schema) in content {
        if matches!(content_type.as_str(), "content_type" | "schema") {
            continue;
        }
        validators.insert(
            normalize_media_type(content_type),
            compile_schema(schema, schema_draft).map_err(|error| {
                format!(
                    "openapi_validator: operations[{operation_index}].request_body schema for {content_type} is invalid: {error}"
                )
            })?,
        );
    }
    Ok(validators)
}

fn parse_response_validators(
    value: Option<&Value>,
    operation_index: usize,
    schema_draft: SchemaDraft,
) -> Result<AHashMap<u16, AHashMap<String, jsonschema::Validator>>, String> {
    let Some(value) = value else {
        return Ok(AHashMap::new());
    };
    if value.is_null() {
        return Ok(AHashMap::new());
    }
    let object = value.as_object().ok_or_else(|| {
        format!("openapi_validator: operations[{operation_index}].responses must be an object")
    })?;
    let mut statuses = AHashMap::new();
    for (status_raw, response_value) in object {
        let status = if status_raw.eq_ignore_ascii_case("default") {
            0
        } else {
            status_raw.parse::<u16>().map_err(|_| {
                format!(
                    "openapi_validator: operations[{operation_index}].responses contains invalid status '{status_raw}'"
                )
            })?
        };
        let response_object = response_value.as_object().ok_or_else(|| {
            format!(
                "openapi_validator: operations[{operation_index}].responses['{status_raw}'] must be an object"
            )
        })?;
        let content = response_object
            .get("content")
            .and_then(Value::as_object)
            .unwrap_or(response_object);
        let mut validators = AHashMap::new();
        for (content_type, schema) in content {
            if content_type == "description" {
                continue;
            }
            validators.insert(
                normalize_media_type(content_type),
                compile_schema(schema, schema_draft).map_err(|error| {
                    format!(
                        "openapi_validator: operations[{operation_index}].responses['{status_raw}'] schema for {content_type} is invalid: {error}"
                    )
                })?,
            );
        }
        statuses.insert(status, validators);
    }
    Ok(statuses)
}

fn compile_schema(
    schema: &Value,
    schema_draft: SchemaDraft,
) -> Result<jsonschema::Validator, jsonschema::ValidationError<'static>> {
    match schema_draft {
        SchemaDraft::Auto => jsonschema::validator_for(schema),
        SchemaDraft::Draft7 => jsonschema::draft7::options().build(schema),
        SchemaDraft::Draft202012 => jsonschema::draft202012::options().build(schema),
    }
}

fn decode_body<'a>(
    headers: &HashMap<String, String>,
    body: &'a [u8],
    max_body_bytes: usize,
) -> Result<Cow<'a, [u8]>, String> {
    if body.len() > max_body_bytes {
        return Err(format!(
            "Body exceeds max_body_bytes of {max_body_bytes} bytes"
        ));
    }
    let Some(encoding) = header_value(headers, "content-encoding") else {
        return Ok(Cow::Borrowed(body));
    };
    let encoding = encoding
        .split(',')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    match encoding.as_str() {
        "" | "identity" => Ok(Cow::Borrowed(body)),
        "gzip" => read_bounded(GzDecoder::new(body), max_body_bytes)
            .map(Cow::Owned)
            .map_err(|error| format!("Failed to decompress gzip body: {error}")),
        "br" => read_bounded(brotli::Decompressor::new(body, 4096), max_body_bytes)
            .map(Cow::Owned)
            .map_err(|error| format!("Failed to decompress brotli body: {error}")),
        other => Err(format!("Unsupported content-encoding '{other}'")),
    }
}

fn read_bounded<R: std::io::Read>(
    mut reader: R,
    max_body_bytes: usize,
) -> Result<Vec<u8>, std::io::Error> {
    let mut decoded = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if decoded.len().saturating_add(n) > max_body_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("decompressed body exceeds max_body_bytes of {max_body_bytes} bytes"),
            ));
        }
        decoded.extend_from_slice(&buf[..n]);
    }
    Ok(decoded)
}

fn validator_for_content_type<'a>(
    validators: &'a AHashMap<String, jsonschema::Validator>,
    content_type: Option<&str>,
) -> Option<&'a jsonschema::Validator> {
    let base = content_type_base(content_type)?;
    validators
        .iter()
        .find(|(expected, _)| expected.eq_ignore_ascii_case(base))
        .map(|(_, validator)| validator)
}

fn content_type_in_scope(configured: &[String], content_type: Option<&str>) -> bool {
    let Some(base) = content_type_base(content_type) else {
        return false;
    };
    configured.is_empty()
        || configured
            .iter()
            .any(|expected| expected.eq_ignore_ascii_case(base))
}

fn content_type_base(content_type: Option<&str>) -> Option<&str> {
    let base = content_type?.split(';').next().unwrap_or("").trim();
    (!base.is_empty()).then_some(base)
}

fn normalize_media_type(value: &str) -> String {
    value
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

fn header_value<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers.get(name).map(String::as_str).or_else(|| {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    })
}

fn format_schema_error(error: &jsonschema::ValidationError<'_>) -> String {
    let path = error.instance_path().to_string();
    if path.is_empty() {
        error.to_string()
    } else {
        format!("{path}: {error}")
    }
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    value.chars().take(max_chars).collect()
}

fn literal_segment_count(path_template: &str) -> u16 {
    path_template
        .split('/')
        .filter(|segment| !segment.is_empty())
        .filter(|segment| !(segment.starts_with('{') && segment.ends_with('}')))
        .count()
        .min(u16::MAX as usize) as u16
}

fn parse_mode(raw: &str) -> Result<EnforcementMode, String> {
    match raw {
        "block" => Ok(EnforcementMode::Block),
        "log_only" => Ok(EnforcementMode::LogOnly),
        "disabled" => Ok(EnforcementMode::Disabled),
        other => Err(format!(
            "openapi_validator: 'enforcement_mode' must be one of block, log_only, disabled; got {other:?}"
        )),
    }
}

fn parse_schema_draft(raw: &str) -> Result<SchemaDraft, String> {
    match raw {
        "auto" => Ok(SchemaDraft::Auto),
        "draft7" | "draft-7" => Ok(SchemaDraft::Draft7),
        "draft202012" | "draft2020-12" | "2020-12" => Ok(SchemaDraft::Draft202012),
        other => Err(format!(
            "openapi_validator: 'schema_draft' must be auto, draft7, or draft2020-12; got {other:?}"
        )),
    }
}

fn parse_regex_set(value: Option<&Value>, field: &'static str) -> Result<Option<RegexSet>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let values = value
        .as_array()
        .ok_or_else(|| format!("openapi_validator: '{field}' must be an array"))?;
    if values.is_empty() {
        return Ok(None);
    }
    let mut patterns = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let Some(pattern) = value.as_str() else {
            return Err(format!(
                "openapi_validator: '{field}' entries must be strings (invalid entry at index {index})"
            ));
        };
        if pattern.is_empty() {
            return Err(format!(
                "openapi_validator: '{field}' entries must not be empty (invalid entry at index {index})"
            ));
        }
        patterns.push(pattern.to_string());
    }
    RegexSet::new(patterns)
        .map(Some)
        .map_err(|error| format!("openapi_validator: failed to compile '{field}': {error}"))
}

fn parse_header_present(value: Option<&Value>) -> Result<HashMap<String, Option<String>>, String> {
    match value {
        None | Some(Value::Null) => Ok(HashMap::new()),
        Some(Value::Object(map)) => {
            let mut parsed = HashMap::new();
            for (key, value) in map {
                if key.is_empty() {
                    return Err(
                        "openapi_validator: bypass.header_present keys must not be empty"
                            .to_string(),
                    );
                }
                let expected = if value.is_null() {
                    None
                } else {
                    Some(value.as_str().ok_or_else(|| {
                        "openapi_validator: bypass.header_present values must be strings or null"
                            .to_string()
                    })?)
                };
                parsed.insert(key.to_ascii_lowercase(), expected.map(str::to_string));
            }
            Ok(parsed)
        }
        Some(_) => Err("openapi_validator: bypass.header_present must be an object".to_string()),
    }
}

fn optional_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &'static str,
) -> Result<Option<&'a str>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value)),
        Some(Value::String(_)) => Err(format!("openapi_validator: '{key}' must not be empty")),
        Some(_) => Err(format!("openapi_validator: '{key}' must be a string")),
    }
}

fn optional_bool(
    object: &serde_json::Map<String, Value>,
    key: &'static str,
) -> Result<Option<bool>, String> {
    optional_bool_from_object(Some(object), key)
}

fn optional_bool_from_object(
    object: Option<&serde_json::Map<String, Value>>,
    key: &'static str,
) -> Result<Option<bool>, String> {
    let Some(object) = object else {
        return Ok(None);
    };
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(format!("openapi_validator: '{key}' must be a boolean")),
    }
}

fn optional_usize(
    object: &serde_json::Map<String, Value>,
    key: &'static str,
) -> Result<Option<usize>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => value
            .as_u64()
            .ok_or_else(|| format!("openapi_validator: '{key}' must be an unsigned integer"))
            .and_then(|value| {
                usize::try_from(value)
                    .map_err(|_| format!("openapi_validator: '{key}' is too large"))
            })
            .map(Some),
        Some(_) => Err(format!(
            "openapi_validator: '{key}' must be an unsigned integer"
        )),
    }
}

fn optional_u16_from_object(
    object: Option<&serde_json::Map<String, Value>>,
    key: &'static str,
) -> Result<Option<u16>, String> {
    let Some(object) = object else {
        return Ok(None);
    };
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => value
            .as_u64()
            .ok_or_else(|| format!("openapi_validator: '{key}' must be an unsigned integer"))
            .and_then(|value| {
                u16::try_from(value).map_err(|_| format!("openapi_validator: '{key}' is too large"))
            })
            .map(Some),
        Some(_) => Err(format!(
            "openapi_validator: '{key}' must be an unsigned integer"
        )),
    }
}

fn optional_string_from_object(
    object: Option<&serde_json::Map<String, Value>>,
    key: &'static str,
) -> Result<Option<String>, String> {
    let Some(object) = object else {
        return Ok(None);
    };
    optional_string(object, key).map(|value| value.map(str::to_string))
}

fn optional_string_vec(
    object: &serde_json::Map<String, Value>,
    key: &'static str,
) -> Result<Option<Vec<String>>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(values)) => parse_string_array(values, key),
        Some(_) => Err(format!("openapi_validator: '{key}' must be an array")),
    }
}

fn optional_string_vec_from_object(
    object: Option<&serde_json::Map<String, Value>>,
    key: &'static str,
) -> Result<Option<Vec<String>>, String> {
    let Some(object) = object else {
        return Ok(None);
    };
    optional_string_vec(object, key)
}

fn parse_string_array(values: &[Value], key: &'static str) -> Result<Option<Vec<String>>, String> {
    let mut out = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let Some(value) = value.as_str() else {
            return Err(format!(
                "openapi_validator: '{key}' entries must be strings (invalid entry at index {index})"
            ));
        };
        if value.is_empty() {
            return Err(format!(
                "openapi_validator: '{key}' entries must not be empty (invalid entry at index {index})"
            ));
        }
        out.push(value.to_string());
    }
    Ok(Some(out))
}

fn validate_status(status: u16, field: &'static str) -> Result<(), String> {
    if (400..=599).contains(&status) {
        Ok(())
    } else {
        Err(format!(
            "openapi_validator: '{field}' must be from 400 to 599"
        ))
    }
}

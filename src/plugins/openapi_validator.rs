//! OpenAPI contract validation plugin.
//!
//! Validates request and response bodies against operation schemas extracted
//! from an attached OpenAPI document. All regexes and JSON Schema validators
//! are compiled at plugin construction time; request-time work is limited to
//! operation matching, optional decompression, media-type parsing, and schema
//! validation.

use ahash::AHashMap;
use async_trait::async_trait;
use flate2::read::GzDecoder;
use regex::{Regex, RegexSet};
use serde_json::Value;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::config::types::OPENAPI_VALIDATOR_DEFAULT_CONTENT_TYPES;

use super::{HTTP_ONLY_PROTOCOLS, Plugin, PluginResult, RequestContext};

const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
const DEFAULT_ERROR_TRUNCATE_CHARS: usize = 1024;
const MATCHED_OPERATION_INDEX_KEY: &str = "openapi_validator.matched_operation_index";
const MATCHED_OPERATION_METHOD_KEY: &str = "openapi_validator.matched_operation_method";
const SKIP_REASON_KEY: &str = "openapi_validator.skip_reason";

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
    literal_segments: u16,
    request_validators: AHashMap<String, MediaValidator>,
    request_required: bool,
    response_validators: ResponseValidators,
}

struct OperationBucket {
    path_regexes: RegexSet,
    entries: Vec<OperationEntry>,
}

struct MediaValidator {
    schema: Arc<Value>,
    validator: jsonschema::Validator,
}

#[derive(Default)]
struct ResponseValidators {
    exact: AHashMap<u16, AHashMap<String, MediaValidator>>,
    ranges: Vec<ResponseRangeValidators>,
    default: Option<AHashMap<String, MediaValidator>>,
}

struct ResponseRangeValidators {
    start: u16,
    end: u16,
    validators: AHashMap<String, MediaValidator>,
}

struct ParsedOperation {
    method: String,
    path_regex: String,
    entry: OperationEntry,
}

struct OperationMatch<'a> {
    method: &'a str,
    index: usize,
    entry: &'a OperationEntry,
}

impl OperationEntry {
    fn has_request_schema(&self) -> bool {
        !self.request_validators.is_empty()
    }

    fn has_response_schema(&self) -> bool {
        !self.response_validators.is_empty()
    }

    fn response_validator(
        &self,
        status: u16,
        content_type: Option<&str>,
    ) -> Option<&MediaValidator> {
        self.response_validators.validator(status, content_type)
    }
}

impl ResponseValidators {
    fn is_empty(&self) -> bool {
        self.exact.values().all(|validators| validators.is_empty())
            && self.ranges.iter().all(|range| range.validators.is_empty())
            && self
                .default
                .as_ref()
                .is_none_or(|validators| validators.is_empty())
    }

    fn validator(&self, status: u16, content_type: Option<&str>) -> Option<&MediaValidator> {
        self.exact
            .get(&status)
            .and_then(|validators| validator_for_content_type(validators, content_type))
            .or_else(|| {
                self.ranges
                    .iter()
                    .find(|range| (range.start..=range.end).contains(&status))
                    .and_then(|range| validator_for_content_type(&range.validators, content_type))
            })
            .or_else(|| {
                self.default
                    .as_ref()
                    .and_then(|validators| validator_for_content_type(validators, content_type))
            })
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
    ops_by_method: AHashMap<String, OperationBucket>,
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
            .unwrap_or_else(default_content_types)
            .into_iter()
            .map(|value| normalize_media_type(&value))
            .collect();
        let response_content_types = optional_string_vec(object, "response_content_types")?
            .unwrap_or_else(default_content_types)
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

        let mut grouped_ops: AHashMap<String, Vec<(String, OperationEntry)>> = AHashMap::new();
        let mut has_any_request_schema = false;
        let mut has_any_response_schema = false;
        for (index, operation) in operations.iter().enumerate() {
            let parsed = parse_operation(operation, index, schema_draft)?;
            has_any_request_schema |= parsed.entry.has_request_schema();
            has_any_response_schema |= parsed.entry.has_response_schema();
            grouped_ops
                .entry(parsed.method)
                .or_default()
                .push((parsed.path_regex, parsed.entry));
        }
        let mut ops_by_method: AHashMap<String, OperationBucket> = AHashMap::new();
        for (method, mut entries) in grouped_ops {
            entries.sort_by(|(_, left), (_, right)| {
                right
                    .literal_segments
                    .cmp(&left.literal_segments)
                    .then_with(|| right.operation_label.len().cmp(&left.operation_label.len()))
            });
            let patterns = entries.iter().map(|(pattern, _)| pattern.as_str());
            let path_regexes = RegexSet::new(patterns).map_err(|error| {
                format!("openapi_validator: failed to compile path regex set for {method}: {error}")
            })?;
            let entries = entries.into_iter().map(|(_, entry)| entry).collect();
            ops_by_method.insert(
                method,
                OperationBucket {
                    path_regexes,
                    entries,
                },
            );
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

    fn match_operation(&self, method: &str, path: &str) -> Option<OperationMatch<'_>> {
        let (method, bucket) = self
            .ops_by_method
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(method))?;
        let index = bucket.path_regexes.matches(path).into_iter().next()?;
        bucket.entries.get(index).map(|entry| OperationMatch {
            method,
            index,
            entry,
        })
    }

    fn cached_operation<'a>(&'a self, ctx: &RequestContext) -> Option<&'a OperationEntry> {
        let method = ctx.metadata.get(MATCHED_OPERATION_METHOD_KEY)?;
        if !method.eq_ignore_ascii_case(&ctx.method) {
            return None;
        }
        let index = ctx
            .metadata
            .get(MATCHED_OPERATION_INDEX_KEY)?
            .parse::<usize>()
            .ok()?;
        self.ops_by_method.get(method)?.entries.get(index)
    }

    fn operation_for_context<'a>(&'a self, ctx: &RequestContext) -> Option<&'a OperationEntry> {
        self.cached_operation(ctx).or_else(|| {
            self.match_operation(&ctx.method, &ctx.path)
                .map(|matched| matched.entry)
        })
    }

    fn mark_operation(&self, ctx: &mut RequestContext, operation: OperationMatch<'_>) {
        self.mark_operation_entry(ctx, operation.entry);
        ctx.metadata.insert(
            MATCHED_OPERATION_METHOD_KEY.to_string(),
            operation.method.to_string(),
        );
        ctx.metadata.insert(
            MATCHED_OPERATION_INDEX_KEY.to_string(),
            operation.index.to_string(),
        );
    }

    fn mark_operation_entry(&self, ctx: &mut RequestContext, operation: &OperationEntry) {
        self.mark_mode(ctx);
        ctx.metadata.insert(
            "openapi_validator.matched_operation".to_string(),
            operation.operation_label.clone(),
        );
    }

    fn match_and_mark_operation<'a>(
        &'a self,
        ctx: &mut RequestContext,
    ) -> Option<&'a OperationEntry> {
        let matched = self.match_operation(&ctx.method, &ctx.path)?;
        let entry = matched.entry;
        self.mark_operation(ctx, matched);
        Some(entry)
    }

    fn cached_bypass_reason(&self, ctx: &RequestContext) -> Option<&'static str> {
        match ctx.metadata.get(SKIP_REASON_KEY).map(String::as_str) {
            Some("bypass_path") => Some("bypass_path"),
            Some("bypass_method") => Some("bypass_method"),
            Some("bypass_consumer") => Some("bypass_consumer"),
            Some("bypass_header") => Some("bypass_header"),
            _ => None,
        }
    }

    fn bypass_reason_for_headers(
        &self,
        ctx: &RequestContext,
        headers: &HashMap<String, String>,
    ) -> Option<&'static str> {
        if let Some(reason) = self.cached_bypass_reason(ctx) {
            return Some(reason);
        }
        if self
            .bypass_paths
            .as_ref()
            .is_some_and(|paths| paths.is_match(&ctx.path))
        {
            return Some("bypass_path");
        }
        if self
            .bypass_methods
            .iter()
            .any(|method| method.eq_ignore_ascii_case(&ctx.method))
        {
            return Some("bypass_method");
        }
        if let Some(identity) = ctx.effective_identity()
            && self.bypass_consumers.contains(identity)
        {
            return Some("bypass_consumer");
        }
        if self.bypass_header_present.iter().any(|(name, expected)| {
            header_value(headers, name).is_some_and(|actual| {
                expected
                    .as_deref()
                    .is_none_or(|expected| actual == expected)
            })
        }) {
            return Some("bypass_header");
        }
        None
    }

    fn bypass_reason(&self, ctx: &RequestContext) -> Option<&'static str> {
        self.bypass_reason_for_headers(ctx, &ctx.headers)
    }

    fn mark_mode(&self, ctx: &mut RequestContext) {
        ctx.metadata.insert(
            "openapi_validator.mode".to_string(),
            self.mode.as_str().to_string(),
        );
    }

    fn mark_skip(&self, ctx: &mut RequestContext, reason: &'static str) {
        self.mark_mode(ctx);
        ctx.metadata
            .insert(SKIP_REASON_KEY.to_string(), reason.to_string());
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
    ) -> Option<&'a MediaValidator> {
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
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !self.active() {
            self.mark_mode(ctx);
            return PluginResult::Continue;
        }
        if let Some(reason) = self.bypass_reason_for_headers(ctx, headers) {
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
            || matches!(ctx.method.as_str(), "GET" | "HEAD" | "OPTIONS")
            || self.bypass_reason(ctx).is_some()
        {
            return false;
        }
        let Some(operation) = self.operation_for_context(ctx) else {
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
        if let Some(reason) = self.bypass_reason_for_headers(ctx, headers) {
            self.mark_skip(ctx, reason);
            return PluginResult::Continue;
        }
        let Some(operation) = self
            .cached_operation(ctx)
            .or_else(|| self.match_and_mark_operation(ctx))
        else {
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
        match validate_media_body(headers, body, content_type, validator, self.max_body_bytes) {
            Ok(()) => PluginResult::Continue,
            Err(error) => self.handle_violation(
                ctx,
                ValidationSide::Request,
                Some(&operation.operation_label),
                error,
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
                .operation_for_context(ctx)
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
        let Some(operation) = self
            .cached_operation(ctx)
            .or_else(|| self.match_and_mark_operation(ctx))
        else {
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
        match validate_media_body(
            response_headers,
            body,
            content_type,
            validator,
            self.max_body_bytes,
        ) {
            Ok(()) => PluginResult::Continue,
            Err(error) => self.handle_violation(
                ctx,
                ValidationSide::Response,
                Some(&operation.operation_label),
                error,
            ),
        }
    }
}

fn parse_operation(
    value: &Value,
    index: usize,
    schema_draft: SchemaDraft,
) -> Result<ParsedOperation, String> {
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
    Regex::new(path_regex_raw).map_err(|error| {
        format!("openapi_validator: operations[{index}].path_regex is invalid: {error}")
    })?;
    let operation_label = optional_string(object, "operation_label")?
        .map(str::to_string)
        .unwrap_or_else(|| format!("{method} {path_template}"));
    let request_required = match optional_bool_from_object(Some(object), "request_required")? {
        Some(value) => value,
        None => optional_bool_from_object(Some(object), "request_body_required")?.unwrap_or(false),
    };
    let request_validators =
        parse_request_validators(object.get("request_body"), index, schema_draft)?;
    let response_validators =
        parse_response_validators(object.get("responses"), index, schema_draft)?;

    Ok(ParsedOperation {
        method,
        path_regex: path_regex_raw.to_string(),
        entry: OperationEntry {
            operation_label,
            literal_segments: literal_segment_count(&path_template),
            request_validators,
            request_required,
            response_validators,
        },
    })
}

fn parse_request_validators(
    value: Option<&Value>,
    operation_index: usize,
    schema_draft: SchemaDraft,
) -> Result<AHashMap<String, MediaValidator>, String> {
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
            compile_media_validator(schema, schema_draft).map_err(|error| {
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
            compile_media_validator(schema, schema_draft).map_err(|error| {
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
) -> Result<ResponseValidators, String> {
    let Some(value) = value else {
        return Ok(ResponseValidators::default());
    };
    if value.is_null() {
        return Ok(ResponseValidators::default());
    }
    let object = value.as_object().ok_or_else(|| {
        format!("openapi_validator: operations[{operation_index}].responses must be an object")
    })?;
    let mut statuses = ResponseValidators::default();
    for (status_raw, response_value) in object {
        let status = parse_response_status_key(status_raw, operation_index)?;
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
                compile_media_validator(schema, schema_draft).map_err(|error| {
                    format!(
                        "openapi_validator: operations[{operation_index}].responses['{status_raw}'] schema for {content_type} is invalid: {error}"
                    )
                })?,
            );
        }
        match status {
            ResponseStatusKey::Exact(status) => {
                statuses.exact.insert(status, validators);
            }
            ResponseStatusKey::Range(start, end) => {
                statuses.ranges.push(ResponseRangeValidators {
                    start,
                    end,
                    validators,
                });
            }
            ResponseStatusKey::Default => {
                statuses.default = Some(validators);
            }
        }
    }
    Ok(statuses)
}

enum ResponseStatusKey {
    Exact(u16),
    Range(u16, u16),
    Default,
}

fn parse_response_status_key(
    status_raw: &str,
    operation_index: usize,
) -> Result<ResponseStatusKey, String> {
    if status_raw.eq_ignore_ascii_case("default") {
        return Ok(ResponseStatusKey::Default);
    }
    let bytes = status_raw.as_bytes();
    if bytes.len() == 3
        && matches!(bytes[0], b'1'..=b'5')
        && bytes[1].eq_ignore_ascii_case(&b'X')
        && bytes[2].eq_ignore_ascii_case(&b'X')
    {
        let class = u16::from(bytes[0] - b'0');
        let start = class * 100;
        return Ok(ResponseStatusKey::Range(start, start + 99));
    }
    status_raw
        .parse::<u16>()
        .map(ResponseStatusKey::Exact)
        .map_err(|_| {
            format!(
                "openapi_validator: operations[{operation_index}].responses contains invalid status '{status_raw}'"
            )
        })
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

fn compile_media_validator(
    schema: &Value,
    schema_draft: SchemaDraft,
) -> Result<MediaValidator, String> {
    let validator = compile_schema(schema, schema_draft).map_err(|error| error.to_string())?;
    Ok(MediaValidator {
        schema: Arc::new(schema.clone()),
        validator,
    })
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

enum SchemaInstance {
    Value(Value),
    BinaryLengthOnly,
}

fn validate_media_body(
    headers: &HashMap<String, String>,
    body: &[u8],
    content_type: Option<&str>,
    validator: &MediaValidator,
    max_body_bytes: usize,
) -> Result<(), String> {
    match body_to_schema_instance(
        headers,
        body,
        content_type,
        validator.schema.as_ref(),
        max_body_bytes,
    )? {
        SchemaInstance::Value(instance) => validator
            .validator
            .validate(&instance)
            .map_err(|error| format_schema_error(&error)),
        SchemaInstance::BinaryLengthOnly => Ok(()),
    }
}

fn body_to_schema_instance(
    headers: &HashMap<String, String>,
    body: &[u8],
    content_type: Option<&str>,
    schema: &Value,
    max_body_bytes: usize,
) -> Result<SchemaInstance, String> {
    let decoded = decode_body(headers, body, max_body_bytes)?;
    let media_type = content_type_base(content_type)
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if is_json_media_type(&media_type) {
        return serde_json::from_slice(decoded.as_ref())
            .map(SchemaInstance::Value)
            .map_err(|error| format!("Invalid JSON body: {error}"));
    }
    if is_xml_media_type(&media_type) {
        let body = std::str::from_utf8(decoded.as_ref())
            .map_err(|error| format!("Invalid XML body encoding: {error}"))?;
        return xml_body_to_value(body, schema).map(SchemaInstance::Value);
    }
    if media_type == "application/x-www-form-urlencoded" {
        let body = std::str::from_utf8(decoded.as_ref())
            .map_err(|error| format!("Invalid form body encoding: {error}"))?;
        return form_urlencoded_to_value(body, schema).map(SchemaInstance::Value);
    }
    if media_type == "multipart/form-data" {
        let boundary = multipart_boundary(content_type.unwrap_or(""))
            .ok_or_else(|| "Multipart body is missing boundary parameter".to_string())?;
        return multipart_to_value(decoded.as_ref(), &boundary, schema).map(SchemaInstance::Value);
    }
    if is_text_media_type(&media_type) {
        let body = std::str::from_utf8(decoded.as_ref())
            .map_err(|error| format!("Invalid text body encoding: {error}"))?;
        return scalar_to_schema_value(body, schema).map(SchemaInstance::Value);
    }
    binary_body_to_schema_instance(decoded.as_ref(), schema)
}

fn xml_body_to_value(body: &str, schema: &Value) -> Result<Value, String> {
    let doc =
        roxmltree::Document::parse(body).map_err(|error| format!("Invalid XML body: {error}"))?;
    let root = doc.root_element();
    if let Some(expected_root) = xml_name(schema, None)
        && root.tag_name().name() != expected_root
    {
        return Err(format!(
            "XML root element '{}' does not match schema xml.name '{}'",
            root.tag_name().name(),
            expected_root
        ));
    }
    xml_node_to_value(root, schema)
}

fn xml_node_to_value(node: roxmltree::Node<'_, '_>, schema: &Value) -> Result<Value, String> {
    let schema = conversion_schema(schema);
    if schema_type_contains(schema, "array") {
        let item_schema = schema.get("items").unwrap_or(&Value::Null);
        let values = node
            .children()
            .filter(roxmltree::Node::is_element)
            .map(|child| xml_node_to_value(child, item_schema))
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(Value::Array(values));
    }
    if schema_type_contains(schema, "object") || schema.get("properties").is_some() {
        let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
            return Ok(generic_xml_node_to_value(node));
        };
        let mut out = serde_json::Map::new();
        let mut modeled_children = HashSet::new();
        let mut modeled_attributes = HashSet::new();
        for (property_name, property_schema) in properties {
            let property_schema = conversion_schema(property_schema);
            if xml_attribute(property_schema) {
                let attr_name = xml_name(property_schema, Some(property_name.as_str()))
                    .unwrap_or(property_name.as_str());
                modeled_attributes.insert(attr_name.to_string());
                if let Some(value) = node.attribute(attr_name) {
                    out.insert(
                        property_name.clone(),
                        scalar_to_schema_value(value, property_schema)?,
                    );
                }
                continue;
            }
            if schema_type_contains(property_schema, "array") {
                let values = xml_array_values(node, property_name, property_schema)?;
                if !values.is_empty() {
                    out.insert(property_name.clone(), Value::Array(values));
                }
                continue;
            }
            let child_name = xml_name(property_schema, Some(property_name.as_str()))
                .unwrap_or(property_name.as_str());
            modeled_children.insert(child_name.to_string());
            if let Some(child) = first_child_element(node, child_name) {
                out.insert(
                    property_name.clone(),
                    xml_node_to_value(child, property_schema)?,
                );
            }
        }
        if schema.get("additionalProperties").and_then(Value::as_bool) == Some(false) {
            for attr in node.attributes() {
                let name = attr.name();
                if !modeled_attributes.contains(name) && !out.contains_key(name) {
                    out.insert(name.to_string(), Value::String(attr.value().to_string()));
                }
            }
            for child in node.children().filter(roxmltree::Node::is_element) {
                let name = child.tag_name().name();
                if !modeled_children.contains(name) && !out.contains_key(name) {
                    out.insert(name.to_string(), generic_xml_node_to_value(child));
                }
            }
        }
        return Ok(Value::Object(out));
    }
    let text = node.text().unwrap_or("").trim();
    scalar_to_schema_value(text, schema)
}

fn xml_array_values(
    node: roxmltree::Node<'_, '_>,
    property_name: &str,
    property_schema: &Value,
) -> Result<Vec<Value>, String> {
    let item_schema = property_schema.get("items").unwrap_or(&Value::Null);
    let item_schema = conversion_schema(item_schema);
    let item_name = xml_name(item_schema, None)
        .or_else(|| xml_name(property_schema, Some(property_name)))
        .unwrap_or(property_name);
    let mut values = Vec::new();
    if xml_wrapped(property_schema) {
        let wrapper_name = xml_name(property_schema, Some(property_name)).unwrap_or(property_name);
        for wrapper in child_elements(node, wrapper_name) {
            for child in child_elements(wrapper, item_name) {
                values.push(xml_node_to_value(child, item_schema)?);
            }
        }
    } else {
        for child in child_elements(node, item_name) {
            values.push(xml_node_to_value(child, item_schema)?);
        }
    }
    Ok(values)
}

fn generic_xml_node_to_value(node: roxmltree::Node<'_, '_>) -> Value {
    let mut out = serde_json::Map::new();
    for attr in node.attributes() {
        out.insert(
            attr.name().to_string(),
            Value::String(attr.value().to_string()),
        );
    }
    let children: Vec<_> = node
        .children()
        .filter(roxmltree::Node::is_element)
        .collect();
    if children.is_empty() {
        return Value::String(node.text().unwrap_or("").trim().to_string());
    }
    for child in children {
        let value = generic_xml_node_to_value(child);
        let name = child.tag_name().name().to_string();
        match out.get_mut(&name) {
            Some(Value::Array(values)) => values.push(value),
            Some(existing) => {
                let first = std::mem::take(existing);
                *existing = Value::Array(vec![first, value]);
            }
            None => {
                out.insert(name, value);
            }
        }
    }
    if let Some(text) = node.text().map(str::trim)
        && !text.is_empty()
    {
        out.insert("#text".to_string(), Value::String(text.to_string()));
    }
    Value::Object(out)
}

fn form_urlencoded_to_value(body: &str, schema: &Value) -> Result<Value, String> {
    let mut fields: HashMap<String, Vec<String>> = HashMap::new();
    for (key, value) in url::form_urlencoded::parse(body.as_bytes()) {
        fields
            .entry(key.into_owned())
            .or_default()
            .push(value.into_owned());
    }
    fields_to_schema_object(fields, schema, "form")
}

#[derive(Debug)]
struct MultipartPart {
    name: String,
    filename: Option<String>,
    content_type: Option<String>,
    body: Vec<u8>,
}

fn multipart_to_value(body: &[u8], boundary: &str, schema: &Value) -> Result<Value, String> {
    let parts = parse_multipart_parts(body, boundary)?;
    let mut grouped: HashMap<String, Vec<MultipartPart>> = HashMap::new();
    for part in parts {
        grouped.entry(part.name.clone()).or_default().push(part);
    }
    multipart_parts_to_schema_object(grouped, schema)
}

fn parse_multipart_parts(body: &[u8], boundary: &str) -> Result<Vec<MultipartPart>, String> {
    if boundary.is_empty() || boundary.len() > 200 {
        return Err("Invalid multipart boundary".to_string());
    }
    let delimiter = format!("--{boundary}");
    let mut parts = Vec::new();
    for raw_segment in split_bytes(body, delimiter.as_bytes()).into_iter().skip(1) {
        let mut segment = trim_leading_line_break(raw_segment);
        if segment.starts_with(b"--") {
            break;
        }
        segment = trim_trailing_line_break(segment);
        if segment.is_empty() {
            continue;
        }
        let Some((header_bytes, part_body)) = split_header_body(segment) else {
            return Err("Malformed multipart part: missing header/body separator".to_string());
        };
        let headers = parse_part_headers(header_bytes)?;
        let Some(disposition) = headers.get("content-disposition") else {
            return Err("Malformed multipart part: missing Content-Disposition".to_string());
        };
        let params = parse_header_params(disposition);
        let Some(name) = params.get("name").filter(|value| !value.is_empty()) else {
            return Err("Malformed multipart part: missing form-data name".to_string());
        };
        parts.push(MultipartPart {
            name: name.clone(),
            filename: params.get("filename").cloned(),
            content_type: headers.get("content-type").cloned(),
            body: part_body.to_vec(),
        });
    }
    Ok(parts)
}

fn fields_to_schema_object(
    fields: HashMap<String, Vec<String>>,
    schema: &Value,
    label: &'static str,
) -> Result<Value, String> {
    let schema = conversion_schema(schema);
    if !(schema_type_contains(schema, "object") || schema.get("properties").is_some()) {
        let Some(values) = fields.values().next() else {
            return Ok(Value::Null);
        };
        return values_to_schema_value(values, schema);
    }
    let mut out = serde_json::Map::new();
    let properties = schema.get("properties").and_then(Value::as_object);
    if let Some(properties) = properties {
        for (property, property_schema) in properties {
            if let Some(values) = fields.get(property) {
                out.insert(
                    property.clone(),
                    values_to_schema_value(values, conversion_schema(property_schema))?,
                );
            }
        }
    }
    for (key, values) in fields {
        if !out.contains_key(&key) {
            out.insert(key, values_to_schema_value(&values, &Value::Null)?);
        }
    }
    if out.is_empty() && schema_has_required(schema) {
        return Err(format!("{label} body did not contain any schema fields"));
    }
    Ok(Value::Object(out))
}

fn multipart_parts_to_schema_object(
    parts: HashMap<String, Vec<MultipartPart>>,
    schema: &Value,
) -> Result<Value, String> {
    let schema = conversion_schema(schema);
    if !(schema_type_contains(schema, "object") || schema.get("properties").is_some()) {
        let Some(values) = parts.values().next() else {
            return Ok(Value::Null);
        };
        let Some(first) = values.first() else {
            return Ok(Value::Null);
        };
        return multipart_part_to_schema_value(first, schema);
    }
    let mut out = serde_json::Map::new();
    let properties = schema.get("properties").and_then(Value::as_object);
    if let Some(properties) = properties {
        for (property, property_schema) in properties {
            if let Some(values) = parts.get(property) {
                let property_schema = conversion_schema(property_schema);
                if schema_type_contains(property_schema, "array") {
                    let item_schema = property_schema.get("items").unwrap_or(&Value::Null);
                    let array = values
                        .iter()
                        .map(|part| multipart_part_to_schema_value(part, item_schema))
                        .collect::<Result<Vec<_>, _>>()?;
                    out.insert(property.clone(), Value::Array(array));
                } else if let Some(first) = values.first() {
                    out.insert(
                        property.clone(),
                        multipart_part_to_schema_value(first, property_schema)?,
                    );
                }
            }
        }
    }
    for (key, values) in parts {
        if !out.contains_key(&key) {
            let value = if values.len() == 1 {
                multipart_part_to_schema_value(&values[0], &Value::Null)?
            } else {
                Value::Array(
                    values
                        .iter()
                        .map(|part| multipart_part_to_schema_value(part, &Value::Null))
                        .collect::<Result<Vec<_>, _>>()?,
                )
            };
            out.insert(key, value);
        }
    }
    Ok(Value::Object(out))
}

fn multipart_part_to_schema_value(part: &MultipartPart, schema: &Value) -> Result<Value, String> {
    let schema = conversion_schema(schema);
    if schema_type_contains(schema, "object") || schema.get("properties").is_some() {
        let mut out = serde_json::Map::new();
        if let Some(filename) = &part.filename {
            out.insert("filename".to_string(), Value::String(filename.clone()));
        }
        if let Some(content_type) = &part.content_type {
            out.insert(
                "content_type".to_string(),
                Value::String(content_type.clone()),
            );
        }
        out.insert(
            "size".to_string(),
            Value::Number(serde_json::Number::from(part.body.len() as u64)),
        );
        if let Ok(text) = std::str::from_utf8(&part.body) {
            out.insert("content".to_string(), Value::String(text.to_string()));
        }
        return Ok(Value::Object(out));
    }
    if schema_format(schema) == Some("binary") || part.filename.is_some() {
        return binary_to_schema_value(&part.body, schema);
    }
    let text = std::str::from_utf8(&part.body)
        .map_err(|error| format!("Multipart field '{}' is not UTF-8: {error}", part.name))?;
    scalar_to_schema_value(text, schema)
}

fn values_to_schema_value(values: &[String], schema: &Value) -> Result<Value, String> {
    if schema_type_contains(schema, "array") {
        let item_schema = schema.get("items").unwrap_or(&Value::Null);
        return values
            .iter()
            .map(|value| scalar_to_schema_value(value, item_schema))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array);
    }
    if values.len() > 1 {
        return Ok(Value::Array(
            values
                .iter()
                .map(|value| scalar_to_schema_value(value, &Value::Null))
                .collect::<Result<Vec<_>, _>>()?,
        ));
    }
    let value = values.first().map(String::as_str).unwrap_or("");
    scalar_to_schema_value(value, schema)
}

fn scalar_to_schema_value(value: &str, schema: &Value) -> Result<Value, String> {
    let schema = conversion_schema(schema);
    if schema_type_contains(schema, "integer") {
        let value = value
            .parse::<i64>()
            .map_err(|error| format!("Invalid integer value '{value}': {error}"))?;
        return Ok(Value::Number(serde_json::Number::from(value)));
    }
    if schema_type_contains(schema, "number") {
        let value = value
            .parse::<f64>()
            .map_err(|error| format!("Invalid number value '{value}': {error}"))?;
        let number = serde_json::Number::from_f64(value)
            .ok_or_else(|| format!("Invalid finite number value '{value}'"))?;
        return Ok(Value::Number(number));
    }
    if schema_type_contains(schema, "boolean") {
        let value = value.trim();
        if value == "1"
            || value.eq_ignore_ascii_case("true")
            || value.eq_ignore_ascii_case("yes")
            || value.eq_ignore_ascii_case("on")
        {
            return Ok(Value::Bool(true));
        }
        if value == "0"
            || value.eq_ignore_ascii_case("false")
            || value.eq_ignore_ascii_case("no")
            || value.eq_ignore_ascii_case("off")
        {
            return Ok(Value::Bool(false));
        }
        return Err(format!("Invalid boolean value '{value}'"));
    }
    Ok(Value::String(value.to_string()))
}

fn binary_body_to_schema_instance(body: &[u8], schema: &Value) -> Result<SchemaInstance, String> {
    match std::str::from_utf8(body) {
        Ok(value) => Ok(SchemaInstance::Value(Value::String(value.to_string()))),
        Err(_) => {
            validate_binary_length(body.len(), schema)?;
            Ok(SchemaInstance::BinaryLengthOnly)
        }
    }
}

fn binary_to_schema_value(body: &[u8], schema: &Value) -> Result<Value, String> {
    match std::str::from_utf8(body) {
        Ok(value) => Ok(Value::String(value.to_string())),
        Err(_) => {
            validate_binary_length(body.len(), schema)?;
            Err(
                "Non-UTF-8 multipart binary fields require an object schema to validate metadata"
                    .to_string(),
            )
        }
    }
}

fn validate_binary_length(len: usize, schema: &Value) -> Result<(), String> {
    let schema = conversion_schema(schema);
    if schema.get("type").is_some() && !schema_type_contains(schema, "string") {
        return Err(
            "Non-UTF-8 binary bodies require a string schema with optional minLength/maxLength"
                .to_string(),
        );
    }
    if let Some(min_length) = schema_usize(schema, "minLength")
        && len < min_length
    {
        return Err(format!(
            "Binary body length {len} is shorter than minLength {min_length}"
        ));
    }
    if let Some(max_length) = schema_usize(schema, "maxLength")
        && len > max_length
    {
        return Err(format!(
            "Binary body length {len} exceeds maxLength {max_length}"
        ));
    }
    Ok(())
}

fn schema_usize(schema: &Value, key: &str) -> Option<usize> {
    schema
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
}

fn validator_for_content_type<'a>(
    validators: &'a AHashMap<String, MediaValidator>,
    content_type: Option<&str>,
) -> Option<&'a MediaValidator> {
    let base = content_type_base(content_type)?;
    validators
        .iter()
        .find(|(expected, _)| expected.eq_ignore_ascii_case(base))
        .map(|(_, validator)| validator)
        .or_else(|| fallback_validator_for_media_type(validators, base))
}

fn content_type_in_scope(configured: &[String], content_type: Option<&str>) -> bool {
    let Some(base) = content_type_base(content_type) else {
        return false;
    };
    configured.is_empty()
        || configured
            .iter()
            .any(|expected| media_type_matches(expected, base))
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

fn default_content_types() -> Vec<String> {
    OPENAPI_VALIDATOR_DEFAULT_CONTENT_TYPES
        .iter()
        .map(|value| value.to_string())
        .collect()
}

fn fallback_validator_for_media_type<'a>(
    validators: &'a AHashMap<String, MediaValidator>,
    actual: &str,
) -> Option<&'a MediaValidator> {
    if is_json_media_type(actual) {
        return validators.get("application/json");
    }
    if is_xml_media_type(actual) {
        return validators
            .get("application/xml")
            .or_else(|| validators.get("text/xml"));
    }
    if actual == "application/x-www-form-urlencoded" {
        return validators.get("application/x-www-form-urlencoded");
    }
    if actual == "multipart/form-data" {
        return validators.get("multipart/form-data");
    }
    if is_text_media_type(actual) {
        return validators.get("text/plain");
    }
    validators.get("application/octet-stream")
}

fn media_type_matches(expected: &str, actual: &str) -> bool {
    expected.eq_ignore_ascii_case(actual)
        || (expected == "application/json" && is_json_media_type(actual))
        || ((expected == "application/xml" || expected == "text/xml") && is_xml_media_type(actual))
        || (expected == "text/plain" && is_text_media_type(actual))
        || (expected == "application/octet-stream" && is_binary_media_type(actual))
}

fn is_json_media_type(media_type: &str) -> bool {
    media_type == "application/json" || media_type.ends_with("+json")
}

fn is_xml_media_type(media_type: &str) -> bool {
    media_type == "application/xml" || media_type == "text/xml" || media_type.ends_with("+xml")
}

fn is_text_media_type(media_type: &str) -> bool {
    media_type == "text/plain" || media_type.starts_with("text/")
}

fn is_binary_media_type(media_type: &str) -> bool {
    media_type == "application/octet-stream"
        || media_type.starts_with("image/")
        || media_type.starts_with("audio/")
        || media_type.starts_with("video/")
        || (media_type.starts_with("application/")
            && !is_json_media_type(media_type)
            && !is_xml_media_type(media_type)
            && media_type != "application/x-www-form-urlencoded")
}

fn multipart_boundary(content_type: &str) -> Option<String> {
    parse_header_params(content_type).remove("boundary")
}

fn parse_header_params(value: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    for piece in value.split(';').skip(1) {
        let Some((key, value)) = piece.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        if key.is_empty() {
            continue;
        }
        params.insert(key, unquote_header_value(value.trim()));
    }
    params
}

fn unquote_header_value(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        value[1..value.len() - 1]
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")
    } else {
        value.to_string()
    }
}

fn parse_part_headers(header_bytes: &[u8]) -> Result<HashMap<String, String>, String> {
    let headers = std::str::from_utf8(header_bytes)
        .map_err(|error| format!("Multipart headers are not UTF-8: {error}"))?;
    let mut out = HashMap::new();
    for line in headers.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        out.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }
    Ok(out)
}

fn split_header_body(segment: &[u8]) -> Option<(&[u8], &[u8])> {
    if let Some(index) = memchr::memmem::find(segment, b"\r\n\r\n") {
        return Some((&segment[..index], &segment[index + 4..]));
    }
    memchr::memmem::find(segment, b"\n\n").map(|index| (&segment[..index], &segment[index + 2..]))
}

fn split_bytes<'a>(body: &'a [u8], delimiter: &[u8]) -> Vec<&'a [u8]> {
    let mut out = Vec::new();
    let mut start = 0;
    let finder = memchr::memmem::Finder::new(delimiter);
    while let Some(offset) = finder.find(&body[start..]) {
        let index = start + offset;
        out.push(&body[start..index]);
        start = index + delimiter.len();
    }
    out.push(&body[start..]);
    out
}

fn trim_leading_line_break(mut value: &[u8]) -> &[u8] {
    if value.starts_with(b"\r\n") {
        value = &value[2..];
    } else if value.starts_with(b"\n") {
        value = &value[1..];
    }
    value
}

fn trim_trailing_line_break(mut value: &[u8]) -> &[u8] {
    if value.ends_with(b"\r\n") {
        value = &value[..value.len() - 2];
    } else if value.ends_with(b"\n") {
        value = &value[..value.len() - 1];
    }
    value
}

fn conversion_schema(schema: &Value) -> &Value {
    if schema.get("type").is_some()
        || schema.get("properties").is_some()
        || schema.get("items").is_some()
    {
        return schema;
    }
    for key in ["allOf", "oneOf", "anyOf"] {
        if let Some(values) = schema.get(key).and_then(Value::as_array)
            && let Some(candidate) = values
                .iter()
                .find(|candidate| !schema_type_contains(candidate, "null"))
        {
            return candidate;
        }
    }
    schema
}

fn schema_type_contains(schema: &Value, expected: &str) -> bool {
    match schema.get("type") {
        Some(Value::String(value)) => value == expected,
        Some(Value::Array(values)) => values.iter().any(|value| value.as_str() == Some(expected)),
        _ => false,
    }
}

fn schema_format(schema: &Value) -> Option<&str> {
    schema.get("format").and_then(Value::as_str)
}

fn schema_has_required(schema: &Value) -> bool {
    schema
        .get("required")
        .and_then(Value::as_array)
        .is_some_and(|values| values.iter().any(Value::is_string))
}

fn xml_name<'a>(schema: &'a Value, default: Option<&'a str>) -> Option<&'a str> {
    schema
        .get("xml")
        .and_then(|value| value.get("name"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .or(default)
}

fn xml_attribute(schema: &Value) -> bool {
    schema
        .get("xml")
        .and_then(|value| value.get("attribute"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn xml_wrapped(schema: &Value) -> bool {
    schema
        .get("xml")
        .and_then(|value| value.get("wrapped"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn first_child_element<'a>(
    node: roxmltree::Node<'a, 'a>,
    local_name: &str,
) -> Option<roxmltree::Node<'a, 'a>> {
    node.children()
        .find(|child| child.is_element() && child.tag_name().name() == local_name)
}

fn child_elements<'a>(
    node: roxmltree::Node<'a, 'a>,
    local_name: &str,
) -> Vec<roxmltree::Node<'a, 'a>> {
    node.children()
        .filter(move |child| child.is_element() && child.tag_name().name() == local_name)
        .collect()
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

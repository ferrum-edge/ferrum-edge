//! AI Request Guard Plugin
//!
//! Validates and constrains AI/LLM API requests before they reach the backend,
//! preventing expensive mistakes and enforcing organizational policy at the
//! gateway layer.
//!
//! Supports model blocking/allowlisting, max_tokens enforcement (reject or
//! clamp), message count limits, prompt character limits, temperature range
//! validation, system prompt blocking, and required field enforcement.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use tracing::{debug, warn};

use super::utils::body_transform::is_json_content_type;
use super::utils::json_escape::escape_json_string;
use super::{Plugin, PluginResult, RequestContext};

/// Action to take when max_tokens exceeds the limit.
#[derive(Debug, Clone, PartialEq, Eq)]
enum MaxTokensAction {
    Reject,
    Clamp,
}

pub struct AiRequestGuard {
    max_tokens_limit: Option<u64>,
    enforce_max_tokens: MaxTokensAction,
    default_max_tokens: Option<u64>,
    allowed_models: HashSet<String>,
    blocked_models: HashSet<String>,
    require_user_field: bool,
    max_messages: Option<u64>,
    max_prompt_characters: Option<u64>,
    temperature_range: Option<(f64, f64)>,
    block_system_prompts: bool,
    required_metadata_fields: Vec<String>,
    fail_on_uninspectable_body: bool,
    /// True when the plugin needs to modify the request body (clamp or inject defaults).
    needs_body_transform: bool,
    /// True when any configured policy needs the request body to be inspected.
    requires_request_body: bool,
}

impl AiRequestGuard {
    pub fn new(config: &Value) -> Result<Self, String> {
        if !config.is_object() {
            return Err("ai_request_guard: config must be an object".to_string());
        }

        let max_tokens_limit = optional_u64(config, "max_tokens_limit")?;
        let enforce_max_tokens = match optional_string(config, "enforce_max_tokens")?
            .unwrap_or("reject")
        {
            "reject" => MaxTokensAction::Reject,
            "clamp" => MaxTokensAction::Clamp,
            other => {
                return Err(format!(
                    "ai_request_guard: 'enforce_max_tokens' must be one of 'reject' or 'clamp', got: {other:?}"
                ));
            }
        };
        let default_max_tokens = optional_u64(config, "default_max_tokens")?;

        // Reject a contradictory cost-control config: the injected default must
        // not exceed the configured cap. `default_max_tokens` is injected when a
        // request omits all token fields and is never clamped, so a default
        // above `max_tokens_limit` would make the gateway itself emit a
        // `max_tokens` value that violates the operator's own limit. Fail fast
        // at construction, consistent with the temperature_range validation.
        if let (Some(default), Some(limit)) = (default_max_tokens, max_tokens_limit)
            && default > limit
        {
            return Err(format!(
                "ai_request_guard: 'default_max_tokens' ({default}) must be <= 'max_tokens_limit' ({limit})"
            ));
        }

        let allowed_models = optional_lowercase_set(config, "allowed_models")?.unwrap_or_default();
        let blocked_models = optional_lowercase_set(config, "blocked_models")?.unwrap_or_default();

        let require_user_field = optional_bool(config, "require_user_field")?.unwrap_or(false);
        let max_messages = optional_u64(config, "max_messages")?;
        let max_prompt_characters = optional_u64(config, "max_prompt_characters")?;

        // Parse temperature_range with strict validation. A misconfigured
        // `[max, min]` or `[NaN, x]` would silently reject every request or
        // silently accept all of them (NaN comparisons always return false),
        // so reject these inputs at construction time rather than producing
        // a plugin that looks active but behaves incorrectly.
        let temperature_range = if let Some(arr) = config.get("temperature_range") {
            let Some(arr) = arr.as_array() else {
                return Err(
                    "ai_request_guard: 'temperature_range' must be an array of two numbers"
                        .to_string(),
                );
            };
            if arr.len() != 2 {
                return Err(format!(
                    "ai_request_guard: 'temperature_range' must have exactly 2 elements, got {}",
                    arr.len()
                ));
            }
            let Some(min) = arr[0].as_f64() else {
                return Err("ai_request_guard: 'temperature_range[0]' must be a number".to_string());
            };
            let Some(max) = arr[1].as_f64() else {
                return Err("ai_request_guard: 'temperature_range[1]' must be a number".to_string());
            };
            if !min.is_finite() || !max.is_finite() {
                return Err(format!(
                    "ai_request_guard: 'temperature_range' bounds must be finite, got [{min}, {max}]"
                ));
            }
            if min > max {
                return Err(format!(
                    "ai_request_guard: 'temperature_range' min must be <= max, got [{min}, {max}]"
                ));
            }
            Some((min, max))
        } else {
            None
        };

        let block_system_prompts = optional_bool(config, "block_system_prompts")?.unwrap_or(false);

        let required_metadata_fields =
            optional_string_vec(config, "required_metadata_fields")?.unwrap_or_default();
        let fail_on_uninspectable_body =
            optional_bool(config, "fail_on_uninspectable_body")?.unwrap_or(true);

        let needs_body_transform = (max_tokens_limit.is_some()
            && enforce_max_tokens == MaxTokensAction::Clamp)
            || default_max_tokens.is_some();
        let requires_request_body = needs_body_transform
            || max_tokens_limit.is_some()
            || !allowed_models.is_empty()
            || !blocked_models.is_empty()
            || require_user_field
            || max_messages.is_some()
            || max_prompt_characters.is_some()
            || temperature_range.is_some()
            || block_system_prompts
            || !required_metadata_fields.is_empty();

        // Reject configs that would make the plugin a no-op: at least one
        // policy must be configured for the plugin to do anything useful.
        if !requires_request_body {
            return Err("ai_request_guard: at least one policy must be configured \
                 (max_tokens_limit, default_max_tokens, allowed_models, blocked_models, \
                 require_user_field, max_messages, max_prompt_characters, \
                 temperature_range, block_system_prompts, or required_metadata_fields)"
                .to_string());
        }

        Ok(Self {
            max_tokens_limit,
            enforce_max_tokens,
            default_max_tokens,
            allowed_models,
            blocked_models,
            require_user_field,
            max_messages,
            max_prompt_characters,
            temperature_range,
            block_system_prompts,
            required_metadata_fields,
            fail_on_uninspectable_body,
            needs_body_transform,
            requires_request_body,
        })
    }

    /// Validate the request body JSON. Returns Err with a rejection tuple on failure.
    fn validate(&self, json: &Value) -> Result<(), (String, String)> {
        // Model blocking/allowlisting
        if let Some(model) = json.get("model").and_then(|v| v.as_str()) {
            let model_lower = model.to_lowercase();

            if !self.blocked_models.is_empty() && self.blocked_models.contains(model_lower.as_str())
            {
                return Err((
                    "Model not allowed".to_string(),
                    format!(
                        "Model '{}' is blocked by gateway policy",
                        escape_json_string(model)
                    ),
                ));
            }

            if !self.allowed_models.is_empty()
                && !self.allowed_models.contains(model_lower.as_str())
            {
                return Err((
                    "Model not allowed".to_string(),
                    format!(
                        "Model '{}' is not in the allowed models list",
                        escape_json_string(model)
                    ),
                ));
            }
        }

        // Max tokens check (reject mode only — clamp is handled in transform_request_body)
        if self.enforce_max_tokens == MaxTokensAction::Reject
            && let Some(limit) = self.max_tokens_limit
        {
            let requested = json
                .get("max_tokens")
                .or_else(|| json.get("max_output_tokens"))
                .or_else(|| json.get("max_completion_tokens"))
                .and_then(|v| v.as_u64());
            if let Some(req) = requested
                && req > limit
            {
                return Err((
                    "max_tokens exceeds limit".to_string(),
                    format!("Requested {} tokens, maximum allowed is {}", req, limit),
                ));
            }
        }

        // Message count
        if let Some(max_msgs) = self.max_messages
            && let Some(messages) = json.get("messages").and_then(|v| v.as_array())
            && messages.len() as u64 > max_msgs
        {
            return Err((
                "Too many messages".to_string(),
                format!(
                    "Request contains {} messages, maximum allowed is {}",
                    messages.len(),
                    max_msgs
                ),
            ));
        }

        // Prompt character limit
        if let Some(max_chars) = self.max_prompt_characters
            && let Some(messages) = json.get("messages").and_then(|v| v.as_array())
        {
            let total_chars: u64 = messages.iter().map(count_message_characters).sum();
            if total_chars > max_chars {
                return Err((
                    "Prompt too long".to_string(),
                    format!(
                        "Total prompt length is {} characters, maximum allowed is {}",
                        total_chars, max_chars
                    ),
                ));
            }
        }

        // Temperature range
        if let Some((min_temp, max_temp)) = self.temperature_range
            && let Some(temp) = json.get("temperature").and_then(|v| v.as_f64())
            && (temp < min_temp || temp > max_temp)
        {
            return Err((
                "Temperature out of range".to_string(),
                format!(
                    "Temperature {} is outside allowed range [{}, {}]",
                    temp, min_temp, max_temp
                ),
            ));
        }

        // System prompt blocking
        if self.block_system_prompts
            && let Some(messages) = json.get("messages").and_then(|v| v.as_array())
        {
            for msg in messages {
                if msg.get("role").and_then(|r| r.as_str()) == Some("system") {
                    return Err((
                        "System prompts not allowed".to_string(),
                        "Requests with system role messages are blocked by gateway policy"
                            .to_string(),
                    ));
                }
            }
        }

        // Require user field
        if self.require_user_field && json.get("user").is_none() {
            return Err((
                "Missing required field".to_string(),
                "The 'user' field is required for audit trail purposes".to_string(),
            ));
        }

        // Required metadata fields
        for field in &self.required_metadata_fields {
            if json.get(field.as_str()).is_none() {
                return Err((
                    "Missing required field".to_string(),
                    format!(
                        "Required field '{}' is missing from the request",
                        escape_json_string(field)
                    ),
                ));
            }
        }

        Ok(())
    }

    fn handle_uninspectable_body(
        &self,
        ctx: &mut RequestContext,
        reason: &'static str,
        status_code: u16,
        details: String,
    ) -> PluginResult {
        let action = if self.fail_on_uninspectable_body {
            "reject"
        } else {
            "allow"
        };
        ctx.metadata.insert(
            "ai_request_guard.uninspectable_body".to_string(),
            "true".to_string(),
        );
        ctx.metadata.insert(
            "ai_request_guard.uninspectable_body_reason".to_string(),
            reason.to_string(),
        );
        ctx.metadata.insert(
            "ai_request_guard.uninspectable_body_action".to_string(),
            action.to_string(),
        );

        if !self.fail_on_uninspectable_body {
            debug!(
                reason,
                action,
                status_code,
                details = %details,
                "ai_request_guard: uninspectable request body allowed by compatibility mode"
            );
            return PluginResult::Continue;
        }

        warn!(
            reason,
            action,
            status_code,
            details = %details,
            "ai_request_guard: rejecting uninspectable request body"
        );
        let client_details = match reason {
            "empty_body" => "JSON request body is empty",
            "non_utf8_body" => "JSON request body is not valid UTF-8",
            "malformed_json" => "Malformed JSON request body",
            _ => "Request body could not be inspected",
        };
        PluginResult::Reject {
            status_code,
            body: serde_json::json!({
                "error": "Request body uninspectable",
                "details": client_details,
            })
            .to_string(),
            headers: HashMap::new(),
        }
    }
}

/// Count total characters in a message's content field.
/// Handles both string content and multimodal array content.
///
/// Counts Unicode scalar values (via `chars().count()`), not UTF-8 byte
/// length, so the value matches the `max_prompt_characters` field name and the
/// "...characters" rejection message. Using `len()` would over-count multibyte
/// input (CJK, emoji, accented Latin) by 2-4x and wrongly reject prompts that
/// are under the operator's character budget.
fn count_message_characters(msg: &Value) -> u64 {
    match msg.get("content") {
        Some(Value::String(s)) => s.chars().count() as u64,
        Some(Value::Array(parts)) => parts
            .iter()
            .filter_map(|part| {
                // Multimodal format: [{"type": "text", "text": "..."}, ...]
                if part.get("type").and_then(|t| t.as_str()) == Some("text") {
                    part.get("text")
                        .and_then(|t| t.as_str())
                        .map(|s| s.chars().count() as u64)
                } else {
                    None
                }
            })
            .sum(),
        _ => 0,
    }
}

#[async_trait]
impl Plugin for AiRequestGuard {
    fn name(&self) -> &str {
        "ai_request_guard"
    }

    fn priority(&self) -> u16 {
        super::priority::AI_REQUEST_GUARD
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
        // Only validate POST requests (AI APIs are always POST)
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

        // Get request body from metadata
        let body = match ctx.metadata.get("request_body") {
            Some(b) if !b.is_empty() => b.as_str(),
            Some(_) => {
                return self.handle_uninspectable_body(
                    ctx,
                    "empty_body",
                    400,
                    "JSON request body is empty and cannot be inspected".to_string(),
                );
            }
            None => {
                let (reason, status_code, details) =
                    if ctx.metadata.contains_key("request_body_size_bytes") {
                        (
                            "non_utf8_body",
                            400,
                            "Request body was buffered but is not valid UTF-8 JSON",
                        )
                    } else {
                        // For matching POST JSON requests, body buffering should
                        // always provide metadata before this hook. Missing metadata
                        // indicates an internal plugin runner inconsistency.
                        (
                            "missing_buffered_body",
                            500,
                            "Buffered request body metadata was unavailable for request inspection",
                        )
                    };
                return self.handle_uninspectable_body(
                    ctx,
                    reason,
                    status_code,
                    details.to_string(),
                );
            }
        };

        // Parse JSON
        let mut json: Value = match serde_json::from_str(body) {
            Ok(v) => v,
            Err(err) => {
                return self.handle_uninspectable_body(
                    ctx,
                    "malformed_json",
                    400,
                    format!("Malformed JSON request body cannot be inspected: {err}"),
                );
            }
        };

        // Run all validation checks
        if let Err((error, details)) = self.validate(&json) {
            debug!(
                "ai_request_guard: validation failed: {} - {}",
                error, details
            );
            return PluginResult::Reject {
                status_code: 400,
                body: serde_json::json!({
                    "error": error,
                    "details": details,
                })
                .to_string(),
                headers: HashMap::new(),
            };
        }

        // Eagerly apply max_tokens transformations so downstream plugins
        // (e.g. ai_federation) see the modified body if they short-circuit
        // before the transform_request_body phase runs.
        let mut body_modified = false;

        // Clamp max_tokens if over limit
        if let Some(limit) = self.max_tokens_limit
            && self.enforce_max_tokens == MaxTokensAction::Clamp
        {
            for field_name in &["max_tokens", "max_output_tokens", "max_completion_tokens"] {
                if let Some(current) = json.get(*field_name).and_then(|v| v.as_u64())
                    && current > limit
                {
                    json[*field_name] = Value::Number(limit.into());
                    body_modified = true;
                }
            }
        }

        // Inject default_max_tokens if not present
        if let Some(default) = self.default_max_tokens
            && json.get("max_tokens").is_none()
            && json.get("max_output_tokens").is_none()
            && json.get("max_completion_tokens").is_none()
            && let Some(obj) = json.as_object_mut()
        {
            obj.insert("max_tokens".to_string(), Value::Number(default.into()));
            body_modified = true;
        }

        if body_modified && let Ok(new_body) = serde_json::to_string(&json) {
            ctx.metadata.insert("request_body".to_string(), new_body);
        }

        PluginResult::Continue
    }

    async fn transform_request_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        _request_headers: &std::collections::HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        // Only transform JSON
        if let Some(ct) = content_type
            && !is_json_content_type(ct)
        {
            return None;
        }

        let mut json: Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(_) => return None,
        };

        let mut modified = false;

        // Clamp max_tokens if over limit
        if let Some(limit) = self.max_tokens_limit
            && self.enforce_max_tokens == MaxTokensAction::Clamp
        {
            for field_name in &["max_tokens", "max_output_tokens", "max_completion_tokens"] {
                if let Some(current) = json.get(*field_name).and_then(|v| v.as_u64())
                    && current > limit
                {
                    json[*field_name] = Value::Number(limit.into());
                    modified = true;
                }
            }
        }

        // Inject default_max_tokens if not present
        if let Some(default) = self.default_max_tokens
            && json.get("max_tokens").is_none()
            && json.get("max_output_tokens").is_none()
            && json.get("max_completion_tokens").is_none()
        {
            json["max_tokens"] = Value::Number(default.into());
            modified = true;
        }

        if modified {
            serde_json::to_vec(&json).ok()
        } else {
            None
        }
    }
}

fn optional_string<'a>(config: &'a Value, field: &'static str) -> Result<Option<&'a str>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_str()
        .map(Some)
        .ok_or_else(|| format!("ai_request_guard: '{field}' must be a string"))
}

fn optional_u64(config: &Value, field: &'static str) -> Result<Option<u64>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_u64()
        .map(Some)
        .ok_or_else(|| format!("ai_request_guard: '{field}' must be an unsigned integer"))
}

fn optional_bool(config: &Value, field: &'static str) -> Result<Option<bool>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| format!("ai_request_guard: '{field}' must be a boolean"))
}

fn optional_string_vec(config: &Value, field: &'static str) -> Result<Option<Vec<String>>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(values) = value.as_array() else {
        return Err(format!("ai_request_guard: '{field}' must be an array"));
    };
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let Some(value) = value.as_str() else {
            return Err(format!(
                "ai_request_guard: '{field}' must contain only strings"
            ));
        };
        out.push(value.to_string());
    }
    Ok(Some(out))
}

fn optional_lowercase_set(
    config: &Value,
    field: &'static str,
) -> Result<Option<HashSet<String>>, String> {
    optional_string_vec(config, field)
        .map(|values| values.map(|values| values.into_iter().map(|s| s.to_lowercase()).collect()))
}

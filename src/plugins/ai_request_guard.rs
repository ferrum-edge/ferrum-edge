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
use tracing::debug;

use super::utils::body_transform::is_json_content_type;
use super::utils::json_escape::escape_json_string;
use super::{Plugin, PluginResult, RequestContext};

const TOP_LEVEL_TOKEN_FIELDS: &[&str] = &[
    "max_tokens",
    "max_output_tokens",
    "max_completion_tokens",
    "max_new_tokens",
    "max_tokens_to_sample",
    "maxOutputTokens",
    "maxTokens",
];

const BUILTIN_SYSTEM_PROMPT_ROLES: &[&str] = &["system", "developer"];

const BUILTIN_SYSTEM_PROMPT_FIELDS: &[&str] = &[
    "instructions",
    "system",
    "systemInstruction",
    "system_instruction",
    "developer",
    "preamble",
];

const TOP_LEVEL_PROMPT_FIELDS: &[&str] = &[
    "prompt",
    "input",
    // TGI / HuggingFace text-generation carries its prompt in the plural
    // `inputs` field. Strict-auto admits these bodies via
    // `looks_like_legacy_completions`, so the prompt-character cap must count
    // them too — otherwise `{"inputs": "<huge prompt>"}` bypasses the limit.
    "inputs",
    // Amazon Titan text-generation carries its prompt in top-level `inputText`
    // (alongside `textGenerationConfig`). Strict-auto admits these bodies via
    // `looks_like_legacy_completions`, so the prompt-character cap must count
    // `inputText` too — otherwise `{"inputText": "<huge prompt>"}` bypasses it.
    "inputText",
    "instructions",
    "system",
    "systemInstruction",
    "system_instruction",
    "message",
    "preamble",
    "context",
];

/// Action to take when max_tokens exceeds the limit.
#[derive(Debug, Clone, PartialEq, Eq)]
enum MaxTokensAction {
    Reject,
    Clamp,
}

/// Request schema family the guard should accept when strict schema checking is enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SupportedSchema {
    ChatCompletions,
    Responses,
    ProviderNative,
    Auto,
}

pub struct AiRequestGuard {
    max_tokens_limit: Option<u64>,
    enforce_max_tokens: MaxTokensAction,
    default_max_tokens: Option<u64>,
    supported_schema: SupportedSchema,
    strict_schema: bool,
    allowed_models: HashSet<String>,
    blocked_models: HashSet<String>,
    require_user_field: bool,
    max_messages: Option<u64>,
    max_prompt_characters: Option<u64>,
    temperature_range: Option<(f64, f64)>,
    block_system_prompts: bool,
    system_prompt_aliases: HashSet<String>,
    required_metadata_fields: Vec<String>,
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
        let supported_schema = match optional_string(config, "supported_schema")?.unwrap_or("auto")
        {
            "chat_completions" => SupportedSchema::ChatCompletions,
            "responses" => SupportedSchema::Responses,
            "provider_native" => SupportedSchema::ProviderNative,
            "auto" => SupportedSchema::Auto,
            other => {
                return Err(format!(
                    "ai_request_guard: 'supported_schema' must be one of 'chat_completions', 'responses', 'provider_native', or 'auto', got: {other:?}"
                ));
            }
        };
        let strict_schema = optional_bool(config, "strict_schema")?.unwrap_or(false);

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
        let system_prompt_aliases =
            optional_lowercase_set(config, "system_prompt_aliases")?.unwrap_or_default();

        let required_metadata_fields =
            optional_string_vec(config, "required_metadata_fields")?.unwrap_or_default();

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
            || strict_schema
            || !required_metadata_fields.is_empty();

        // Reject configs that would make the plugin a no-op: at least one
        // policy must be configured for the plugin to do anything useful.
        if !requires_request_body {
            return Err("ai_request_guard: at least one policy must be configured \
                 (max_tokens_limit, default_max_tokens, allowed_models, blocked_models, \
                 require_user_field, max_messages, max_prompt_characters, \
                 temperature_range, block_system_prompts, strict_schema, or \
                 required_metadata_fields)"
                .to_string());
        }

        Ok(Self {
            max_tokens_limit,
            enforce_max_tokens,
            default_max_tokens,
            supported_schema,
            strict_schema,
            allowed_models,
            blocked_models,
            require_user_field,
            max_messages,
            max_prompt_characters,
            temperature_range,
            block_system_prompts,
            system_prompt_aliases,
            required_metadata_fields,
            needs_body_transform,
            requires_request_body,
        })
    }

    /// Validate the request body JSON. Returns Err with a rejection tuple on failure.
    fn validate(&self, json: &Value) -> Result<(), (String, String)> {
        // Optional schema admission. In non-strict mode, the guard still applies
        // every configured policy to any fields it recognizes, preserving the
        // historical pass-through behavior for unusual provider payloads.
        if self.strict_schema && !schema_matches(json, self.supported_schema) {
            return Err((
                "Unsupported AI request schema".to_string(),
                schema_rejection_details(self.supported_schema),
            ));
        }

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
            let requested = max_requested_tokens(json);
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
        if let Some(max_msgs) = self.max_messages {
            let count = count_message_entries(json);
            if count > max_msgs {
                return Err((
                    "Too many messages".to_string(),
                    format!(
                        "Request contains {} messages, maximum allowed is {}",
                        count, max_msgs
                    ),
                ));
            }
        }

        // Prompt character limit
        if let Some(max_chars) = self.max_prompt_characters {
            let total_chars = count_prompt_characters(json);
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
        if self.block_system_prompts && contains_system_prompt(json, &self.system_prompt_aliases) {
            return Err((
                "System prompts not allowed".to_string(),
                "Requests with system, developer, instructions, or aliased system-prompt fields are blocked by gateway policy"
                    .to_string(),
            ));
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
}

fn schema_matches(json: &Value, supported_schema: SupportedSchema) -> bool {
    match supported_schema {
        SupportedSchema::ChatCompletions => looks_like_chat_completions(json),
        SupportedSchema::Responses => looks_like_responses(json),
        SupportedSchema::ProviderNative => looks_like_provider_native(json),
        SupportedSchema::Auto => {
            looks_like_chat_completions(json)
                || looks_like_responses(json)
                || looks_like_provider_native(json)
                || looks_like_legacy_completions(json)
        }
    }
}

fn schema_rejection_details(supported_schema: SupportedSchema) -> String {
    let expected = match supported_schema {
        SupportedSchema::ChatCompletions => "OpenAI Chat Completions",
        SupportedSchema::Responses => "OpenAI Responses API",
        SupportedSchema::ProviderNative => "provider-native AI",
        SupportedSchema::Auto => "a supported AI",
    };
    format!("Request body does not match {expected} schema coverage")
}

fn looks_like_chat_completions(json: &Value) -> bool {
    json.get("messages").and_then(Value::as_array).is_some()
        && json.get("input").is_none()
        && json.get("instructions").is_none()
        && json.get("contents").is_none()
        && json.get("systemInstruction").is_none()
        && json.get("system_instruction").is_none()
        && json.get("inferenceConfig").is_none()
        && json.get("generationConfig").is_none()
        // Provider-native top-level markers disqualify the body from the OpenAI
        // Chat Completions family even when it also carries a `messages` array
        // (e.g. Anthropic `{"system": ..., "messages": [...]}`, Cohere
        // `preamble`/`message`/`chat_history`, RAG `documents`). In strict
        // `chat_completions` mode these must be rejected rather than admitted as
        // chat schema.
        && json.get("system").is_none()
        && json.get("preamble").is_none()
        && json.get("message").is_none()
        && json.get("chat_history").is_none()
        && json.get("documents").is_none()
        && json.get("retrieved_context").is_none()
        && json.get("tool_results").is_none()
}

fn looks_like_responses(json: &Value) -> bool {
    json.get("input").is_some()
        || json.get("instructions").is_some()
        || json.get("previous_response_id").is_some()
}

fn looks_like_provider_native(json: &Value) -> bool {
    json.get("system").is_some()
        || json.get("systemInstruction").is_some()
        || json.get("system_instruction").is_some()
        || json.get("contents").is_some()
        || json.get("generationConfig").is_some()
        || json.get("inferenceConfig").is_some()
        || json.get("preamble").is_some()
        || json.get("message").is_some()
        || json.get("chat_history").is_some()
        || json.get("documents").is_some()
        || json.get("retrieved_context").is_some()
        || json.get("tool_results").is_some()
        // Amazon Titan text-generation is provider-native: the prompt lives in
        // `inputText` and the output cap in `textGenerationConfig.maxTokenCount`
        // (read by `max_requested_tokens` / `clamp_max_token_fields`). Without
        // these markers a strict `provider_native` config rejects Titan bodies
        // before the documented `textGenerationConfig` reject/clamp logic runs.
        || json.get("inputText").is_some()
        || json.get("textGenerationConfig").is_some()
        // Anthropic Messages and Cohere v2 can be indistinguishable from
        // OpenAI-style chat when they carry only a `messages` array.
        || json.get("messages").and_then(Value::as_array).is_some()
}

/// Recognizes legacy text-completion and text-generation bodies that carry a
/// single prompt string instead of a message array: OpenAI legacy completions
/// (`{"model", "prompt"}`), TGI/HuggingFace text-generation
/// (`{"inputs", "max_new_tokens"}`), and Amazon Titan text-generation
/// (`{"inputText", "textGenerationConfig"}`). `prompt`/`inputs`/`inputText` are
/// in `TOP_LEVEL_PROMPT_FIELDS`, `max_new_tokens`/`max_tokens_to_sample` are
/// honored as token fields, and `textGenerationConfig.maxTokenCount` is read by
/// `max_requested_tokens` / `clamp_max_token_fields`, so strict mode must admit
/// these shapes rather than reject them as unsupported.
fn looks_like_legacy_completions(json: &Value) -> bool {
    json.get("prompt").is_some()
        || json.get("inputs").is_some()
        || json.get("inputText").is_some()
        || json.get("textGenerationConfig").is_some()
}

fn max_requested_tokens(json: &Value) -> Option<u64> {
    let mut requested = None;
    for field in TOP_LEVEL_TOKEN_FIELDS {
        update_max_token(&mut requested, json.get(field).and_then(Value::as_u64));
    }
    update_max_token(
        &mut requested,
        json.get("generationConfig")
            .and_then(|v| v.get("maxOutputTokens"))
            .and_then(Value::as_u64),
    );
    update_max_token(
        &mut requested,
        json.get("inferenceConfig")
            .and_then(|v| v.get("maxTokens"))
            .and_then(Value::as_u64),
    );
    update_max_token(
        &mut requested,
        json.get("textGenerationConfig")
            .and_then(|v| v.get("maxTokenCount"))
            .and_then(Value::as_u64),
    );
    requested
}

fn update_max_token(current: &mut Option<u64>, candidate: Option<u64>) {
    if let Some(candidate) = candidate {
        *current = Some(current.map_or(candidate, |value| value.max(candidate)));
    }
}

/// Whether the request already caps output tokens for the *specific* provider
/// that `default_max_tokens` would be injected into.
///
/// This is deliberately provider-aware rather than schema-agnostic. A previous
/// `has_any_max_token_field` check treated any token-looking top-level field as
/// an existing cap, so a Gemini- or TGI-native body carrying a stray OpenAI
/// `max_tokens` (which those backends ignore) suppressed injection into the
/// real field (`generationConfig.maxOutputTokens` / `max_new_tokens`), silently
/// dropping the documented default cap. We only treat the *target* provider's
/// own output-token field as an existing cap so injection still lands in the
/// field the backend actually honors.
fn target_already_caps_output(json: &Value, target: DefaultTokenTarget) -> bool {
    match target {
        DefaultTokenTarget::Gemini => json
            .get("generationConfig")
            .is_some_and(|v| v.get("maxOutputTokens").is_some()),
        DefaultTokenTarget::Bedrock => json
            .get("inferenceConfig")
            .is_some_and(|v| v.get("maxTokens").is_some()),
        DefaultTokenTarget::TextGeneration => json.get("max_new_tokens").is_some(),
        // OpenAI Chat Completions honors both the legacy `max_tokens` and the
        // newer `max_completion_tokens`; the OpenAI Responses API (which also
        // falls through to `TopLevel` for a bare `{"input", ...}` body) caps
        // output via `max_output_tokens`. Any of these is the real cap for this
        // target, so injecting a separate `max_tokens` would add a redundant —
        // and for Responses, conflicting — parameter.
        DefaultTokenTarget::TopLevel => {
            json.get("max_tokens").is_some()
                || json.get("max_completion_tokens").is_some()
                || json.get("max_output_tokens").is_some()
        }
    }
}

fn clamp_max_token_fields(json: &mut Value, limit: u64) -> bool {
    let mut modified = false;
    if let Some(obj) = json.as_object_mut() {
        for field in TOP_LEVEL_TOKEN_FIELDS {
            modified |= clamp_number_field(obj, field, limit);
        }
    }
    for (container, field) in [
        ("generationConfig", "maxOutputTokens"),
        ("inferenceConfig", "maxTokens"),
        ("textGenerationConfig", "maxTokenCount"),
    ] {
        if let Some(obj) = json.get_mut(container).and_then(Value::as_object_mut) {
            modified |= clamp_number_field(obj, field, limit);
        }
    }
    modified
}

fn clamp_number_field(obj: &mut serde_json::Map<String, Value>, field: &str, limit: u64) -> bool {
    if let Some(current) = obj.get(field).and_then(Value::as_u64)
        && current > limit
    {
        obj.insert(field.to_string(), Value::Number(limit.into()));
        return true;
    }
    false
}

#[derive(Clone, Copy)]
enum DefaultTokenTarget {
    TopLevel,
    Gemini,
    Bedrock,
    TextGeneration,
}

/// Picks the container that `default_max_tokens` is injected into.
///
/// Routing is driven by provider-native marker containers that are already
/// present on the body. A Bedrock Converse body is only recognized when it
/// already carries `inferenceConfig`; a body that omits it — or an Amazon Titan
/// body (`textGenerationConfig.maxTokenCount`) — falls through to `TopLevel` and
/// receives a top-level `max_tokens` those providers ignore. A bare,
/// messages-only Bedrock body is wire-indistinguishable from OpenAI, so this is
/// inherent: we do not provider-sniff. This limitation is documented in the
/// schema-coverage matrix in docs/plugins.md.
///
/// TGI / HuggingFace text-generation bodies (recognized by their top-level
/// `inputs` prompt field) cap output via `max_new_tokens`, so they route to
/// `TextGeneration`; injecting a top-level `max_tokens` there would be ignored
/// by the backend and silently drop the intended default cap.
fn default_token_target(json: &Value) -> DefaultTokenTarget {
    if json.get("generationConfig").is_some()
        || json.get("contents").is_some()
        || json.get("systemInstruction").is_some()
        || json.get("system_instruction").is_some()
    {
        DefaultTokenTarget::Gemini
    } else if json.get("inferenceConfig").is_some() {
        DefaultTokenTarget::Bedrock
    } else if json.get("inputs").is_some() {
        DefaultTokenTarget::TextGeneration
    } else {
        DefaultTokenTarget::TopLevel
    }
}

fn inject_default_max_tokens(json: &mut Value, default: u64) -> bool {
    let target = default_token_target(json);
    // Provider-aware: only suppress injection when the *target* provider already
    // caps output tokens. A token-looking field for a different provider that the
    // target backend ignores must not block the default from landing in the real
    // field.
    if target_already_caps_output(json, target) {
        return false;
    }
    let Some(obj) = json.as_object_mut() else {
        return false;
    };

    match target {
        DefaultTokenTarget::Gemini => {
            let entry = obj
                .entry("generationConfig".to_string())
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
            if let Some(gen_config) = entry.as_object_mut() {
                gen_config.insert("maxOutputTokens".to_string(), Value::Number(default.into()));
                true
            } else {
                false
            }
        }
        DefaultTokenTarget::Bedrock => {
            let entry = obj
                .entry("inferenceConfig".to_string())
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
            if let Some(inference_config) = entry.as_object_mut() {
                inference_config.insert("maxTokens".to_string(), Value::Number(default.into()));
                true
            } else {
                false
            }
        }
        DefaultTokenTarget::TextGeneration => {
            obj.insert("max_new_tokens".to_string(), Value::Number(default.into()));
            true
        }
        DefaultTokenTarget::TopLevel => {
            obj.insert("max_tokens".to_string(), Value::Number(default.into()));
            true
        }
    }
}

fn count_message_entries(json: &Value) -> u64 {
    let mut total = 0u64;
    total = total.saturating_add(count_message_array(json.get("messages")));
    total = total.saturating_add(count_message_array(json.get("input")));
    total = total.saturating_add(count_message_array(json.get("contents")));
    total = total.saturating_add(count_message_array(json.get("chat_history")));
    // Cohere-native requests carry the current user turn in a top-level
    // `message` string (the prior turns live in `chat_history`). Count it as one
    // entry so `max_messages` reflects the full conversation length; without it a
    // request with N `chat_history` entries plus a current `message` is counted
    // as N and slips one message past the cap.
    if json
        .get("message")
        .and_then(Value::as_str)
        .is_some_and(|message| !message.is_empty())
    {
        total = total.saturating_add(1);
    }
    total
}

fn count_message_array(value: Option<&Value>) -> u64 {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter(|item| match item {
                Value::String(_) => true,
                Value::Object(obj) => {
                    !is_typed_non_text_content_part(obj)
                        && (obj.contains_key("role")
                            || obj.contains_key("content")
                            || obj.contains_key("parts")
                            || obj.contains_key("message"))
                }
                _ => false,
            })
            .count() as u64,
        _ => 0,
    }
}

/// Counts Unicode scalar values in model-visible request text, not UTF-8 bytes.
///
/// The extraction mirrors `ai_prompt_shield`'s content-mode coverage for chat
/// messages, Responses `input`/`instructions`, Anthropic top-level `system`,
/// and multimodal text parts. It extends that baseline for policy fields that
/// affect prompt cost/risk: tool definitions, tool-call arguments, and common
/// RAG/document fields. Non-text multimodal parts are intentionally ignored.
fn count_prompt_characters(json: &Value) -> u64 {
    let mut total = 0u64;

    if let Some(messages) = json.get("messages").and_then(Value::as_array) {
        for message in messages {
            count_text_value(message.get("content"), &mut total);
        }
    }

    if let Some(contents) = json.get("contents") {
        count_text_value(Some(contents), &mut total);
    }
    if let Some(chat_history) = json.get("chat_history") {
        count_text_value(Some(chat_history), &mut total);
    }

    for field in TOP_LEVEL_PROMPT_FIELDS {
        count_text_value(json.get(field), &mut total);
    }

    for field in [
        "documents",
        "retrieved_context",
        "tool_results",
        "toolResults",
    ] {
        count_text_value(json.get(field), &mut total);
    }

    count_tool_definition_text(json.get("tools"), &mut total);
    count_tool_definition_text(json.get("functions"), &mut total);
    count_tool_argument_fields(json, &mut total);

    total
}

fn count_text_value(value: Option<&Value>, total: &mut u64) {
    let Some(value) = value else {
        return;
    };
    match value {
        Value::String(text) => add_chars(total, text),
        Value::Array(items) => {
            for item in items {
                count_text_value(Some(item), total);
            }
        }
        Value::Object(obj) => {
            if let Some(part_type) = obj.get("type").and_then(Value::as_str) {
                if is_text_content_part_type(part_type) {
                    count_text_value(obj.get("text").or_else(|| obj.get("content")), total);
                    return;
                }
                // Responses API tool-result items carry model-visible text in
                // `output` (e.g. `{"type": "function_call_output", "output":
                // "..."}`). These are typed non-text parts as far as the content
                // matchers are concerned, so count `output` explicitly before the
                // non-text bailout — otherwise a large tool result re-fed to the
                // model dodges `max_prompt_characters` entirely.
                if part_type == "function_call_output"
                    && let Some(output) = obj.get("output")
                {
                    count_text_value(Some(output), total);
                    return;
                }
                if is_typed_non_text_content_part(obj) {
                    return;
                }
            }
            if let Some(parts) = obj.get("parts") {
                count_text_value(Some(parts), total);
            } else if let Some(content) = obj.get("content") {
                count_text_value(Some(content), total);
            } else if let Some(message) = obj.get("message") {
                count_text_value(Some(message), total);
            } else if let Some(text) = obj.get("text") {
                count_text_value(Some(text), total);
            }
        }
        _ => {}
    }
}

fn is_text_content_part_type(part_type: &str) -> bool {
    matches!(part_type, "text" | "input_text" | "output_text")
}

fn is_typed_non_text_content_part(obj: &serde_json::Map<String, Value>) -> bool {
    obj.get("type")
        .and_then(Value::as_str)
        .is_some_and(|part_type| !is_text_content_part_type(part_type))
        && !obj.contains_key("role")
        && !obj.contains_key("content")
        && !obj.contains_key("parts")
        && !obj.contains_key("message")
}

/// Counts text in tool/function definitions. Only string *values* are counted,
/// mirroring `count_text_value`: JSON-Schema boilerplate keys (`type`,
/// `properties`, `description`, `parameters`, `enum`, ...) describe the tool's
/// structure rather than model-visible prompt text, so counting them would
/// inconsistently inflate `max_prompt_characters` and push otherwise small
/// requests over the limit.
fn count_tool_definition_text(value: Option<&Value>, total: &mut u64) {
    match value {
        Some(Value::String(text)) => add_chars(total, text),
        Some(Value::Array(items)) => {
            for item in items {
                count_tool_definition_text(Some(item), total);
            }
        }
        Some(Value::Object(obj)) => {
            for value in obj.values() {
                count_tool_definition_text(Some(value), total);
            }
        }
        _ => {}
    }
}

/// Counts assistant tool-call argument payloads, scoped to the *legitimate*
/// tool-call locations of the supported schemas rather than any `arguments` key
/// anywhere in the body. Walking the whole tree (the previous behavior) counted
/// unrelated nested `arguments` keys — e.g. `metadata.arguments` or an embedded
/// transcript under `documents` — which is the same arbitrary-nesting
/// false-positive class the system-role scoping (`array_item_has_system_role`)
/// deliberately avoids. Mirroring that structure, we only inspect items of the
/// known message arrays and pull arguments from:
///   * OpenAI Chat Completions: `messages[].tool_calls[].function.arguments`
///   * OpenAI Responses function-call items: `input[].arguments`
///   * Anthropic / Bedrock content blocks: `messages[].content[]` entries of
///     `type: "tool_use"` carrying an `input` arguments object
///   * Gemini: `contents[].parts[]` entries carrying `functionCall.args`
fn count_tool_argument_fields(json: &Value, total: &mut u64) {
    for field in ["messages", "input", "contents", "chat_history"] {
        if let Some(Value::Array(items)) = json.get(field) {
            for item in items {
                count_item_tool_arguments(item, total);
            }
        }
    }
}

fn count_item_tool_arguments(item: &Value, total: &mut u64) {
    let Value::Object(obj) = item else {
        return;
    };

    // OpenAI Responses function-call item: the call lives at the array-item
    // level (`{"type": "function_call", "name": ..., "arguments": "..."}`).
    if let Some(arguments) = obj.get("arguments") {
        count_argument_value(arguments, total);
    }

    // OpenAI Chat Completions assistant message: tool calls are nested under
    // `tool_calls[].function.arguments`.
    if let Some(Value::Array(tool_calls)) = obj.get("tool_calls") {
        for call in tool_calls {
            if let Some(arguments) = call
                .get("function")
                .and_then(|function| function.get("arguments"))
            {
                count_argument_value(arguments, total);
            }
        }
    }

    // Anthropic / Bedrock Converse assistant message: tool calls are typed
    // content blocks (`content[]` entries of `type: "tool_use"` whose `input`
    // object is the model-emitted arguments). Scope to the typed block so an
    // unrelated `input` key elsewhere is not counted.
    if let Some(Value::Array(blocks)) = obj.get("content") {
        for block in blocks {
            if let Value::Object(block_obj) = block
                && block_obj.get("type").and_then(Value::as_str) == Some("tool_use")
                && let Some(input) = block_obj.get("input")
            {
                count_argument_value(input, total);
            }
        }
    }

    // Gemini: tool calls live in `contents[].parts[]` entries carrying a
    // `functionCall` object whose `args` is the arguments payload.
    if let Some(Value::Array(parts)) = obj.get("parts") {
        for part in parts {
            if let Some(args) = part
                .get("functionCall")
                .and_then(|function_call| function_call.get("args"))
            {
                count_argument_value(args, total);
            }
        }
    }
}

fn count_argument_value(value: &Value, total: &mut u64) {
    match value {
        Value::String(text) => add_chars(total, text),
        Value::Array(items) => {
            for item in items {
                count_argument_value(item, total);
            }
        }
        Value::Object(obj) => {
            for value in obj.values() {
                count_argument_value(value, total);
            }
        }
        _ => {}
    }
}

fn add_chars(total: &mut u64, text: &str) {
    *total = total.saturating_add(text.chars().count() as u64);
}

fn contains_system_prompt(json: &Value, aliases: &HashSet<String>) -> bool {
    object_has_system_prompt_field(json, aliases)
        || value_has_system_role(json.get("messages"), aliases)
        || value_has_system_role(json.get("input"), aliases)
        || value_has_system_role(json.get("contents"), aliases)
        || value_has_system_role(json.get("chat_history"), aliases)
}

fn object_has_system_prompt_field(json: &Value, aliases: &HashSet<String>) -> bool {
    let Some(obj) = json.as_object() else {
        return false;
    };

    for field in BUILTIN_SYSTEM_PROMPT_FIELDS {
        if obj.get(*field).is_some_and(|value| !value.is_null()) {
            return true;
        }
    }

    // Default config carries no aliases: the fixed-field check above already
    // covered the work, so skip the per-key lowercase allocation entirely. Only
    // when an operator opts into aliases do we pay the case-insensitive scan.
    !aliases.is_empty()
        && obj
            .iter()
            .any(|(key, value)| !value.is_null() && aliases.contains(key.to_lowercase().as_str()))
}

/// Checks whether any entry of a message/content array carries a system-prompt
/// role. In every supported schema (OpenAI `messages[]`, Responses `input[]`,
/// Gemini `contents[]`, Cohere `chat_history[]`) the role lives at the top of
/// each array item (`role` for OpenAI/Anthropic/Cohere, `author` for some
/// provider shapes), so we inspect only the item level. Recursing into arbitrary
/// nested values would flag any user-supplied data that happens to contain a
/// `role`/`author` key (e.g. an embedded transcript under `metadata`),
/// producing false-positive system-prompt blocks.
fn value_has_system_role(value: Option<&Value>, aliases: &HashSet<String>) -> bool {
    let Some(Value::Array(items)) = value else {
        return false;
    };
    items
        .iter()
        .any(|item| array_item_has_system_role(item, aliases))
}

fn array_item_has_system_role(item: &Value, aliases: &HashSet<String>) -> bool {
    let Value::Object(obj) = item else {
        return false;
    };
    obj.get("role")
        .and_then(Value::as_str)
        .is_some_and(|role| is_system_prompt_role(role, aliases))
        || obj
            .get("author")
            .and_then(Value::as_str)
            .is_some_and(|role| is_system_prompt_role(role, aliases))
}

fn is_system_prompt_role(role: &str, aliases: &HashSet<String>) -> bool {
    let role_lower = role.to_lowercase();
    BUILTIN_SYSTEM_PROMPT_ROLES.contains(&role_lower.as_str())
        || aliases.contains(role_lower.as_str())
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
            _ => return PluginResult::Continue,
        };

        // Parse JSON
        let mut json: Value = match serde_json::from_str(body) {
            Ok(v) => v,
            Err(_) => {
                // Let the backend handle malformed JSON
                return PluginResult::Continue;
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
            body_modified |= clamp_max_token_fields(&mut json, limit);
        }

        // Inject default_max_tokens if not present
        if let Some(default) = self.default_max_tokens {
            body_modified |= inject_default_max_tokens(&mut json, default);
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
            modified |= clamp_max_token_fields(&mut json, limit);
        }

        // Inject default_max_tokens if not present
        if let Some(default) = self.default_max_tokens {
            modified |= inject_default_max_tokens(&mut json, default);
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

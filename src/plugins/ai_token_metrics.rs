//! AI Token Metrics Plugin
//!
//! Parses LLM response bodies to extract token usage metadata (prompt tokens,
//! completion tokens, total tokens, model name) and writes the data to
//! `RequestContext.metadata` so it flows into `TransactionSummary` for
//! downstream logging/observability plugins (stdout_logging, http_logging,
//! prometheus_metrics, otel_tracing).
//!
//! Supports OpenAI, Anthropic, Google Gemini, Cohere, Mistral, and AWS Bedrock
//! response formats. Auto-detection inspects the JSON structure to determine
//! the provider when `provider` is set to `"auto"` (the default).
//!
//! Also supports SSE (Server-Sent Events) streaming responses (`text/event-stream`).
//! For streaming responses, the plugin parses each `data:` line as JSON, extracts
//! the model name from the first chunk, and looks for a final `usage` object in
//! the last chunk (OpenAI sends usage in the final SSE event when
//! `stream_options.include_usage` is set). For Anthropic streaming, the plugin
//! looks for `message_delta` events containing `usage`. For Cohere v2 streaming
//! (`/v2/chat` with `stream: true`), the plugin looks for the `message-end`
//! event which nests counts under `delta.usage.tokens.*`.
//!
//! This plugin is observability-only: it never rejects a request.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tracing::debug;

use super::utils::ai_providers::{
    AiProvider, AiTokenUsage, detect_response_provider, detect_sse_provider,
    extract_response_usage, parse_ai_provider,
};
use super::utils::body_transform::{is_event_stream_content_type, is_json_content_type};
use super::{Plugin, PluginResult, RequestContext};

pub struct AiTokenMetrics {
    provider: String,
    include_model: bool,
    include_token_details: bool,
    provider_key: String,
    total_tokens_key: String,
    prompt_tokens_key: String,
    completion_tokens_key: String,
    model_key: String,
    estimated_cost_key: String,
    streaming_key: String,
    cost_per_prompt_token: Option<f64>,
    cost_per_completion_token: Option<f64>,
}

impl AiTokenMetrics {
    pub fn new(config: &Value) -> Result<Self, String> {
        if !config.is_object() {
            return Err("ai_token_metrics: config must be an object".to_string());
        }

        let provider = match optional_string(config, "provider")? {
            Some(raw) => {
                let provider = raw.trim();
                if provider.is_empty() {
                    return Err("ai_token_metrics: 'provider' must not be empty".to_string());
                }
                provider.to_ascii_lowercase()
            }
            None => "auto".to_string(),
        };
        if provider != "auto" && parse_ai_provider(&provider).is_none() {
            return Err(format!(
                "ai_token_metrics: unknown 'provider' value '{}' (expected auto, openai, anthropic, google, cohere, mistral, or bedrock)",
                provider
            ));
        }

        let include_model = optional_bool(config, "include_model")?.unwrap_or(true);
        let include_token_details = optional_bool(config, "include_token_details")?.unwrap_or(true);
        let metadata_prefix = match optional_string(config, "metadata_prefix")? {
            Some(raw) => {
                let prefix = raw.trim();
                if prefix.is_empty() {
                    return Err("ai_token_metrics: 'metadata_prefix' must not be empty".to_string());
                }
                prefix.to_string()
            }
            None => "ai".to_string(),
        };
        let cost_per_prompt_token = optional_f64(config, "cost_per_prompt_token")?;
        let cost_per_completion_token = optional_f64(config, "cost_per_completion_token")?;

        // Reject negative or non-finite cost rates — they would produce
        // nonsensical (negative or NaN/Inf) cost metrics that pollute
        // observability pipelines and chargeback accounting.
        if let Some(rate) = cost_per_prompt_token
            && (rate < 0.0 || !rate.is_finite())
        {
            return Err(format!(
                "ai_token_metrics: 'cost_per_prompt_token' must be a non-negative finite number, got {rate}"
            ));
        }
        if let Some(rate) = cost_per_completion_token
            && (rate < 0.0 || !rate.is_finite())
        {
            return Err(format!(
                "ai_token_metrics: 'cost_per_completion_token' must be a non-negative finite number, got {rate}"
            ));
        }

        let provider_key = metadata_key(&metadata_prefix, "provider");
        let total_tokens_key = metadata_key(&metadata_prefix, "total_tokens");
        let prompt_tokens_key = metadata_key(&metadata_prefix, "prompt_tokens");
        let completion_tokens_key = metadata_key(&metadata_prefix, "completion_tokens");
        let model_key = metadata_key(&metadata_prefix, "model");
        let estimated_cost_key = metadata_key(&metadata_prefix, "estimated_cost");
        let streaming_key = metadata_key(&metadata_prefix, "streaming");

        Ok(Self {
            provider,
            include_model,
            include_token_details,
            provider_key,
            total_tokens_key,
            prompt_tokens_key,
            completion_tokens_key,
            model_key,
            estimated_cost_key,
            streaming_key,
            cost_per_prompt_token,
            cost_per_completion_token,
        })
    }

    /// Parse an SSE (text/event-stream) response body to extract token usage.
    ///
    /// SSE responses consist of `data: {...}\n\n` lines. The plugin scans for:
    /// - **Model name**: extracted from the first parseable chunk
    /// - **Usage data**: extracted from the final chunk that contains a `usage` object
    ///   (OpenAI sends this when `stream_options.include_usage: true`)
    /// - **Anthropic streaming**: looks for `message_delta` events with `usage`
    fn extract_from_sse(&self, body: &[u8]) -> Option<AiTokenUsage> {
        let body_str = std::str::from_utf8(body).ok()?;

        let mut model: Option<String> = None;
        let mut final_usage: Option<AiTokenUsage> = None;
        let mut detected_provider: Option<AiProvider> = None;

        for line in body_str.lines() {
            let data = if let Some(stripped) = line.strip_prefix("data: ") {
                stripped.trim()
            } else if let Some(stripped) = line.strip_prefix("data:") {
                stripped.trim()
            } else {
                continue;
            };

            // Skip the [DONE] sentinel
            if data == "[DONE]" {
                continue;
            }

            let json: Value = match serde_json::from_str(data) {
                Ok(v) => v,
                Err(_) => continue,
            };

            // Extract model from first chunk that has it
            if model.is_none() {
                model = json.get("model").and_then(|v| v.as_str()).map(String::from);
            }

            // Auto-detect provider from first parseable chunk
            if detected_provider.is_none() {
                if self.provider == "auto" {
                    detected_provider = detect_sse_provider(&json);
                } else {
                    detected_provider = parse_ai_provider(&self.provider);
                }
            }

            // Check for usage data in this chunk
            // OpenAI: final chunk has "usage" object with prompt_tokens/completion_tokens
            if let Some(usage) = json.get("usage")
                && usage.is_object()
                && !usage.as_object().is_some_and(|o| o.is_empty())
            {
                let provider = detected_provider.unwrap_or(AiProvider::OpenAi);
                let mut extracted = extract_response_usage(&json, provider);
                if extracted.model.is_none() {
                    extracted.model = model.clone();
                }
                final_usage = Some(extracted);
            }

            // Anthropic streaming: message_delta event with usage
            if json.get("type").and_then(|t| t.as_str()) == Some("message_delta")
                && json.get("usage").is_some()
            {
                let usage = json.get("usage");
                let output_tokens = usage
                    .and_then(|u| u.get("output_tokens"))
                    .and_then(|v| v.as_u64());
                // message_delta only has output_tokens; input_tokens come from message_start
                if output_tokens.is_some() {
                    let mut u = AiTokenUsage {
                        prompt_tokens: None,
                        completion_tokens: output_tokens,
                        total_tokens: None,
                        model: model.clone(),
                        provider: Some(AiProvider::Anthropic),
                    };
                    // Try to merge with any previously seen input_tokens
                    if let Some(ref prev) = final_usage {
                        u.prompt_tokens = prev.prompt_tokens;
                    }
                    u.total_tokens = match (u.prompt_tokens, u.completion_tokens) {
                        (Some(p), Some(c)) => Some(p.saturating_add(c)),
                        _ => None,
                    };
                    final_usage = Some(u);
                }
            }

            // Anthropic streaming: message_start event with input_tokens
            if json.get("type").and_then(|t| t.as_str()) == Some("message_start")
                && let Some(message) = json.get("message")
            {
                let input_tokens = message
                    .get("usage")
                    .and_then(|u| u.get("input_tokens"))
                    .and_then(|v| v.as_u64());
                if input_tokens.is_some() {
                    let u = AiTokenUsage {
                        prompt_tokens: input_tokens,
                        completion_tokens: None,
                        total_tokens: None,
                        model: message
                            .get("model")
                            .and_then(|v| v.as_str())
                            .map(String::from)
                            .or_else(|| model.clone()),
                        provider: Some(AiProvider::Anthropic),
                    };
                    final_usage = Some(u);
                }
            }

            // Cohere v2 streaming: message-end event nests counts under
            // `delta.usage.tokens.*` instead of root `usage`, so the
            // root-`usage` check above doesn't fire. `extract_cohere_usage`
            // knows how to read both shapes.
            if json.get("type").and_then(|t| t.as_str()) == Some("message-end") {
                let mut extracted = extract_response_usage(&json, AiProvider::Cohere);
                if extracted.prompt_tokens.is_some() || extracted.completion_tokens.is_some() {
                    if extracted.model.is_none() {
                        extracted.model = model.clone();
                    }
                    final_usage = Some(extracted);
                }
            }
        }

        final_usage
    }
    /// Write extracted token usage into the request context metadata.
    fn write_metadata(&self, metadata: &mut HashMap<String, String>, usage: &AiTokenUsage) {
        if let Some(provider) = usage.provider {
            metadata.insert(self.provider_key.clone(), provider.as_str().to_string());
        }

        if let Some(total) = usage.total_tokens {
            metadata.insert(self.total_tokens_key.clone(), total.to_string());
        }

        if self.include_token_details {
            if let Some(prompt) = usage.prompt_tokens {
                metadata.insert(self.prompt_tokens_key.clone(), prompt.to_string());
            }
            if let Some(completion) = usage.completion_tokens {
                metadata.insert(self.completion_tokens_key.clone(), completion.to_string());
            }
        }

        if self.include_model
            && let Some(ref model) = usage.model
        {
            metadata.insert(self.model_key.clone(), model.clone());
        }

        // Calculate estimated cost if at least one cost rate is configured
        if self.cost_per_prompt_token.is_some() || self.cost_per_completion_token.is_some() {
            let prompt_tokens = usage.prompt_tokens.unwrap_or(0) as f64;
            let completion_tokens = usage.completion_tokens.unwrap_or(0) as f64;
            let total_cost = prompt_tokens * self.cost_per_prompt_token.unwrap_or(0.0)
                + completion_tokens * self.cost_per_completion_token.unwrap_or(0.0);
            metadata.insert(
                self.estimated_cost_key.clone(),
                format!("{:.6}", total_cost),
            );
        }
    }
}

fn metadata_key(prefix: &str, suffix: &str) -> String {
    let mut key = String::with_capacity(prefix.len() + 1 + suffix.len());
    key.push_str(prefix);
    key.push('_');
    key.push_str(suffix);
    key
}

fn optional_string<'a>(config: &'a Value, field: &'static str) -> Result<Option<&'a str>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_str()
        .map(Some)
        .ok_or_else(|| format!("ai_token_metrics: '{field}' must be a string"))
}

fn optional_bool(config: &Value, field: &'static str) -> Result<Option<bool>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| format!("ai_token_metrics: '{field}' must be a boolean"))
}

fn optional_f64(config: &Value, field: &'static str) -> Result<Option<f64>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    value
        .as_f64()
        .map(Some)
        .ok_or_else(|| format!("ai_token_metrics: '{field}' must be a number"))
}

#[async_trait]
impl Plugin for AiTokenMetrics {
    fn name(&self) -> &str {
        "ai_token_metrics"
    }

    fn priority(&self) -> u16 {
        super::priority::AI_TOKEN_METRICS
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_GRPC_PROTOCOLS
    }

    fn requires_response_body_buffering(&self) -> bool {
        true
    }

    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        ctx.method.eq_ignore_ascii_case("POST")
    }

    async fn on_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Only record token usage for successful responses. Error bodies
        // (4xx / 5xx) are typically not LLM-shaped JSON and should not
        // pollute token metrics or chargeback accounting.
        if !(200..300).contains(&response_status) {
            debug!(
                "ai_token_metrics: skipping non-2xx response (status {})",
                response_status
            );
            return PluginResult::Continue;
        }

        let content_type = response_headers
            .get("content-type")
            .map(|s| s.as_str())
            .unwrap_or("");

        if body.is_empty() {
            debug!("ai_token_metrics: empty response body, skipping");
            return PluginResult::Continue;
        }

        // Handle SSE streaming responses
        if is_event_stream_content_type(content_type) {
            debug!("ai_token_metrics: parsing SSE streaming response");
            if let Some(usage) = self.extract_from_sse(body) {
                self.write_metadata(&mut ctx.metadata, &usage);
                ctx.metadata
                    .insert(self.streaming_key.clone(), "true".to_string());
            } else {
                debug!("ai_token_metrics: no usage data found in SSE stream");
            }
            return PluginResult::Continue;
        }

        // Handle regular JSON responses
        if !is_json_content_type(content_type) {
            debug!(
                "ai_token_metrics: skipping non-JSON response (content-type: {})",
                content_type
            );
            return PluginResult::Continue;
        }

        // Parse the response body as JSON
        let json: Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => {
                debug!("ai_token_metrics: failed to parse response JSON: {}", e);
                return PluginResult::Continue;
            }
        };

        // Determine the provider
        let provider = if self.provider == "auto" {
            match detect_response_provider(&json) {
                Some(p) => p,
                None => {
                    debug!("ai_token_metrics: could not auto-detect provider from response");
                    return PluginResult::Continue;
                }
            }
        } else {
            match parse_ai_provider(&self.provider) {
                Some(p) => p,
                None => {
                    debug!(
                        "ai_token_metrics: unknown configured provider '{}'",
                        self.provider
                    );
                    return PluginResult::Continue;
                }
            }
        };

        // Extract token usage and write to metadata
        let usage = extract_response_usage(&json, provider);
        self.write_metadata(&mut ctx.metadata, &usage);

        PluginResult::Continue
    }
}

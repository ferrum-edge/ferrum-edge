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
//! looks for `message_delta` events containing `usage`.
//!
//! This plugin is observability-only: it never rejects a request.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tracing::debug;

use super::{Plugin, PluginResult, RequestContext};

/// Detected or configured LLM provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provider {
    OpenAi,
    Anthropic,
    Google,
    Cohere,
    Mistral,
    Bedrock,
}

impl Provider {
    fn as_str(self) -> &'static str {
        match self {
            Provider::OpenAi => "openai",
            Provider::Anthropic => "anthropic",
            Provider::Google => "google",
            Provider::Cohere => "cohere",
            Provider::Mistral => "mistral",
            Provider::Bedrock => "bedrock",
        }
    }
}

/// Extracted token usage data from an LLM response.
#[derive(Debug, Default)]
struct TokenUsage {
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
    total_tokens: Option<u64>,
    model: Option<String>,
    provider: Option<Provider>,
}

pub struct AiTokenMetrics {
    provider: String,
    include_model: bool,
    include_token_details: bool,
    metadata_prefix: String,
    cost_per_prompt_token: Option<f64>,
    cost_per_completion_token: Option<f64>,
}

impl AiTokenMetrics {
    pub fn new(config: &Value) -> Result<Self, String> {
        let provider = config["provider"]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("auto")
            .to_ascii_lowercase();
        let include_model = config["include_model"].as_bool().unwrap_or(true);
        let include_token_details = config["include_token_details"].as_bool().unwrap_or(true);
        let metadata_prefix = config["metadata_prefix"]
            .as_str()
            .unwrap_or("ai")
            .to_string();
        let cost_per_prompt_token = config["cost_per_prompt_token"].as_f64();
        let cost_per_completion_token = config["cost_per_completion_token"].as_f64();

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

        Ok(Self {
            provider,
            include_model,
            include_token_details,
            metadata_prefix,
            cost_per_prompt_token,
            cost_per_completion_token,
        })
    }

    /// Auto-detect the provider from the JSON response structure.
    fn detect_provider(json: &Value) -> Option<Provider> {
        // Google Gemini: usageMetadata.promptTokenCount
        if json
            .get("usageMetadata")
            .and_then(|u| u.get("promptTokenCount"))
            .is_some()
        {
            return Some(Provider::Google);
        }

        // Anthropic: usage.input_tokens
        if json
            .get("usage")
            .and_then(|u| u.get("input_tokens"))
            .is_some()
        {
            return Some(Provider::Anthropic);
        }

        // Cohere: meta.tokens
        if json.get("meta").and_then(|m| m.get("tokens")).is_some() {
            return Some(Provider::Cohere);
        }

        // Bedrock: usage.inputTokens
        if json
            .get("usage")
            .and_then(|u| u.get("inputTokens"))
            .is_some()
        {
            return Some(Provider::Bedrock);
        }

        // OpenAI (and compatible: Mistral, Groq, Together, Azure): usage.prompt_tokens
        if json
            .get("usage")
            .and_then(|u| u.get("prompt_tokens"))
            .is_some()
        {
            return Some(Provider::OpenAi);
        }

        None
    }

    /// Parse the configured provider string into a Provider enum.
    fn parse_configured_provider(provider: &str) -> Option<Provider> {
        match provider {
            "openai" => Some(Provider::OpenAi),
            "anthropic" => Some(Provider::Anthropic),
            "google" => Some(Provider::Google),
            "cohere" => Some(Provider::Cohere),
            "mistral" => Some(Provider::Mistral),
            "bedrock" => Some(Provider::Bedrock),
            _ => None,
        }
    }

    /// Extract token usage from the JSON response based on the provider.
    fn extract_tokens(json: &Value, provider: Provider) -> TokenUsage {
        match provider {
            Provider::OpenAi | Provider::Mistral => Self::extract_openai(json, provider),
            Provider::Anthropic => Self::extract_anthropic(json),
            Provider::Google => Self::extract_google(json),
            Provider::Cohere => Self::extract_cohere(json),
            Provider::Bedrock => Self::extract_bedrock(json),
        }
    }

    fn extract_openai(json: &Value, provider: Provider) -> TokenUsage {
        let usage = json.get("usage");
        let prompt = usage
            .and_then(|u| u.get("prompt_tokens"))
            .and_then(|v| v.as_u64());
        let completion = usage
            .and_then(|u| u.get("completion_tokens"))
            .and_then(|v| v.as_u64());
        let total = usage
            .and_then(|u| u.get("total_tokens"))
            .and_then(|v| v.as_u64())
            .or_else(|| match (prompt, completion) {
                (Some(p), Some(c)) => Some(p.saturating_add(c)),
                _ => None,
            });
        let model = json.get("model").and_then(|v| v.as_str()).map(String::from);

        TokenUsage {
            prompt_tokens: prompt,
            completion_tokens: completion,
            total_tokens: total,
            model,
            provider: Some(provider),
        }
    }

    fn extract_anthropic(json: &Value) -> TokenUsage {
        let usage = json.get("usage");
        let prompt = usage
            .and_then(|u| u.get("input_tokens"))
            .and_then(|v| v.as_u64());
        let completion = usage
            .and_then(|u| u.get("output_tokens"))
            .and_then(|v| v.as_u64());
        let total = match (prompt, completion) {
            (Some(p), Some(c)) => Some(p.saturating_add(c)),
            _ => None,
        };
        let model = json.get("model").and_then(|v| v.as_str()).map(String::from);

        TokenUsage {
            prompt_tokens: prompt,
            completion_tokens: completion,
            total_tokens: total,
            model,
            provider: Some(Provider::Anthropic),
        }
    }

    fn extract_google(json: &Value) -> TokenUsage {
        let usage = json.get("usageMetadata");
        let prompt = usage
            .and_then(|u| u.get("promptTokenCount"))
            .and_then(|v| v.as_u64());
        let completion = usage
            .and_then(|u| u.get("candidatesTokenCount"))
            .and_then(|v| v.as_u64());
        let total = usage
            .and_then(|u| u.get("totalTokenCount"))
            .and_then(|v| v.as_u64())
            .or_else(|| match (prompt, completion) {
                (Some(p), Some(c)) => Some(p.saturating_add(c)),
                _ => None,
            });
        let model = json
            .get("modelVersion")
            .and_then(|v| v.as_str())
            .map(String::from);

        TokenUsage {
            prompt_tokens: prompt,
            completion_tokens: completion,
            total_tokens: total,
            model,
            provider: Some(Provider::Google),
        }
    }

    fn extract_cohere(json: &Value) -> TokenUsage {
        let tokens = json.get("meta").and_then(|m| m.get("tokens"));
        let prompt = tokens
            .and_then(|t| t.get("input_tokens"))
            .and_then(|v| v.as_u64());
        let completion = tokens
            .and_then(|t| t.get("output_tokens"))
            .and_then(|v| v.as_u64());
        let total = match (prompt, completion) {
            (Some(p), Some(c)) => Some(p.saturating_add(c)),
            _ => None,
        };
        let model = json.get("model").and_then(|v| v.as_str()).map(String::from);

        TokenUsage {
            prompt_tokens: prompt,
            completion_tokens: completion,
            total_tokens: total,
            model,
            provider: Some(Provider::Cohere),
        }
    }

    fn extract_bedrock(json: &Value) -> TokenUsage {
        let usage = json.get("usage");
        let prompt = usage
            .and_then(|u| u.get("inputTokens"))
            .and_then(|v| v.as_u64());
        let completion = usage
            .and_then(|u| u.get("outputTokens"))
            .and_then(|v| v.as_u64());
        let total = usage
            .and_then(|u| u.get("totalTokens"))
            .and_then(|v| v.as_u64())
            .or_else(|| match (prompt, completion) {
                (Some(p), Some(c)) => Some(p.saturating_add(c)),
                _ => None,
            });

        TokenUsage {
            prompt_tokens: prompt,
            completion_tokens: completion,
            total_tokens: total,
            model: None,
            provider: Some(Provider::Bedrock),
        }
    }

    /// Parse an SSE (text/event-stream) response body to extract token usage.
    ///
    /// SSE responses consist of `data: {...}\n\n` lines. The plugin scans for:
    /// - **Model name**: extracted from the first parseable chunk
    /// - **Usage data**: extracted from the final chunk that contains a `usage` object
    ///   (OpenAI sends this when `stream_options.include_usage: true`)
    /// - **Anthropic streaming**: looks for `message_delta` events with `usage`
    fn extract_from_sse(&self, body: &[u8]) -> Option<TokenUsage> {
        let body_str = std::str::from_utf8(body).ok()?;

        let mut model: Option<String> = None;
        let mut final_usage: Option<TokenUsage> = None;
        let mut detected_provider: Option<Provider> = None;

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
                    detected_provider = Self::detect_sse_provider(&json);
                } else {
                    detected_provider = Self::parse_configured_provider(&self.provider);
                }
            }

            // Check for usage data in this chunk
            // OpenAI: final chunk has "usage" object with prompt_tokens/completion_tokens
            if let Some(usage) = json.get("usage")
                && usage.is_object()
                && !usage.as_object().is_some_and(|o| o.is_empty())
            {
                let provider = detected_provider.unwrap_or(Provider::OpenAi);
                let mut extracted = Self::extract_tokens(&json, provider);
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
                    let mut u = TokenUsage {
                        prompt_tokens: None,
                        completion_tokens: output_tokens,
                        total_tokens: None,
                        model: model.clone(),
                        provider: Some(Provider::Anthropic),
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
                    let u = TokenUsage {
                        prompt_tokens: input_tokens,
                        completion_tokens: None,
                        total_tokens: None,
                        model: message
                            .get("model")
                            .and_then(|v| v.as_str())
                            .map(String::from)
                            .or_else(|| model.clone()),
                        provider: Some(Provider::Anthropic),
                    };
                    final_usage = Some(u);
                }
            }
        }

        final_usage
    }

    /// Detect provider from an SSE chunk's JSON structure.
    fn detect_sse_provider(json: &Value) -> Option<Provider> {
        // Anthropic SSE: has "type" field like "message_start", "content_block_delta", etc.
        if json.get("type").and_then(|t| t.as_str()).is_some_and(|t| {
            t.starts_with("message") || t.starts_with("content_block") || t == "ping"
        }) {
            return Some(Provider::Anthropic);
        }

        // OpenAI SSE: has "object" field like "chat.completion.chunk"
        if json
            .get("object")
            .and_then(|o| o.as_str())
            .is_some_and(|o| o.contains("chat.completion"))
        {
            return Some(Provider::OpenAi);
        }

        // Google Gemini SSE: has "candidates" array
        if json.get("candidates").is_some() {
            return Some(Provider::Google);
        }

        // Fall back to full detection
        Self::detect_provider(json)
    }

    /// Write extracted token usage into the request context metadata.
    fn write_metadata(&self, metadata: &mut HashMap<String, String>, usage: &TokenUsage) {
        let prefix = &self.metadata_prefix;

        if let Some(provider) = usage.provider {
            metadata.insert(
                format!("{}_provider", prefix),
                provider.as_str().to_string(),
            );
        }

        if let Some(total) = usage.total_tokens {
            metadata.insert(format!("{}_total_tokens", prefix), total.to_string());
        }

        if self.include_token_details {
            if let Some(prompt) = usage.prompt_tokens {
                metadata.insert(format!("{}_prompt_tokens", prefix), prompt.to_string());
            }
            if let Some(completion) = usage.completion_tokens {
                metadata.insert(
                    format!("{}_completion_tokens", prefix),
                    completion.to_string(),
                );
            }
        }

        if self.include_model
            && let Some(ref model) = usage.model
        {
            metadata.insert(format!("{}_model", prefix), model.clone());
        }

        // Calculate estimated cost if at least one cost rate is configured
        if self.cost_per_prompt_token.is_some() || self.cost_per_completion_token.is_some() {
            let prompt_tokens = usage.prompt_tokens.unwrap_or(0) as f64;
            let completion_tokens = usage.completion_tokens.unwrap_or(0) as f64;
            let total_cost = prompt_tokens * self.cost_per_prompt_token.unwrap_or(0.0)
                + completion_tokens * self.cost_per_completion_token.unwrap_or(0.0);
            metadata.insert(
                format!("{}_estimated_cost", prefix),
                format!("{:.6}", total_cost),
            );
        }
    }
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
        // Only buffer for POST requests — AI/LLM API calls that contain token
        // usage data in the response body. We check method only, not request
        // Content-Type, because multipart/form-data uploads (e.g., file inputs
        // to vision models) also return JSON responses with token counts.
        ctx.method == "POST"
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
        if content_type.contains("text/event-stream") || content_type.contains("event-stream") {
            debug!("ai_token_metrics: parsing SSE streaming response");
            if let Some(usage) = self.extract_from_sse(body) {
                self.write_metadata(&mut ctx.metadata, &usage);
                ctx.metadata.insert(
                    format!("{}_streaming", self.metadata_prefix),
                    "true".to_string(),
                );
            } else {
                debug!("ai_token_metrics: no usage data found in SSE stream");
            }
            return PluginResult::Continue;
        }

        // Handle regular JSON responses
        if !content_type.contains("json") {
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
            match Self::detect_provider(&json) {
                Some(p) => p,
                None => {
                    debug!("ai_token_metrics: could not auto-detect provider from response");
                    return PluginResult::Continue;
                }
            }
        } else {
            match Self::parse_configured_provider(&self.provider) {
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
        let usage = Self::extract_tokens(&json, provider);
        self.write_metadata(&mut ctx.metadata, &usage);

        PluginResult::Continue
    }
}

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
    pub fn new(config: &Value) -> Self {
        let provider = config["provider"].as_str().unwrap_or("auto").to_string();
        let include_model = config["include_model"].as_bool().unwrap_or(true);
        let include_token_details = config["include_token_details"].as_bool().unwrap_or(true);
        let metadata_prefix = config["metadata_prefix"]
            .as_str()
            .unwrap_or("ai")
            .to_string();
        let cost_per_prompt_token = config["cost_per_prompt_token"].as_f64();
        let cost_per_completion_token = config["cost_per_completion_token"].as_f64();

        Self {
            provider,
            include_model,
            include_token_details,
            metadata_prefix,
            cost_per_prompt_token,
            cost_per_completion_token,
        }
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
                (Some(p), Some(c)) => Some(p + c),
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
            (Some(p), Some(c)) => Some(p + c),
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
                (Some(p), Some(c)) => Some(p + c),
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
            (Some(p), Some(c)) => Some(p + c),
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
                (Some(p), Some(c)) => Some(p + c),
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

    async fn on_response_body(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Only parse JSON responses
        let content_type = response_headers
            .get("content-type")
            .map(|s| s.as_str())
            .unwrap_or("");
        if !content_type.contains("json") {
            debug!(
                "ai_token_metrics: skipping non-JSON response (content-type: {})",
                content_type
            );
            return PluginResult::Continue;
        }

        if body.is_empty() {
            debug!("ai_token_metrics: empty response body, skipping");
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

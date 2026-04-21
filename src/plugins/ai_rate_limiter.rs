//! AI token-budget rate limiting with shared local/Redis/failover storage.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::time::Instant;
use tracing::{debug, warn};

use super::utils::ai_providers::{
    AiProvider, detect_response_provider, extract_response_usage, parse_ai_provider,
};
use super::utils::rate_limit::{
    AiRateLimitOp, AiTokenRateAlgorithm, RateLimitBackend, RateLimitOutcome,
};
use super::{Plugin, PluginHttpClient, PluginResult, RequestContext};

const MAX_STATE_ENTRIES: usize = 100_000;

pub struct AiRateLimiter {
    token_limit: u64,
    window_seconds: u64,
    count_mode: String,
    limit_by: String,
    expose_headers: bool,
    provider: String,
    limiter: RateLimitBackend<String, AiTokenRateAlgorithm>,
}

impl AiRateLimiter {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let token_limit = config["token_limit"].as_u64().ok_or_else(|| {
            "ai_rate_limiter: 'token_limit' is required (positive integer)".to_string()
        })?;
        if token_limit == 0 {
            return Err("ai_rate_limiter: 'token_limit' must be greater than zero".to_string());
        }

        let window_seconds = config["window_seconds"].as_u64().unwrap_or(60);
        if window_seconds == 0 {
            return Err("ai_rate_limiter: 'window_seconds' must be greater than zero".to_string());
        }

        let count_mode = config["count_mode"]
            .as_str()
            .unwrap_or("total_tokens")
            .to_string();
        if !matches!(
            count_mode.as_str(),
            "prompt_tokens" | "completion_tokens" | "total_tokens"
        ) {
            return Err(format!(
                "ai_rate_limiter: unknown 'count_mode' value '{}' (expected 'prompt_tokens', 'completion_tokens', or 'total_tokens')",
                count_mode
            ));
        }

        let limit_by = config["limit_by"]
            .as_str()
            .unwrap_or("consumer")
            .to_string();
        if !matches!(limit_by.as_str(), "consumer" | "ip") {
            return Err(format!(
                "ai_rate_limiter: unknown 'limit_by' value '{}' (expected 'consumer' or 'ip')",
                limit_by
            ));
        }

        let expose_headers = config["expose_headers"].as_bool().unwrap_or(false);
        let provider = config["provider"]
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("auto")
            .to_ascii_lowercase();

        Ok(Self {
            token_limit,
            window_seconds,
            count_mode,
            limit_by,
            expose_headers,
            provider,
            limiter: RateLimitBackend::from_plugin_config(
                "ai_rate_limiter",
                config,
                &http_client,
                AiTokenRateAlgorithm::new(token_limit, window_seconds),
            ),
        })
    }

    fn rate_key(&self, ctx: &RequestContext) -> String {
        if self.limit_by == "consumer"
            && let Some(identity) = ctx.effective_identity()
        {
            let mut key = String::with_capacity(identity.len() + 9);
            key.push_str("consumer:");
            key.push_str(identity);
            return key;
        }

        let mut key = String::with_capacity(ctx.client_ip.len() + 3);
        key.push_str("ip:");
        key.push_str(&ctx.client_ip);
        key
    }

    fn evict_stale_entries(&self) {
        if self.limiter.tracked_keys_count() > MAX_STATE_ENTRIES {
            self.limiter.retain_active_at(Instant::now());
        }
    }

    fn store_metadata(&self, ctx: &mut RequestContext, outcome: &RateLimitOutcome) {
        if !self.expose_headers {
            return;
        }

        ctx.metadata.insert(
            "ai_ratelimit_limit".to_string(),
            self.token_limit.to_string(),
        );
        ctx.metadata.insert(
            "ai_ratelimit_window".to_string(),
            self.window_seconds.to_string(),
        );
        ctx.metadata.insert(
            "ai_ratelimit_remaining".to_string(),
            outcome.remaining.unwrap_or(0).to_string(),
        );
        ctx.metadata.insert(
            "ai_ratelimit_usage".to_string(),
            outcome.usage.unwrap_or(0).to_string(),
        );
    }

    fn reject(&self, usage: u64) -> PluginResult {
        let mut headers = HashMap::new();
        if self.expose_headers {
            headers.insert(
                "x-ai-ratelimit-limit".to_string(),
                self.token_limit.to_string(),
            );
            headers.insert("x-ai-ratelimit-remaining".to_string(), "0".to_string());
            headers.insert(
                "x-ai-ratelimit-window".to_string(),
                self.window_seconds.to_string(),
            );
            headers.insert("x-ai-ratelimit-usage".to_string(), usage.to_string());
        }

        PluginResult::Reject {
            status_code: 429,
            body: format!(
                r#"{{"error":"AI token rate limit exceeded","details":"Token usage {} exceeds limit {} in window of {} seconds"}}"#,
                usage, self.token_limit, self.window_seconds
            ),
            headers,
        }
    }

    async fn record_usage(&self, key: String, tokens: u64) {
        let _ = self
            .limiter
            .check(key.clone(), &key, &AiRateLimitOp::RecordUsage { tokens })
            .await;
    }

    fn read_tokens_from_metadata(&self, metadata: &HashMap<String, String>) -> Option<u64> {
        let key = match self.count_mode.as_str() {
            "prompt_tokens" => "ai_prompt_tokens",
            "completion_tokens" => "ai_completion_tokens",
            _ => "ai_total_tokens",
        };
        metadata
            .get(key)
            .and_then(|value| value.parse::<u64>().ok())
    }

    fn extract_token_count(&self, body: &[u8]) -> Option<u64> {
        let json: Value = serde_json::from_slice(body).ok()?;
        let usage = if self.provider != "auto" {
            extract_response_usage(&json, parse_ai_provider(&self.provider)?)
        } else {
            extract_response_usage(&json, detect_response_provider(&json)?)
        };
        usage.total_for_mode(&self.count_mode)
    }

    fn extract_token_count_from_sse(&self, body: &[u8]) -> Option<u64> {
        let body = std::str::from_utf8(body).ok()?;
        let mut prompt_tokens: Option<u64> = None;
        let mut completion_tokens: Option<u64> = None;
        let mut total_tokens: Option<u64> = None;

        for line in body.lines() {
            let data = if let Some(stripped) = line.strip_prefix("data: ") {
                stripped.trim()
            } else if let Some(stripped) = line.strip_prefix("data:") {
                stripped.trim()
            } else {
                continue;
            };

            if data == "[DONE]" {
                continue;
            }

            let json: Value = match serde_json::from_str(data) {
                Ok(value) => value,
                Err(_) => continue,
            };

            if let Some(usage) = json.get("usage")
                && usage.is_object()
                && !usage.as_object().is_some_and(|object| object.is_empty())
            {
                let usage = if self.provider != "auto" {
                    extract_response_usage(
                        &json,
                        parse_ai_provider(&self.provider).unwrap_or(AiProvider::OpenAi),
                    )
                } else {
                    extract_response_usage(
                        &json,
                        detect_response_provider(&json).unwrap_or(AiProvider::OpenAi),
                    )
                };
                prompt_tokens = usage.prompt_tokens;
                completion_tokens = usage.completion_tokens;
                total_tokens = usage.total_tokens;
            }

            if json.get("type").and_then(|value| value.as_str()) == Some("message_start")
                && let Some(message) = json.get("message")
                && let Some(usage) = message.get("usage")
            {
                prompt_tokens = usage.get("input_tokens").and_then(|value| value.as_u64());
            }

            if json.get("type").and_then(|value| value.as_str()) == Some("message_delta")
                && let Some(usage) = json.get("usage")
            {
                completion_tokens = usage.get("output_tokens").and_then(|value| value.as_u64());
            }
        }

        if total_tokens.is_none() {
            total_tokens = match (prompt_tokens, completion_tokens) {
                (Some(prompt), Some(completion)) => Some(prompt.saturating_add(completion)),
                (Some(prompt), None) => Some(prompt),
                (None, Some(completion)) => Some(completion),
                (None, None) => None,
            };
        }

        match self.count_mode.as_str() {
            "prompt_tokens" => prompt_tokens.or(Some(0)),
            "completion_tokens" => completion_tokens.or(Some(0)),
            _ => total_tokens,
        }
    }
}

#[async_trait]
impl Plugin for AiRateLimiter {
    fn name(&self) -> &str {
        "ai_rate_limiter"
    }

    fn priority(&self) -> u16 {
        super::priority::AI_RATE_LIMITER
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_GRPC_PROTOCOLS
    }

    fn modifies_request_headers(&self) -> bool {
        self.expose_headers
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.limiter.warmup_hostname().into_iter().collect()
    }

    fn tracked_keys_count(&self) -> Option<usize> {
        Some(self.limiter.tracked_keys_count())
    }

    fn requires_response_body_buffering(&self) -> bool {
        true
    }

    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        ctx.method == "POST"
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        true
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        _headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        self.evict_stale_entries();

        let key = self.rate_key(ctx);
        let outcome = self
            .limiter
            .check(key.clone(), &key, &AiRateLimitOp::CheckBudget)
            .await;

        if !outcome.allowed {
            let usage = outcome.usage.unwrap_or(0);
            warn!(
                rate_limit_key = %key,
                current_tokens = usage,
                limit = self.token_limit,
                plugin = "ai_rate_limiter",
                "AI token rate limit exceeded"
            );
            return self.reject(usage);
        }

        self.store_metadata(ctx, &outcome);
        PluginResult::Continue
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if ctx.metadata.contains_key("ai_federation_provider")
            && let Some(tokens) = self.read_tokens_from_metadata(&ctx.metadata)
        {
            self.record_usage(self.rate_key(ctx), tokens).await;
        }

        if !self.expose_headers {
            return PluginResult::Continue;
        }

        for (meta_key, header_name) in &[
            ("ai_ratelimit_limit", "x-ai-ratelimit-limit"),
            ("ai_ratelimit_remaining", "x-ai-ratelimit-remaining"),
            ("ai_ratelimit_window", "x-ai-ratelimit-window"),
            ("ai_ratelimit_usage", "x-ai-ratelimit-usage"),
        ] {
            if let Some(value) = ctx.metadata.get(*meta_key) {
                response_headers.insert(header_name.to_string(), value.clone());
            }
        }

        PluginResult::Continue
    }

    async fn on_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        if !(200..300).contains(&response_status) {
            debug!(
                "ai_rate_limiter: skipping non-2xx response (status {})",
                response_status
            );
            return PluginResult::Continue;
        }

        let tokens = self.read_tokens_from_metadata(&ctx.metadata).or_else(|| {
            let content_type = response_headers
                .get("content-type")
                .map(String::as_str)
                .unwrap_or("");

            if body.is_empty() {
                return None;
            }

            if content_type.contains("text/event-stream") || content_type.contains("event-stream") {
                return self.extract_token_count_from_sse(body);
            }

            if !content_type.contains("json") {
                return None;
            }

            self.extract_token_count(body)
        });

        let tokens = match tokens {
            Some(tokens) => tokens,
            None => {
                debug!("ai_rate_limiter: could not extract token count from response");
                return PluginResult::Continue;
            }
        };

        self.record_usage(self.rate_key(ctx), tokens).await;
        PluginResult::Continue
    }
}

//! AI Token Rate Limiter Plugin
//!
//! Rate-limits consumers by LLM token consumption rather than request count.
//! A 10-token request and a 50,000-token request shouldn't count the same.
//!
//! Works in two phases:
//! 1. `before_proxy`: Check if consumer/IP is already over the token limit.
//! 2. `on_response_body`: After the response comes back, extract token usage
//!    and accumulate it against the consumer/IP's token budget.
//!
//! Supports OpenAI, Anthropic, Google Gemini, Cohere, Mistral, and AWS Bedrock
//! response formats with auto-detection.

use async_trait::async_trait;
use dashmap::DashMap;
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

use super::{Plugin, PluginResult, RequestContext};

/// A sliding window that tracks token consumption over time.
#[derive(Debug)]
struct TokenWindow {
    /// Timestamped token usage entries: (when, how_many_tokens).
    entries: VecDeque<(Instant, u64)>,
    window_duration: Duration,
    limit: u64,
}

impl TokenWindow {
    fn new(limit: u64, window_duration: Duration) -> Self {
        Self {
            entries: VecDeque::new(),
            window_duration,
            limit,
        }
    }

    /// Evict stale entries and return current token usage within the window.
    fn current_usage(&mut self) -> u64 {
        let now = Instant::now();
        let cutoff = now - self.window_duration;
        while let Some((ts, _)) = self.entries.front() {
            if *ts < cutoff {
                self.entries.pop_front();
            } else {
                break;
            }
        }
        self.entries.iter().map(|(_, tokens)| *tokens).sum()
    }

    /// Record token usage.
    fn record_usage(&mut self, tokens: u64) {
        self.entries.push_back((Instant::now(), tokens));
    }

    /// Tokens remaining before limit is reached.
    fn remaining(&mut self) -> u64 {
        self.limit.saturating_sub(self.current_usage())
    }

    /// Whether there has been any activity in the window.
    fn has_recent_activity(&self, now: Instant) -> bool {
        self.entries
            .back()
            .is_some_and(|(ts, _)| now.duration_since(*ts) < self.window_duration)
    }
}

/// Maximum state entries before triggering eviction.
const MAX_STATE_ENTRIES: usize = 100_000;

pub struct AiRateLimiter {
    token_limit: u64,
    window_seconds: u64,
    count_mode: String,
    limit_by: String,
    expose_headers: bool,
    provider: String,
    state: Arc<DashMap<String, TokenWindow>>,
}

impl AiRateLimiter {
    pub fn new(config: &Value) -> Self {
        let token_limit = config["token_limit"].as_u64().unwrap_or_else(|| {
            tracing::warn!("ai_rate_limiter: 'token_limit' not configured, defaulting to 100000");
            100_000
        });
        let window_seconds = config["window_seconds"].as_u64().unwrap_or(60);
        let count_mode = config["count_mode"]
            .as_str()
            .unwrap_or("total_tokens")
            .to_string();
        let limit_by = config["limit_by"]
            .as_str()
            .unwrap_or("consumer")
            .to_string();
        let expose_headers = config["expose_headers"].as_bool().unwrap_or(false);
        let provider = config["provider"].as_str().unwrap_or("auto").to_string();

        Self {
            token_limit,
            window_seconds,
            count_mode,
            limit_by,
            expose_headers,
            provider,
            state: Arc::new(DashMap::new()),
        }
    }

    /// Build the rate limit key from the request context.
    fn rate_key(&self, ctx: &RequestContext) -> String {
        if self.limit_by == "consumer" {
            if let Some(ref consumer) = ctx.identified_consumer {
                return format!("consumer:{}", consumer.username);
            }
            if let Some(ref identity) = ctx.authenticated_identity {
                return format!("consumer:{}", identity);
            }
        }
        format!("ip:{}", ctx.client_ip)
    }

    /// Evict stale entries to prevent unbounded memory growth.
    fn evict_stale_entries(&self) {
        if self.state.len() <= MAX_STATE_ENTRIES {
            return;
        }
        let now = Instant::now();
        self.state
            .retain(|_, window| window.has_recent_activity(now));
    }

    /// Try to read the token count from metadata written by ai_token_metrics.
    /// This avoids re-parsing the response JSON when both plugins are active
    /// (ai_token_metrics runs at priority 4100, before this plugin at 4200).
    fn read_tokens_from_metadata(&self, metadata: &HashMap<String, String>) -> Option<u64> {
        let key = match self.count_mode.as_str() {
            "prompt_tokens" => "ai_prompt_tokens",
            "completion_tokens" => "ai_completion_tokens",
            _ => "ai_total_tokens",
        };
        metadata.get(key).and_then(|v| v.parse::<u64>().ok())
    }

    /// Extract token count from a response body based on provider and count_mode.
    fn extract_token_count(&self, body: &[u8]) -> Option<u64> {
        let json: Value = serde_json::from_slice(body).ok()?;

        let (prompt, completion, total) = if self.provider != "auto" {
            self.extract_by_provider(&json)?
        } else {
            self.auto_extract(&json)?
        };

        match self.count_mode.as_str() {
            "prompt_tokens" => prompt.or(Some(0)),
            "completion_tokens" => completion.or(Some(0)),
            _ => total.or_else(|| match (prompt, completion) {
                (Some(p), Some(c)) => Some(p + c),
                _ => None,
            }),
        }
    }

    /// Extract tokens using a specific provider format.
    fn extract_by_provider(&self, json: &Value) -> Option<(Option<u64>, Option<u64>, Option<u64>)> {
        match self.provider.as_str() {
            "openai" | "mistral" => Some(Self::extract_openai(json)),
            "anthropic" => Some(Self::extract_anthropic(json)),
            "google" => Some(Self::extract_google(json)),
            "cohere" => Some(Self::extract_cohere(json)),
            "bedrock" => Some(Self::extract_bedrock(json)),
            _ => None,
        }
    }

    /// Auto-detect provider and extract tokens.
    fn auto_extract(&self, json: &Value) -> Option<(Option<u64>, Option<u64>, Option<u64>)> {
        // Google Gemini
        if json
            .get("usageMetadata")
            .and_then(|u| u.get("promptTokenCount"))
            .is_some()
        {
            return Some(Self::extract_google(json));
        }
        // Anthropic
        if json
            .get("usage")
            .and_then(|u| u.get("input_tokens"))
            .is_some()
        {
            return Some(Self::extract_anthropic(json));
        }
        // Cohere
        if json.get("meta").and_then(|m| m.get("tokens")).is_some() {
            return Some(Self::extract_cohere(json));
        }
        // Bedrock
        if json
            .get("usage")
            .and_then(|u| u.get("inputTokens"))
            .is_some()
        {
            return Some(Self::extract_bedrock(json));
        }
        // OpenAI (and compatible)
        if json
            .get("usage")
            .and_then(|u| u.get("prompt_tokens"))
            .is_some()
        {
            return Some(Self::extract_openai(json));
        }
        None
    }

    fn extract_openai(json: &Value) -> (Option<u64>, Option<u64>, Option<u64>) {
        let usage = json.get("usage");
        let prompt = usage
            .and_then(|u| u.get("prompt_tokens"))
            .and_then(|v| v.as_u64());
        let completion = usage
            .and_then(|u| u.get("completion_tokens"))
            .and_then(|v| v.as_u64());
        let total = usage
            .and_then(|u| u.get("total_tokens"))
            .and_then(|v| v.as_u64());
        (prompt, completion, total)
    }

    fn extract_anthropic(json: &Value) -> (Option<u64>, Option<u64>, Option<u64>) {
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
        (prompt, completion, total)
    }

    fn extract_google(json: &Value) -> (Option<u64>, Option<u64>, Option<u64>) {
        let usage = json.get("usageMetadata");
        let prompt = usage
            .and_then(|u| u.get("promptTokenCount"))
            .and_then(|v| v.as_u64());
        let completion = usage
            .and_then(|u| u.get("candidatesTokenCount"))
            .and_then(|v| v.as_u64());
        let total = usage
            .and_then(|u| u.get("totalTokenCount"))
            .and_then(|v| v.as_u64());
        (prompt, completion, total)
    }

    fn extract_cohere(json: &Value) -> (Option<u64>, Option<u64>, Option<u64>) {
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
        (prompt, completion, total)
    }

    fn extract_bedrock(json: &Value) -> (Option<u64>, Option<u64>, Option<u64>) {
        let usage = json.get("usage");
        let prompt = usage
            .and_then(|u| u.get("inputTokens"))
            .and_then(|v| v.as_u64());
        let completion = usage
            .and_then(|u| u.get("outputTokens"))
            .and_then(|v| v.as_u64());
        let total = usage
            .and_then(|u| u.get("totalTokens"))
            .and_then(|v| v.as_u64());
        (prompt, completion, total)
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

    fn requires_response_body_buffering(&self) -> bool {
        true
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        _headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        self.evict_stale_entries();

        let key = self.rate_key(ctx);
        let window_duration = Duration::from_secs(self.window_seconds.max(1));

        let mut entry = self
            .state
            .entry(key.clone())
            .or_insert_with(|| TokenWindow::new(self.token_limit, window_duration));

        let current = entry.current_usage();

        if current >= self.token_limit {
            warn!(
                rate_limit_key = %key,
                current_tokens = current,
                limit = self.token_limit,
                plugin = "ai_rate_limiter",
                "AI token rate limit exceeded"
            );
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
                headers.insert("x-ai-ratelimit-usage".to_string(), current.to_string());
            }
            return PluginResult::Reject {
                status_code: 429,
                body: format!(
                    r#"{{"error":"AI token rate limit exceeded","details":"Token usage {} exceeds limit {} in window of {} seconds"}}"#,
                    current, self.token_limit, self.window_seconds
                ),
                headers,
            };
        }

        // Store rate info in metadata for header injection
        if self.expose_headers {
            let remaining = entry.remaining();
            ctx.metadata.insert(
                "ai_ratelimit_limit".to_string(),
                self.token_limit.to_string(),
            );
            ctx.metadata
                .insert("ai_ratelimit_remaining".to_string(), remaining.to_string());
            ctx.metadata.insert(
                "ai_ratelimit_window".to_string(),
                self.window_seconds.to_string(),
            );
            ctx.metadata
                .insert("ai_ratelimit_usage".to_string(), current.to_string());
        }

        PluginResult::Continue
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !self.expose_headers {
            return PluginResult::Continue;
        }
        // Inject rate limit headers into response
        for (meta_key, header_name) in &[
            ("ai_ratelimit_limit", "x-ai-ratelimit-limit"),
            ("ai_ratelimit_remaining", "x-ai-ratelimit-remaining"),
            ("ai_ratelimit_window", "x-ai-ratelimit-window"),
            ("ai_ratelimit_usage", "x-ai-ratelimit-usage"),
        ] {
            if let Some(val) = ctx.metadata.get(*meta_key) {
                response_headers.insert(header_name.to_string(), val.clone());
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
        // Only count tokens for successful responses
        if !(200..300).contains(&response_status) {
            debug!(
                "ai_rate_limiter: skipping non-2xx response (status {})",
                response_status
            );
            return PluginResult::Continue;
        }

        // Try to read token count from ai_token_metrics metadata first (avoids
        // re-parsing the response JSON when both plugins are active). Falls back
        // to parsing the body directly if metadata isn't available.
        let tokens = self.read_tokens_from_metadata(&ctx.metadata).or_else(|| {
            // Only parse JSON responses
            let content_type = response_headers
                .get("content-type")
                .map(|s| s.as_str())
                .unwrap_or("");
            if !content_type.contains("json") || body.is_empty() {
                return None;
            }
            self.extract_token_count(body)
        });

        let tokens = match tokens {
            Some(t) => t,
            None => {
                debug!("ai_rate_limiter: could not extract token count from response");
                return PluginResult::Continue;
            }
        };

        // Record token usage
        let key = self.rate_key(ctx);
        let window_duration = Duration::from_secs(self.window_seconds.max(1));
        let mut entry = self
            .state
            .entry(key)
            .or_insert_with(|| TokenWindow::new(self.token_limit, window_duration));

        entry.record_usage(tokens);

        PluginResult::Continue
    }
}

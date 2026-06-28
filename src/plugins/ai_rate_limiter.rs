//! AI token-budget rate limiting with shared local/Redis/failover storage.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::time::Instant;
use tracing::{debug, warn};

use super::utils::ai_providers::{
    AiProvider, detect_response_provider, extract_response_usage, parse_ai_provider,
};
use super::utils::body_transform::{is_event_stream_content_type, is_json_content_type};
use super::utils::rate_limit::{
    AiRateLimitOp, AiTokenRateAlgorithm, RateLimitBackend, RateLimitOutcome,
};
use super::{Plugin, PluginHttpClient, PluginResult, RequestContext};

const MAX_STATE_ENTRIES: usize = 100_000;
const RESERVED_TOKENS_METADATA_KEY: &str = "ai_ratelimit_reserved_tokens";
const ACTUAL_TOKENS_METADATA_KEY: &str = "ai_ratelimit_actual_tokens";
const UNMETERED_ACTION_METADATA_KEY: &str = "ai_ratelimit_unmetered_action";
const FEDERATION_TOKENS_RECORDED_METADATA_KEY: &str = "ai_ratelimit_federation_tokens_recorded";
const REJECTION_RESPONSE_METADATA_KEY: &str = "ferrum:rejection_response";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OnUnmeteredResponse {
    Reject,
    ChargeEstimate,
    Warn,
}

impl OnUnmeteredResponse {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "reject" => Some(Self::Reject),
            "charge_estimate" => Some(Self::ChargeEstimate),
            "warn" => Some(Self::Warn),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::ChargeEstimate => "charge_estimate",
            Self::Warn => "warn",
        }
    }
}

pub struct AiRateLimiter {
    token_limit: u64,
    window_seconds: u64,
    count_mode: String,
    limit_by: String,
    expose_headers: bool,
    provider: String,
    on_unmetered_response: OnUnmeteredResponse,
    limiter: RateLimitBackend<String, AiTokenRateAlgorithm>,
}

impl AiRateLimiter {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        if !config.is_object() {
            return Err("ai_rate_limiter: config must be an object".to_string());
        }

        let token_limit = required_u64(config, "token_limit")?;
        if token_limit == 0 {
            return Err("ai_rate_limiter: 'token_limit' must be greater than zero".to_string());
        }

        let window_seconds = optional_u64(config, "window_seconds")?.unwrap_or(60);
        if window_seconds == 0 {
            return Err("ai_rate_limiter: 'window_seconds' must be greater than zero".to_string());
        }

        let count_mode = optional_string(config, "count_mode")?
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

        let limit_by = optional_string(config, "limit_by")?
            .unwrap_or("consumer")
            .to_string();
        if !matches!(limit_by.as_str(), "consumer" | "ip") {
            return Err(format!(
                "ai_rate_limiter: unknown 'limit_by' value '{}' (expected 'consumer' or 'ip')",
                limit_by
            ));
        }

        let expose_headers = optional_bool(config, "expose_headers")?.unwrap_or(false);
        let provider = match optional_string(config, "provider")? {
            Some(raw) => {
                let provider = raw.trim();
                if provider.is_empty() {
                    return Err("ai_rate_limiter: 'provider' must not be empty".to_string());
                }
                provider.to_ascii_lowercase()
            }
            None => "auto".to_string(),
        };
        if provider != "auto" && parse_ai_provider(&provider).is_none() {
            return Err(format!(
                "ai_rate_limiter: unknown 'provider' value '{}' (expected auto, openai, anthropic, google, cohere, mistral, or bedrock)",
                provider
            ));
        }

        let on_unmetered_response = match optional_string(config, "on_unmetered_response")?
            .unwrap_or("charge_estimate")
        {
            value @ ("reject" | "charge_estimate" | "warn") => {
                OnUnmeteredResponse::parse(value).unwrap_or(OnUnmeteredResponse::ChargeEstimate)
            }
            other => {
                return Err(format!(
                    "ai_rate_limiter: unknown 'on_unmetered_response' value '{}' (expected 'reject', 'charge_estimate', or 'warn')",
                    other
                ));
            }
        };

        Ok(Self {
            token_limit,
            window_seconds,
            count_mode,
            limit_by,
            expose_headers,
            provider,
            on_unmetered_response,
            limiter: RateLimitBackend::from_plugin_config(
                "ai_rate_limiter",
                config,
                &http_client,
                AiTokenRateAlgorithm::new(token_limit, window_seconds),
            )?,
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
            // `enforce_capacity` first calls `retain_active_at` to drop
            // entries whose token-usage window has fully expired, then —
            // if the map is still over capacity — forcibly removes
            // additional keys until the hard cap holds. Plain
            // `retain_active_at` is not enough on its own: when traffic
            // is sustained, every tracked key keeps reporting "active"
            // and nothing gets evicted, so the DashMap can grow without
            // bound past `MAX_STATE_ENTRIES`.
            self.limiter
                .enforce_capacity(MAX_STATE_ENTRIES, Instant::now());
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

    fn reject_unmetered(&self) -> PluginResult {
        PluginResult::Reject {
            status_code: 502,
            body: r#"{"error":"AI token usage missing","details":"Successful AI response did not include token usage metadata required by ai_rate_limiter"}"#.to_string(),
            headers: HashMap::new(),
        }
    }

    async fn reserve_usage(&self, key: String, tokens: u64) -> RateLimitOutcome {
        self.limiter
            .check(key.clone(), &key, &AiRateLimitOp::Reserve { tokens })
            .await
    }

    async fn adjust_usage(&self, key: String, delta: i64) {
        if delta == 0 {
            return;
        }
        let _ = self
            .limiter
            .check(key.clone(), &key, &AiRateLimitOp::AdjustUsage { delta })
            .await;
    }

    fn reserved_tokens(ctx: &RequestContext) -> u64 {
        ctx.metadata
            .get(RESERVED_TOKENS_METADATA_KEY)
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0)
    }

    fn should_release_gateway_rejection(ctx: &RequestContext) -> bool {
        ctx.metadata
            .get(REJECTION_RESPONSE_METADATA_KEY)
            .is_some_and(|value| value == "true")
            && Self::reserved_tokens(ctx) > 0
            && ctx
                .metadata
                .get(UNMETERED_ACTION_METADATA_KEY)
                .map(String::as_str)
                != Some(OnUnmeteredResponse::Reject.as_str())
    }

    fn reservation_delta(actual_tokens: u64, reserved_tokens: u64) -> i64 {
        let delta = i128::from(actual_tokens) - i128::from(reserved_tokens);
        delta.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
    }

    fn estimate_request_tokens(&self, ctx: &RequestContext) -> u64 {
        let Some(body) = ctx.metadata.get("request_body") else {
            return 0;
        };
        let Ok(json) = serde_json::from_str::<Value>(body) else {
            return 0;
        };

        self.estimate_request_tokens_from_json(&json)
    }

    fn estimate_request_tokens_from_json(&self, json: &Value) -> u64 {
        let prompt_tokens = estimate_prompt_tokens(json);
        let completion_tokens = requested_completion_tokens(json);
        match self.count_mode.as_str() {
            "prompt_tokens" => prompt_tokens,
            "completion_tokens" => completion_tokens,
            _ => prompt_tokens.saturating_add(completion_tokens),
        }
    }

    async fn reconcile_usage(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        actual_tokens: Option<u64>,
        unmetered_detail: &str,
    ) -> PluginResult {
        let reserved_tokens = Self::reserved_tokens(ctx);

        if let Some(actual_tokens) = actual_tokens {
            ctx.metadata.insert(
                ACTUAL_TOKENS_METADATA_KEY.to_string(),
                actual_tokens.to_string(),
            );
            self.adjust_usage(
                self.rate_key(ctx),
                Self::reservation_delta(actual_tokens, reserved_tokens),
            )
            .await;
            return PluginResult::Continue;
        }

        if !(200..300).contains(&response_status) {
            self.adjust_usage(
                self.rate_key(ctx),
                Self::reservation_delta(0, reserved_tokens),
            )
            .await;
            return PluginResult::Continue;
        }

        match self.on_unmetered_response {
            OnUnmeteredResponse::ChargeEstimate => {
                ctx.metadata.insert(
                    UNMETERED_ACTION_METADATA_KEY.to_string(),
                    OnUnmeteredResponse::ChargeEstimate.as_str().to_string(),
                );
                warn!(
                    provider = %self.provider,
                    count_mode = %self.count_mode,
                    reserved_tokens,
                    detail = %unmetered_detail,
                    "ai_rate_limiter: successful response did not include token usage; keeping pre-request reservation"
                );
                PluginResult::Continue
            }
            OnUnmeteredResponse::Warn => {
                ctx.metadata.insert(
                    UNMETERED_ACTION_METADATA_KEY.to_string(),
                    OnUnmeteredResponse::Warn.as_str().to_string(),
                );
                self.adjust_usage(
                    self.rate_key(ctx),
                    Self::reservation_delta(0, reserved_tokens),
                )
                .await;
                warn!(
                    provider = %self.provider,
                    count_mode = %self.count_mode,
                    reserved_tokens,
                    detail = %unmetered_detail,
                    "ai_rate_limiter: successful response did not include token usage; releasing reservation because on_unmetered_response=warn"
                );
                PluginResult::Continue
            }
            OnUnmeteredResponse::Reject => {
                ctx.metadata.insert(
                    UNMETERED_ACTION_METADATA_KEY.to_string(),
                    OnUnmeteredResponse::Reject.as_str().to_string(),
                );
                warn!(
                    provider = %self.provider,
                    count_mode = %self.count_mode,
                    reserved_tokens,
                    detail = %unmetered_detail,
                    "ai_rate_limiter: rejecting successful response without token usage"
                );
                self.reject_unmetered()
            }
        }
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
        // Whether any usage/token block was actually observed in the stream.
        // Used to distinguish "provider reported the field as 0" (a real count)
        // from "the stream had no recognizable usage block" (unmeasurable) in
        // prompt_tokens/completion_tokens modes.
        let mut saw_usage = false;

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
                saw_usage = true;
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
                saw_usage = true;
                prompt_tokens = usage.get("input_tokens").and_then(|value| value.as_u64());
            }

            if json.get("type").and_then(|value| value.as_str()) == Some("message_delta")
                && let Some(usage) = json.get("usage")
            {
                saw_usage = true;
                completion_tokens = usage.get("output_tokens").and_then(|value| value.as_u64());
            }

            // Cohere v2 streaming: message-end event nests counts under
            // `delta.usage.tokens.*` instead of root `usage`. Reuse
            // `extract_response_usage` so we share Cohere v2's shape logic.
            if json.get("type").and_then(|value| value.as_str()) == Some("message-end") {
                let usage = extract_response_usage(&json, AiProvider::Cohere);
                if usage.prompt_tokens.is_some()
                    || usage.completion_tokens.is_some()
                    || usage.total_tokens.is_some()
                {
                    saw_usage = true;
                }
                if usage.prompt_tokens.is_some() {
                    prompt_tokens = usage.prompt_tokens;
                }
                if usage.completion_tokens.is_some() {
                    completion_tokens = usage.completion_tokens;
                }
                if usage.total_tokens.is_some() {
                    total_tokens = usage.total_tokens;
                }
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

        // Only substitute 0 when a usage block was actually present but the
        // per-mode counter was legitimately reported as absent (treat as 0).
        // When no usage block was seen at all, return None so the caller's
        // None-branch warning fires, matching total_tokens-mode behavior and
        // giving operators a signal that the SSE shape was not understood.
        let zero_if_seen = if saw_usage { Some(0) } else { None };
        match self.count_mode.as_str() {
            "prompt_tokens" => prompt_tokens.or(zero_if_seen),
            "completion_tokens" => completion_tokens.or(zero_if_seen),
            _ => total_tokens,
        }
    }
}

fn requested_completion_tokens(json: &Value) -> u64 {
    ["max_tokens", "max_completion_tokens", "max_output_tokens"]
        .iter()
        .filter_map(|field| json.get(*field).and_then(Value::as_u64))
        .max()
        .unwrap_or(0)
}

fn estimate_prompt_tokens(json: &Value) -> u64 {
    let chars = prompt_character_count(json);
    if chars == 0 { 0 } else { chars.div_ceil(4) }
}

fn prompt_character_count(json: &Value) -> u64 {
    let mut chars = 0_u64;

    if let Some(system) = json.get("system") {
        chars = chars.saturating_add(string_value_character_count(system));
    }
    if let Some(messages) = json.get("messages") {
        chars = chars.saturating_add(string_value_character_count(messages));
    }
    if let Some(prompt) = json.get("prompt") {
        chars = chars.saturating_add(string_value_character_count(prompt));
    }
    if let Some(input) = json.get("input") {
        chars = chars.saturating_add(string_value_character_count(input));
    }
    if let Some(contents) = json.get("contents") {
        chars = chars.saturating_add(string_value_character_count(contents));
    }
    if let Some(tools) = json.get("tools") {
        chars = chars.saturating_add(string_value_character_count(tools));
    }

    if chars == 0 {
        string_value_character_count(json)
    } else {
        chars
    }
}

fn string_value_character_count(value: &Value) -> u64 {
    match value {
        Value::String(value) => value.chars().count() as u64,
        Value::Array(values) => values.iter().fold(0_u64, |acc, value| {
            acc.saturating_add(string_value_character_count(value))
        }),
        Value::Object(values) => values.iter().fold(0_u64, |acc, (key, value)| {
            if matches!(
                key.as_str(),
                "max_tokens" | "max_completion_tokens" | "max_output_tokens"
            ) {
                acc
            } else {
                acc.saturating_add(string_value_character_count(value))
            }
        }),
        _ => 0,
    }
}

fn optional_string<'a>(config: &'a Value, field: &'static str) -> Result<Option<&'a str>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_str()
        .map(Some)
        .ok_or_else(|| format!("ai_rate_limiter: '{field}' must be a string"))
}

fn required_u64(config: &Value, field: &'static str) -> Result<u64, String> {
    let Some(value) = config.get(field) else {
        return Err(format!(
            "ai_rate_limiter: '{field}' is required (positive integer)"
        ));
    };
    value
        .as_u64()
        .ok_or_else(|| format!("ai_rate_limiter: '{field}' must be an unsigned integer"))
}

fn optional_u64(config: &Value, field: &'static str) -> Result<Option<u64>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_u64()
        .map(Some)
        .ok_or_else(|| format!("ai_rate_limiter: '{field}' must be an unsigned integer"))
}

fn optional_bool(config: &Value, field: &'static str) -> Result<Option<bool>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| format!("ai_rate_limiter: '{field}' must be a boolean"))
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

    fn requires_request_body_before_before_proxy(&self) -> bool {
        true
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        ctx.method == "POST"
            && ctx
                .headers
                .get("content-type")
                .is_some_and(|content_type| is_json_content_type(content_type))
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

    fn should_buffer_response_body(&self, _ctx: &RequestContext) -> bool {
        true
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        true
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        _headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        let key = self.rate_key(ctx);
        let reserved_tokens = self.estimate_request_tokens(ctx);
        let outcome = if reserved_tokens > 0 {
            self.reserve_usage(key.clone(), reserved_tokens).await
        } else {
            self.limiter
                .check(key.clone(), &key, &AiRateLimitOp::CheckBudget)
                .await
        };
        // Evict AFTER the check so the current request's key cannot be
        // force-evicted by `enforce_capacity` between insertion and the
        // budget read — that race would let a hot user slip through
        // against a freshly-allocated zero-usage window. Mirrors
        // `rate_limiting.rs::check_rate` ordering.
        self.evict_stale_entries();

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

        if reserved_tokens > 0 {
            ctx.metadata.insert(
                RESERVED_TOKENS_METADATA_KEY.to_string(),
                reserved_tokens.to_string(),
            );
        }
        self.store_metadata(ctx, &outcome);
        PluginResult::Continue
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if ctx.metadata.contains_key("ai_federation_provider") {
            let actual_tokens = self.read_tokens_from_metadata(&ctx.metadata);
            let result = self
                .reconcile_usage(
                    ctx,
                    response_status,
                    actual_tokens,
                    "ai_federation_metadata",
                )
                .await;
            if !matches!(result, PluginResult::Continue) {
                return result;
            }
            ctx.metadata.insert(
                FEDERATION_TOKENS_RECORDED_METADATA_KEY.to_string(),
                "true".to_string(),
            );
        } else if Self::should_release_gateway_rejection(ctx) {
            let result = self
                .reconcile_usage(ctx, 500, None, "gateway_rejection")
                .await;
            if !matches!(result, PluginResult::Continue) {
                return result;
            }
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
        if ctx
            .metadata
            .get(FEDERATION_TOKENS_RECORDED_METADATA_KEY)
            .is_some_and(|value| value == "true")
        {
            return PluginResult::Continue;
        }

        if !(200..300).contains(&response_status) {
            debug!(
                "ai_rate_limiter: skipping non-2xx response (status {})",
                response_status
            );
            return self
                .reconcile_usage(ctx, response_status, None, "non_2xx_response")
                .await;
        }

        let content_type = response_headers
            .get("content-type")
            .map(String::as_str)
            .unwrap_or("");

        let metadata_tokens = self.read_tokens_from_metadata(&ctx.metadata);
        let mut unmetered_detail = "metadata_without_usage";
        let tokens = metadata_tokens.or_else(|| {
            if body.is_empty() {
                unmetered_detail = "empty_body";
                return None;
            }

            if is_event_stream_content_type(content_type) {
                unmetered_detail = "sse_without_usage";
                return self.extract_token_count_from_sse(body);
            }

            if !is_json_content_type(content_type) {
                unmetered_detail = "unsupported_content_type";
                return None;
            }

            unmetered_detail = "json_without_usage";
            self.extract_token_count(body)
        });

        self.reconcile_usage(ctx, response_status, tokens, unmetered_detail)
            .await
    }
}

//! AI token-budget rate limiting with shared local/Redis/failover storage.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
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
/// Base prefix for the per-request idempotency flag that marks a federated
/// synthetic response's tokens as already recorded by `after_proxy` (the sole
/// federation charger — `on_response_body` always skips federation traffic). The
/// flag guards the case where `after_proxy` runs twice for one request (a
/// synthetic 2xx short-circuit followed by a response-body rejection that
/// re-runs the reject hooks). The full key is per-limiter-instance (see
/// [`AiRateLimiter::federation_flag_key`]) so that multiple `ai_rate_limiter`
/// instances on one proxy (e.g. a per-consumer and a per-IP budget) each record
/// the federation tokens against their own window exactly once, instead of the
/// first instance's flag suppressing the others.
const FEDERATION_TOKENS_RECORDED_METADATA_KEY_PREFIX: &str =
    "ai_ratelimit_federation_tokens_recorded";

/// Process-wide monotonic counter used to give every `AiRateLimiter` instance a
/// unique id. The id is folded into [`AiRateLimiter::federation_flag_key`] so the
/// per-request federation idempotency flag is scoped to ONE limiter instance,
/// never to a budget-config fingerprint that two intentionally-separate budgets
/// could share. Mirrors the `INSTANCE_ID_COUNTER` idiom in `openapi_validator`.
static INSTANCE_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct AiRateLimiter {
    token_limit: u64,
    window_seconds: u64,
    count_mode: String,
    limit_by: String,
    expose_headers: bool,
    provider: String,
    /// Per-instance metadata key for the federation-tokens-recorded idempotency
    /// flag. Scoped to this limiter instance via a process-unique id so that two
    /// `ai_rate_limiter` instances — even with byte-identical budget config but
    /// intentionally separate budgets (distinct `sync_mode`/`redis_key_prefix`,
    /// or simply two local instances) — never share the flag. Each instance
    /// records the federation tokens against its own window exactly once.
    federation_flag_key: String,
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

        // Scope the per-request federation idempotency flag to THIS limiter
        // instance via a process-unique id, not to a budget-config fingerprint.
        // Each instance owns its own token window (a separate in-memory map for
        // the local backend, or a distinct `redis_key_prefix` for the centralized
        // backend), so the idempotency flag — which guards against `after_proxy`
        // running twice for ONE request — must be per instance too. A
        // config-derived key would be shared by two limiters with identical
        // budget config that are nonetheless SEPARATE budgets (e.g. different
        // `sync_mode`/`redis_key_prefix`, or just two local instances): the first
        // to run would set the flag and the second would skip `record_usage`,
        // under-counting its own window for `ai_federation` traffic and
        // contradicting the documented per-instance accounting contract. The id
        // keeps the within-request, within-instance dedup semantics intact while
        // never cross-suppressing a sibling instance.
        let instance_id = INSTANCE_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        let federation_flag_key =
            format!("{FEDERATION_TOKENS_RECORDED_METADATA_KEY_PREFIX}:{instance_id}");

        Ok(Self {
            token_limit,
            window_seconds,
            count_mode,
            limit_by,
            expose_headers,
            provider,
            federation_flag_key,
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
        let outcome = self
            .limiter
            .check(key.clone(), &key, &AiRateLimitOp::CheckBudget)
            .await;
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

        self.store_metadata(ctx, &outcome);
        PluginResult::Continue
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // `after_proxy` is the SOLE federation-token charger. It runs exactly
        // once on both response paths — first on the normal path, and LAST on
        // the synthetic short-circuit reject path
        // (`apply_reject_after_proxy_and_synthetic_body_hooks` runs the body
        // hooks first and this hook once afterwards). `on_response_body`
        // deliberately skips recording whenever `ai_federation_provider` is
        // present, so there is no second federation charger to coordinate with.
        //
        // The only remaining double-charge risk is `after_proxy` itself running
        // twice for ONE request (e.g. a synthetic 2xx short-circuit followed by
        // a response-body rejection that re-runs the reject hooks). `record_usage`
        // is additive, so a per-instance idempotency flag (`federation_flag_key`)
        // guards against that: the first run records and sets it, any later run
        // skips. The flag is per limiter instance so multiple `ai_rate_limiter`
        // budgets on one proxy each charge their own window once.
        if !ctx.metadata.contains_key(&self.federation_flag_key)
            && ctx.metadata.contains_key("ai_federation_provider")
            && let Some(tokens) = self.read_tokens_from_metadata(&ctx.metadata)
        {
            self.record_usage(self.rate_key(ctx), tokens).await;
            ctx.metadata
                .insert(self.federation_flag_key.clone(), "true".to_string());
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
        // Federation tokens are charged EXCLUSIVELY by `after_proxy`, never here.
        // `after_proxy` is the single authoritative federation charger: it runs
        // exactly once on both paths — first on the normal response path, and
        // LAST on the synthetic short-circuit reject path
        // (`apply_reject_after_proxy_and_synthetic_body_hooks` runs the body
        // hooks, i.e. this `on_response_body`, FIRST and the reject `after_proxy`
        // hook once afterwards). `record_usage` is additive, so if `on_response_body`
        // also recorded the same `ai_federation` tokens the consumer would be
        // double-charged for one synthetic response (and a *blocked* response
        // could be pushed over the limit). `after_proxy` carries its own
        // per-instance idempotency guard (`federation_flag_key`) for the case
        // where it runs twice for one request, so the only thing this hook must
        // do for federation traffic is stay out of the way.
        if ctx.metadata.contains_key("ai_federation_provider") {
            return PluginResult::Continue;
        }

        // Do not charge tokens for ANY synthetic short-circuit body. A synthetic
        // body is a plugin-generated 2xx that never reached the upstream model
        // (cache hit, dedup replay, `response_mock`, `serverless_function`,
        // `request_termination`, federation, …). All of them flow through
        // `on_response_body` via the `RejectBinary` short-circuit, and the proxy
        // sets `ferrum:synthetic_short_circuit` in `ctx.metadata` for the
        // duration of that body-hook phase (see
        // `apply_synthetic_response_body_hooks`). Without this guard a synthetic
        // body that happens to carry an OpenAI-shaped `usage` block — e.g. a
        // `response_mock` returning a canned chat-completion — would be charged
        // against the window even though no provider tokens were consumed,
        // silently shrinking the user's budget. The synthetic marker is the
        // correct exemption signal precisely BECAUSE it is internal and
        // unspoofable: it is set only on the synthetic path and never on a real
        // backend response, so a backend (or a `response_transformer` rewrite)
        // emitting a `usage` block, an `x-idempotent-replayed`, or any cache
        // header on a genuine model response cannot satisfy it. The earlier
        // cache/replay producers that already charge (or never charge) elsewhere
        // are a strict subset of this set; federation is handled above by
        // `after_proxy`. A FRESH backend response carries no synthetic marker and
        // is charged normally below.
        if ctx
            .metadata
            .contains_key(crate::proxy::SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY)
        {
            debug!(
                "ai_rate_limiter: skipping synthetic short-circuit response (no model tokens consumed)"
            );
            return PluginResult::Continue;
        }

        if !(200..300).contains(&response_status) {
            debug!(
                "ai_rate_limiter: skipping non-2xx response (status {})",
                response_status
            );
            return PluginResult::Continue;
        }

        let content_type = response_headers
            .get("content-type")
            .map(String::as_str)
            .unwrap_or("");

        let tokens = self.read_tokens_from_metadata(&ctx.metadata).or_else(|| {
            if body.is_empty() {
                return None;
            }

            if is_event_stream_content_type(content_type) {
                return self.extract_token_count_from_sse(body);
            }

            if !is_json_content_type(content_type) {
                return None;
            }

            self.extract_token_count(body)
        });

        let tokens = match tokens {
            Some(tokens) => tokens,
            None => {
                // Fail-open on accuracy: a 2xx whose token count we cannot
                // resolve (unrecognized provider/response shape, truncated
                // SSE, or missing usage block) is not charged to the window.
                // Surface at warn so operators can detect which providers /
                // response shapes are being silently missed.
                warn!(
                    provider = %self.provider,
                    content_type = %content_type,
                    count_mode = %self.count_mode,
                    "ai_rate_limiter: could not extract token count from 2xx response; \
                     request not charged to rate-limit window"
                );
                return PluginResult::Continue;
            }
        };

        // Charge the (fresh, non-cached, non-federation) response exactly once.
        // Federation responses already returned above — `after_proxy` is their
        // sole charger — so this records only genuine backend bodies and never
        // touches the federation idempotency flag.
        self.record_usage(self.rate_key(ctx), tokens).await;

        PluginResult::Continue
    }
}

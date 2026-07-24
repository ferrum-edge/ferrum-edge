//! AI Token Metrics Plugin
//!
//! Parses LLM response bodies to extract token usage metadata (prompt tokens,
//! completion tokens, total tokens, model name) and writes the data to
//! `RequestContext.metadata` so it flows into `TransactionSummary` for
//! downstream logging plugins. Prometheus receives the same usage through a
//! private typed snapshot rather than trusting public metadata provenance.
//!
//! Supports OpenAI, Anthropic, Google Gemini, Cohere, Mistral, and AWS Bedrock
//! response formats. Auto-detection inspects the JSON structure to determine
//! the provider when `provider` is set to `"auto"` (the default).
//!
//! Also supports SSE (Server-Sent Events) streaming responses (`text/event-stream`),
//! but only when `buffer_streaming_responses` is explicitly enabled — buffering an
//! SSE stream to extract its final usage event defeats live token delivery, so it
//! is opt-in. By default a streamed request (client `Accept: text/event-stream` or a
//! `stream: true` request another AI plugin flagged) is never buffered, on every
//! backend dispatch path. For streaming responses, the plugin parses each `data:`
//! line as JSON and merges provider cumulative/partial usage snapshots without
//! summing repeated cumulative values. OpenAI Chat Completions and
//! `response.completed`, Anthropic start/delta, Gemini/Vertex usage metadata,
//! and Cohere terminal usage shapes are recognized.
//!
//! This plugin supports HTTP JSON/SSE only. Native gRPC protobuf messages do not
//! have a generic verifiable provider schema and are deliberately excluded.
//!
//! This plugin is observability-only: it never rejects a request.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;

use super::utils::ai_providers::{
    AiProvider, AiTokenUsage, detect_response_provider, detect_sse_provider,
    extract_response_usage, parse_ai_provider,
};
use super::utils::body_transform::{is_event_stream_content_type, is_json_content_type};
use super::utils::content_encoding::{DecodeLimits, decode_content_encoding};
use super::utils::sse::is_sse_request;
use super::{AiCost, AiUsageExport, Plugin, PluginResult, RequestContext};

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
    metadata_prefix: Arc<str>,
    buffer_streaming_responses: bool,
    cost_per_prompt_token: Option<f64>,
    cost_per_completion_token: Option<f64>,
}

const ALLOWED_CONFIG_KEYS: &[&str] = &[
    "provider",
    "include_model",
    "include_token_details",
    "metadata_prefix",
    "buffer_streaming_responses",
    "cost_per_prompt_token",
    "cost_per_completion_token",
];
const MAX_METADATA_PREFIX_LEN: usize = 64;
const MAX_INSPECTION_BYTES: usize = 4 * 1024 * 1024;
const MAX_CUMULATIVE_DECODED_BYTES: usize = 8 * 1024 * 1024;
const MAX_CONTENT_CODINGS: usize = 4;
const MAX_COST_RATE: f64 = 18_446_744_073_709.55;

impl AiTokenMetrics {
    pub fn new(config: &Value) -> Result<Self, String> {
        if !config.is_object() {
            return Err("ai_token_metrics: config must be an object".to_string());
        }
        let object = config
            .as_object()
            .ok_or_else(|| "ai_token_metrics: config must be an object".to_string())?;
        let unknown = object
            .keys()
            .filter(|key| !ALLOWED_CONFIG_KEYS.contains(&key.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        if !unknown.is_empty() {
            return Err(format!(
                "ai_token_metrics: unknown config key(s): {}; allowed keys: {}",
                unknown.join(", "),
                ALLOWED_CONFIG_KEYS.join(", ")
            ));
        }

        let provider = match optional_string(config, "provider")? {
            Some(raw) => {
                if raw.is_empty() {
                    return Err("ai_token_metrics: 'provider' must not be empty".to_string());
                }
                raw.to_string()
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
                if raw.is_empty() {
                    return Err("ai_token_metrics: 'metadata_prefix' must not be empty".to_string());
                }
                if raw.len() > MAX_METADATA_PREFIX_LEN
                    || !raw.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
                    })
                {
                    return Err(format!(
                        "ai_token_metrics: 'metadata_prefix' must be 1-{MAX_METADATA_PREFIX_LEN} ASCII letters, digits, '.', '_' or '-'"
                    ));
                }
                raw.to_string()
            }
            None => "ai".to_string(),
        };
        let cost_per_prompt_token = optional_f64(config, "cost_per_prompt_token")?;
        let cost_per_completion_token = optional_f64(config, "cost_per_completion_token")?;
        let buffer_streaming_responses =
            optional_bool(config, "buffer_streaming_responses")?.unwrap_or(false);

        // Reject negative or non-finite cost rates — they would produce
        // nonsensical (negative or NaN/Inf) cost metrics that pollute
        // observability pipelines and chargeback accounting.
        if let Some(rate) = cost_per_prompt_token
            && (rate < 0.0 || !rate.is_finite() || rate > MAX_COST_RATE)
        {
            return Err(format!(
                "ai_token_metrics: 'cost_per_prompt_token' must be a non-negative finite number no greater than {MAX_COST_RATE}, got {rate}"
            ));
        }
        if let Some(rate) = cost_per_completion_token
            && (rate < 0.0 || !rate.is_finite() || rate > MAX_COST_RATE)
        {
            return Err(format!(
                "ai_token_metrics: 'cost_per_completion_token' must be a non-negative finite number no greater than {MAX_COST_RATE}, got {rate}"
            ));
        }

        let provider_key = metadata_key(&metadata_prefix, "provider");
        let total_tokens_key = metadata_key(&metadata_prefix, "total_tokens");
        let prompt_tokens_key = metadata_key(&metadata_prefix, "prompt_tokens");
        let completion_tokens_key = metadata_key(&metadata_prefix, "completion_tokens");
        let model_key = metadata_key(&metadata_prefix, "model");
        let estimated_cost_key = metadata_key(&metadata_prefix, "estimated_cost");
        let streaming_key = metadata_key(&metadata_prefix, "streaming");

        debug!("ai_token_metrics is HTTP-only; native gRPC protobuf responses are not inspected");

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
            metadata_prefix: Arc::from(metadata_prefix),
            buffer_streaming_responses,
            cost_per_prompt_token,
            cost_per_completion_token,
        })
    }

    /// Whether the request signals a streamed (SSE) response that must not be
    /// buffered: either the client sent `Accept: text/event-stream`, or an
    /// earlier request plugin (e.g. `ai_prompt_shield`) detected `stream: true`
    /// in the request body and set the shared `ai_request_streaming` marker.
    #[inline]
    fn request_prefers_streaming(&self, ctx: &RequestContext) -> bool {
        is_sse_request(ctx)
            || ctx.metadata.get("ai_request_streaming").map(String::as_str) == Some("true")
    }

    /// Parse an SSE (text/event-stream) response body to extract token usage.
    ///
    /// SSE responses consist of `data: {...}\n\n` lines. Supported providers
    /// report cumulative or partial snapshots, so each newer present field
    /// replaces that field while omitted fields retain the earlier value.
    fn extract_from_sse(&self, body: &[u8]) -> Option<AiTokenUsage> {
        let body_str = std::str::from_utf8(body).ok()?;

        let mut model: Option<String> = None;
        let mut final_usage: Option<AiTokenUsage> = None;
        let mut detected_provider: Option<AiProvider> = None;
        let fixed_provider = if self.provider == "auto" {
            None
        } else {
            parse_ai_provider(&self.provider)
        };

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

            let event_type = json.get("type").and_then(Value::as_str);
            // Failed/incomplete Responses events are deliberately not usage
            // authorities. Only response.completed unwraps its Response object.
            let payload = if event_type == Some("response.completed") {
                let Some(response) = json.get("response") else {
                    continue;
                };
                response
            } else if event_type.is_some_and(|kind| kind.starts_with("response.")) {
                continue;
            } else if event_type == Some("message_start") {
                json.get("message").unwrap_or(&json)
            } else {
                &json
            };

            if model.is_none() {
                model = payload
                    .get("model")
                    .or_else(|| payload.get("modelVersion"))
                    .and_then(Value::as_str)
                    .map(String::from);
            }

            let event_provider = fixed_provider
                .or_else(|| detect_sse_provider(payload))
                .or(detected_provider);
            let Some(provider) = event_provider else {
                continue;
            };
            detected_provider.get_or_insert(provider);

            let mut extracted = extract_response_usage(payload, provider);
            if extracted.prompt_tokens.is_none()
                && extracted.completion_tokens.is_none()
                && extracted.total_tokens.is_none()
            {
                continue;
            }
            if extracted.model.is_none() {
                extracted.model = model.clone();
            }
            match &mut final_usage {
                Some(current) => current.merge_cumulative(extracted),
                None => final_usage = Some(extracted),
            }
        }

        final_usage
    }
    fn calculate_cost(
        &self,
        prompt_tokens: Option<u64>,
        completion_tokens: Option<u64>,
    ) -> Option<(f64, AiCost)> {
        let prompt_cost = prompt_tokens
            .zip(self.cost_per_prompt_token)
            .map(|(tokens, rate)| tokens as f64 * rate);
        let completion_cost = completion_tokens
            .zip(self.cost_per_completion_token)
            .map(|(tokens, rate)| tokens as f64 * rate);
        if prompt_cost.is_none() && completion_cost.is_none() {
            return None;
        }

        let total_cost = prompt_cost.unwrap_or(0.0) + completion_cost.unwrap_or(0.0);
        if !total_cost.is_finite() || total_cost > MAX_COST_RATE {
            return None;
        }
        Some((total_cost, AiCost::from_currency_units(total_cost)?))
    }

    fn provider_matches_export(&self, provider: &str) -> bool {
        if self.provider == "auto" {
            return true;
        }
        let family = match provider {
            "openai" | "azure_openai" | "xai" | "deepseek" | "meta_llama" | "hugging_face" => {
                "openai"
            }
            "anthropic" => "anthropic",
            "google" | "google_gemini" | "google_vertex" => "google",
            "cohere" => "cohere",
            "mistral" => "mistral",
            "bedrock" | "aws_bedrock" => "bedrock",
            _ => return false,
        };
        self.provider == family
    }

    /// Apply this instance's configured rates to a trusted federation usage
    /// snapshot. Federation already parsed the provider response and publishes
    /// typed provenance before its synthetic response enters body hooks, so no
    /// public metadata or client-visible body needs to be trusted here.
    fn price_federated_usage(&self, ctx: &mut RequestContext) {
        let Some(mut usage) = ctx.authoritative_ai_usage_export() else {
            return;
        };
        if !self.provider_matches_export(usage.provider) {
            return;
        }
        let Some((total_cost, cost)) =
            self.calculate_cost(usage.prompt_tokens, usage.completion_tokens)
        else {
            return;
        };

        ctx.metadata
            .insert(self.estimated_cost_key.clone(), format!("{total_cost:.6}"));
        usage.prefix = Arc::clone(&self.metadata_prefix);
        usage.cost = Some(cost);
        ctx.stage_ai_usage_export(usage);
    }

    /// Write extracted token usage into the request context metadata.
    fn write_metadata(&self, ctx: &mut RequestContext, usage: &AiTokenUsage) {
        if let Some(provider) = usage.provider {
            ctx.metadata
                .insert(self.provider_key.clone(), provider.as_str().to_string());
        }

        if let Some(total) = usage.total_tokens {
            ctx.metadata
                .insert(self.total_tokens_key.clone(), total.to_string());
        }

        if self.include_token_details {
            if let Some(prompt) = usage.prompt_tokens {
                ctx.metadata
                    .insert(self.prompt_tokens_key.clone(), prompt.to_string());
            }
            if let Some(completion) = usage.completion_tokens {
                ctx.metadata
                    .insert(self.completion_tokens_key.clone(), completion.to_string());
            }
        }

        if self.include_model
            && let Some(ref model) = usage.model
        {
            ctx.metadata.insert(self.model_key.clone(), model.clone());
        }

        // Public per-request metadata retains its six-decimal contract, while
        // the typed export keeps a sub-micro remainder for cumulative metrics.
        let cost = self
            .calculate_cost(usage.prompt_tokens, usage.completion_tokens)
            .map(|(total_cost, cost)| {
                ctx.metadata
                    .insert(self.estimated_cost_key.clone(), format!("{total_cost:.6}"));
                cost
            });
        if let Some(provider) = usage.provider {
            ctx.stage_ai_usage_export(AiUsageExport {
                prefix: Arc::clone(&self.metadata_prefix),
                provider: provider.as_str(),
                prompt_tokens: if self.include_token_details {
                    usage.prompt_tokens
                } else {
                    None
                },
                completion_tokens: if self.include_token_details {
                    usage.completion_tokens
                } else {
                    None
                },
                total_tokens: usage.total_tokens,
                cost,
            });
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

fn header_value<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
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
        super::HTTP_ONLY_PROTOCOLS
    }

    fn requires_response_body_buffering(&self) -> bool {
        true
    }

    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        // The pre-header buffering decision drives EVERY backend dispatch path —
        // including the retry and HTTP/3-backend paths that never
        // consult the header-time `should_buffer_response_body_for_content_type`
        // refinement below. Gate it on the request shape so those paths preserve
        // streaming too, mirroring `ai_response_guard`:
        //
        //   * A client asking for a stream (`Accept: text/event-stream`) or a
        //     request another plugin flagged as `stream: true`
        //     (`ai_request_streaming`) keeps streaming unless the operator opted
        //     into `buffer_streaming_responses`. Otherwise the SSE response would
        //     be collected until `max_response_body_size_bytes` (502) instead of
        //     streaming tokens to the client — the exact regression #1726 fixes.
        if !self.buffer_streaming_responses && self.request_prefers_streaming(ctx) {
            return false;
        }
        true
    }

    fn should_buffer_response_body_for_content_type(
        &self,
        ctx: &RequestContext,
        content_type: Option<&str>,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        self.should_buffer_response_body(ctx)
            && content_type.is_some_and(|ct| {
                if is_event_stream_content_type(ct) {
                    self.buffer_streaming_responses
                } else {
                    is_json_content_type(ct)
                }
            })
    }

    async fn on_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &mut HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Do not record token usage for ANY synthetic short-circuit body. A
        // synthetic body is a plugin-generated 2xx that never reached the
        // upstream model (an `ai_semantic_cache`/`response_caching` hit, a
        // `request_deduplication` replay, `response_mock`, `serverless_function`,
        // `request_termination`, an `ai_federation` synthetic response, …). The
        // feature funnels all of them back through `on_response_body` via the
        // generic synthetic body-hook path, and the proxy sets
        // `ferrum:synthetic_short_circuit` in `ctx.metadata` for the duration of
        // that phase (see `apply_synthetic_response_body_hooks`). Without this
        // guard a synthetic body that happens to carry a provider-shaped `usage`
        // block — e.g. a `response_mock` returning a canned chat-completion, or a
        // cached/replayed model response — would have its token counts and
        // estimated cost written into `ctx.metadata`, polluting token metrics,
        // logging sinks, and chargeback accounting with phantom usage for tokens
        // no provider actually billed. The marker is set only on the synthetic
        // path and never on a real backend response, so it is the correct,
        // unspoofable exemption signal (a backend or `response_transformer`
        // emitting a `usage` block on a genuine model response cannot satisfy
        // it). This mirrors the sibling `ai_rate_limiter` synthetic guard
        // (priority 4200, right after this plugin) — both must agree that a
        // synthetic short-circuit consumed no model tokens. A FRESH backend
        // response carries no synthetic marker and is accounted normally below.
        if ctx
            .metadata
            .contains_key(crate::proxy::SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY)
        {
            self.price_federated_usage(ctx);
            debug!(
                "ai_token_metrics: skipping synthetic short-circuit response (no model tokens consumed)"
            );
            return PluginResult::Continue;
        }

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

        let content_type = header_value(response_headers, "content-type").unwrap_or("");

        // Buffering is a shared response-level decision: another plugin may
        // require an SSE body even when this instance did not opt in. Enforce
        // the local streaming policy again before inspection so a sibling
        // bufferer cannot enable token accounting implicitly.
        if is_event_stream_content_type(content_type) && !self.buffer_streaming_responses {
            debug!("ai_token_metrics: skipping SSE response because stream buffering is disabled");
            return PluginResult::Continue;
        }

        if body.is_empty() {
            debug!("ai_token_metrics: empty response body, skipping");
            return PluginResult::Continue;
        }

        if body.len() > MAX_INSPECTION_BYTES {
            debug!(
                "ai_token_metrics: encoded response body exceeds inspection limit of {} bytes",
                MAX_INSPECTION_BYTES
            );
            return PluginResult::Continue;
        }

        let inspection_body = match decode_content_encoding(
            header_value(response_headers, "content-encoding"),
            body,
            DecodeLimits {
                max_decoded_bytes: MAX_INSPECTION_BYTES,
                max_cumulative_bytes: MAX_CUMULATIVE_DECODED_BYTES,
                max_codings: MAX_CONTENT_CODINGS,
                max_amplification_ratio: 0,
            },
        ) {
            Ok(decoded) => decoded,
            Err(error) => {
                debug!("ai_token_metrics: response content decoding skipped: {error}");
                return PluginResult::Continue;
            }
        };

        // Handle SSE streaming responses
        if is_event_stream_content_type(content_type) {
            debug!("ai_token_metrics: parsing SSE streaming response");
            if let Some(usage) = self.extract_from_sse(&inspection_body) {
                self.write_metadata(ctx, &usage);
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
        let json: Value = match serde_json::from_slice(&inspection_body) {
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
        if usage.prompt_tokens.is_none()
            && usage.completion_tokens.is_none()
            && usage.total_tokens.is_none()
        {
            debug!("ai_token_metrics: provider response contained no valid usage fields");
            return PluginResult::Continue;
        }
        self.write_metadata(ctx, &usage);

        PluginResult::Continue
    }
}

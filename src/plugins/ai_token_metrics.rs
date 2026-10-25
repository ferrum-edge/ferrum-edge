//! AI Token Metrics Plugin
//!
//! Parses LLM response bodies to extract token usage metadata (prompt tokens,
//! completion tokens, total tokens, model name) and writes the data to
//! `RequestContext.metadata` so it flows into `TransactionSummary` for
//! downstream logging plugins. Prometheus receives the same usage through a
//! private typed snapshot rather than trusting public metadata provenance.
//!
//! Supports OpenAI, Anthropic, Google Gemini, Cohere, Mistral, AWS Bedrock, and TGI
//! response formats. Auto-detection inspects the JSON structure to determine
//! the provider when `provider` is set to `"auto"` (the default).
//!
//! Streamed responses (`text/event-stream` and AWS
//! `application/vnd.amazon.eventstream`) are metered by default WITHOUT
//! buffering: a pass-through stream inspector feeds every chunk to the shared
//! bounded [`UsageStreamExtractor`] as it is forwarded, and the terminal
//! stream hook publishes the observed usage exactly once before the
//! transaction is logged. A streamed request (client `Accept:
//! text/event-stream` or a `stream: true` request another AI plugin flagged)
//! is therefore never buffered by default, on every backend dispatch path.
//! Under retries the plugin also confirms release of both stream framings.
//! `buffer_streaming_responses: true` instead collects the complete SSE
//! response before inspection (disabling live delivery); buffered SSE joins
//! each event's `data:` fields as JSON and merges provider cumulative/partial
//! usage snapshots without summing repeated cumulative values. OpenAI Chat
//! Completions and `response.completed`, Anthropic start/delta, Gemini/Vertex
//! usage metadata, and Cohere terminal usage shapes are recognized.
//!
//! When a request is not metered, a bounded `{prefix}_unmetered_reason`
//! metadata value names why (oversized body, decode failure, malformed body,
//! undetected provider, no usage, or a stream that was not inspected or never
//! reported usage), so "zero usage" is distinguishable from "unmetered".
//!
//! This plugin supports HTTP JSON/SSE only. Native gRPC protobuf messages do not
//! have a generic verifiable provider schema and are deliberately excluded.
//!
//! This plugin is observability-only: it never rejects a request.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tracing::{debug, warn};

use super::utils::ai_model_glob::{
    MAX_MODEL_PATTERNS_PER_PROVIDER, is_valid_model_pattern, matches_model_glob,
};
use super::utils::ai_providers::{
    AiProvider, AiTokenUsage, detect_response_provider, detect_sse_provider,
    extract_response_usage, parse_ai_provider,
};
use super::utils::ai_usage_stream::{
    UsageAccumulator, UsageStreamExtractor, UsageStreamFormat, is_aws_event_stream_content_type,
    is_publishable_model_name,
};
use super::utils::body_transform::{is_event_stream_content_type, is_json_content_type};
use super::utils::content_encoding::{DecodeLimits, decode_content_encoding};
use super::utils::sse::{is_sse_request, strip_sse_boms};
use super::{
    AiCost, AiUsageExport, Plugin, PluginResult, RequestContext, ResponseStreamAction,
    ResponseStreamInspector, allocate_response_stream_handoff_id,
};

pub struct AiTokenMetrics {
    provider: String,
    /// `provider` resolved once; `None` for `auto`.
    fixed_provider: Option<AiProvider>,
    include_model: bool,
    include_token_details: bool,
    provider_key: String,
    total_tokens_key: String,
    prompt_tokens_key: String,
    completion_tokens_key: String,
    model_key: String,
    estimated_cost_key: String,
    streaming_key: String,
    unmetered_reason_key: String,
    metadata_prefix: Arc<str>,
    buffer_streaming_responses: bool,
    cost_per_prompt_token: Option<f64>,
    cost_per_completion_token: Option<f64>,
    /// Ordered per-model rate overrides; the first matching glob wins and the
    /// flat rates above apply when none matches.
    model_pricing: Vec<ModelPrice>,
    /// Process-unique key for this instance's response-stream usage handoff.
    stream_usage_handoff_key: u64,
}

/// One `model_pricing` entry: an anchored `*`-only model glob and the rates
/// that replace the flat rates for a matching model. An omitted rate leaves
/// that side unpriced for the matching model.
struct ModelPrice {
    model: String,
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
    "model_pricing",
];
const ALLOWED_MODEL_PRICE_KEYS: &[&str] = &[
    "model",
    "cost_per_prompt_token",
    "cost_per_completion_token",
];
const MAX_METADATA_PREFIX_LEN: usize = 64;
const MAX_INSPECTION_BYTES: usize = 4 * 1024 * 1024;
const MAX_CUMULATIVE_DECODED_BYTES: usize = 8 * 1024 * 1024;
const MAX_CONTENT_CODINGS: usize = 4;
const MAX_COST_RATE: f64 = 18_446_744_073_709.55;

/// Fixed `{prefix}_unmetered_reason` vocabulary. Only a 2xx, non-synthetic
/// response whose representation could carry provider usage is labelled, so
/// the key distinguishes "unmetered" from "zero usage" without tagging
/// unrelated traffic.
const UNMETERED_BODY_TOO_LARGE: &str = "body_too_large";
const UNMETERED_DECODE_FAILED: &str = "decode_failed";
const UNMETERED_MALFORMED_BODY: &str = "malformed_body";
const UNMETERED_PROVIDER_UNDETECTED: &str = "provider_undetected";
const UNMETERED_NO_USAGE: &str = "no_usage";
const UNMETERED_STREAM_NOT_INSPECTED: &str = "stream_not_inspected";
const UNMETERED_STREAM_WITHOUT_USAGE: &str = "stream_without_usage";

/// Process-wide ceiling on concurrently observed response streams.
///
/// Each observer retains one bounded parser carry plus a fixed-size
/// accumulator, so this caps their AGGREGATE retention. Beyond it no observer
/// attaches: the response still streams untouched and is labelled
/// `stream_not_inspected`. The cap is separate from `ai_rate_limiter`'s, so
/// observability saturation can never change enforcement accounting.
const MAX_CONCURRENT_STREAM_OBSERVATIONS: usize = 4_096;
static ACTIVE_STREAM_OBSERVATIONS: AtomicUsize = AtomicUsize::new(0);
/// Cumulative refusals at that ceiling, used only to sample the warning.
static STREAM_OBSERVATION_REFUSALS: AtomicU64 = AtomicU64::new(0);
const STREAM_OBSERVATION_REFUSAL_LOG_INTERVAL: u64 = 1024;

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
                "ai_token_metrics: unknown config key(s): {:?}; allowed keys: `{}`",
                unknown.join(", "),
                ALLOWED_CONFIG_KEYS.join("`, `")
            ));
        }

        let provider = match optional_string(config, "provider")? {
            Some(raw) => {
                if raw.is_empty() {
                    return Err("ai_token_metrics: `provider` must not be empty".to_string());
                }
                raw.to_string()
            }
            None => "auto".to_string(),
        };
        if provider != "auto" && parse_ai_provider(&provider).is_none() {
            return Err(format!(
                "ai_token_metrics: unknown `provider` value {:?} (expected `auto`, `openai`, `anthropic`, `google`, `cohere`, `mistral`, `bedrock`, or `tgi`)",
                provider
            ));
        }

        let include_model = optional_bool(config, "include_model")?.unwrap_or(true);
        let include_token_details = optional_bool(config, "include_token_details")?.unwrap_or(true);
        let metadata_prefix = match optional_string(config, "metadata_prefix")? {
            Some(raw) => {
                if raw.is_empty() {
                    return Err("ai_token_metrics: `metadata_prefix` must not be empty".to_string());
                }
                if raw.len() > MAX_METADATA_PREFIX_LEN
                    || !raw.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
                    })
                {
                    return Err(format!(
                        "ai_token_metrics: `metadata_prefix` must be 1-{MAX_METADATA_PREFIX_LEN} ASCII letters, digits, `.`, `_` or `-`"
                    ));
                }
                raw.to_string()
            }
            None => "ai".to_string(),
        };
        let cost_per_prompt_token = cost_rate(config, "cost_per_prompt_token", "")?;
        let cost_per_completion_token = cost_rate(config, "cost_per_completion_token", "")?;
        let buffer_streaming_responses =
            optional_bool(config, "buffer_streaming_responses")?.unwrap_or(false);
        let model_pricing = parse_model_pricing(config)?;

        let provider_key = metadata_key(&metadata_prefix, "provider");
        let total_tokens_key = metadata_key(&metadata_prefix, "total_tokens");
        let prompt_tokens_key = metadata_key(&metadata_prefix, "prompt_tokens");
        let completion_tokens_key = metadata_key(&metadata_prefix, "completion_tokens");
        let model_key = metadata_key(&metadata_prefix, "model");
        let estimated_cost_key = metadata_key(&metadata_prefix, "estimated_cost");
        let streaming_key = metadata_key(&metadata_prefix, "streaming");
        let unmetered_reason_key = metadata_key(&metadata_prefix, "unmetered_reason");
        let fixed_provider = parse_ai_provider(&provider);

        debug!("ai_token_metrics is HTTP-only; native gRPC protobuf responses are not inspected");

        Ok(Self {
            provider,
            fixed_provider,
            include_model,
            include_token_details,
            provider_key,
            total_tokens_key,
            prompt_tokens_key,
            completion_tokens_key,
            model_key,
            estimated_cost_key,
            streaming_key,
            unmetered_reason_key,
            metadata_prefix: Arc::from(metadata_prefix),
            buffer_streaming_responses,
            cost_per_prompt_token,
            cost_per_completion_token,
            model_pricing,
            stream_usage_handoff_key: allocate_response_stream_handoff_id(),
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
    /// LF, CRLF, and CR delimit lines; a blank line dispatches the joined data
    /// fields of one event, and the end of the body dispatches a final event
    /// whose terminating blank line the provider omitted (as the shared
    /// streaming extractor does). Leading BOMs are stripped by the shared SSE
    /// policy. Only one event is retained at a time, bounded by the decoded
    /// body's inspection limit. Supported providers report cumulative or
    /// partial snapshots, so each newer present field replaces that field while
    /// omitted fields retain the earlier value.
    fn extract_from_sse(&self, body: &[u8]) -> Option<AiTokenUsage> {
        let body_str = std::str::from_utf8(body).ok()?;
        let body_str = strip_sse_boms(body_str);

        let mut model: Option<String> = None;
        let mut final_usage: Option<AiTokenUsage> = None;
        let mut detected_provider: Option<AiProvider> = None;
        let fixed_provider = self.fixed_provider;

        let mut event_data = String::new();
        let mut skip_lf = false;
        // The trailing empty line is a synthetic end-of-body dispatch. After a
        // properly terminated final event it finds no pending data.
        for raw_line in body_str
            .split_inclusive(['\r', '\n'])
            .chain(std::iter::once(""))
        {
            // CRLF is one line ending, not an intervening blank line.
            if skip_lf && raw_line == "\n" {
                skip_lf = false;
                continue;
            }
            skip_lf = raw_line.ends_with('\r');
            let line = raw_line.trim_end_matches(['\r', '\n']);
            if !line.is_empty() {
                let data = match line.split_once(':') {
                    Some(("data", value)) => value.strip_prefix(' ').unwrap_or(value),
                    None if line == "data" => "",
                    _ => continue,
                };
                event_data.push_str(data);
                event_data.push('\n');
                continue;
            }

            // Empty data, [DONE], and malformed events carry no usage. Clear
            // the event before continuing so unrelated events never combine.
            let data = event_data.trim();
            if data.is_empty() || data == "[DONE]" {
                event_data.clear();
                continue;
            }
            let parsed = serde_json::from_str::<Value>(data);
            event_data.clear();
            let json = match parsed {
                Ok(v) => v,
                Err(_) => continue,
            };

            let event_type = json.get("type").and_then(Value::as_str);
            // Failed and in-progress Responses events are deliberately not usage
            // authorities. The two terminal events — `response.completed` and
            // `response.incomplete` (a finished response that stopped early and
            // still bills what it reports) — unwrap their Response object.
            let payload = if matches!(
                event_type,
                Some("response.completed" | "response.incomplete")
            ) {
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
                    .filter(|candidate| is_publishable_model_name(candidate))
                    .map(String::from);
            }

            // An Anthropic Messages event is authoritative by its own shape
            // (as in the shared streaming accumulator), even under a
            // configured provider such as `bedrock` that wraps it; otherwise
            // its usage, cache categories included, would be parsed as the
            // wrapper's and lost.
            let anthropic_event = event_type.is_some_and(|kind| {
                kind.starts_with("message_") || kind.starts_with("content_block_")
            });
            let event_provider = if anthropic_event {
                Some(AiProvider::Anthropic)
            } else {
                fixed_provider
                    .or_else(|| detect_sse_provider(payload))
                    .or(detected_provider)
            };
            let Some(provider) = event_provider else {
                continue;
            };
            detected_provider.get_or_insert(provider);

            // `message_start` carries only the authoritative input side; its
            // `output_tokens` is a placeholder the terminal delta supersedes.
            // The event's own usage carrier first (with the `message_start`
            // output placeholder dropped), then any co-located Bedrock
            // invocation metrics, each merged independently exactly as the
            // shared streaming accumulator does.
            let native = if event_type == Some("message_start") && provider == AiProvider::Anthropic
            {
                let carrier =
                    crate::plugins::utils::ai_providers::anthropic_message_start_usage(payload);
                extract_response_usage(&carrier, provider)
            } else {
                extract_response_usage(payload, provider)
            };
            let mut snapshots = vec![native];
            if provider != AiProvider::Bedrock
                && let Some(mut metrics) =
                    crate::plugins::utils::ai_providers::extract_bedrock_invocation_metrics(payload)
            {
                // Bedrock's terminal metrics fold in the same layout as the
                // Anthropic events they follow; keep the stream's provider so
                // `merge_cumulative` merges them instead of refusing the switch.
                metrics.provider = Some(provider);
                snapshots.push(metrics);
            }
            // A standalone invocation-metrics event detects as Bedrock, but it
            // continues the stream already identified; keep that identity so
            // `merge_cumulative` merges it (same category layout).
            if fixed_provider.is_none()
                && payload.get("amazon-bedrock-invocationMetrics").is_some()
                && let Some(established) = final_usage.as_ref().and_then(|usage| usage.provider)
            {
                for snapshot in &mut snapshots {
                    snapshot.provider = Some(established);
                }
            }
            // The wire parser follows the event's shape, but the exported
            // identity follows an explicit configuration: wrapped events under
            // `provider: bedrock` stay labelled Bedrock.
            if fixed_provider == Some(AiProvider::Bedrock) {
                for snapshot in &mut snapshots {
                    snapshot.provider = Some(AiProvider::Bedrock);
                }
            }
            for mut extracted in snapshots {
                // A category-bearing snapshot is merged even when it folds to no
                // counter: a malformed (or cache-only) update must still reach
                // `merge_cumulative` to invalidate (or extend) the running state.
                if extracted.prompt_tokens.is_none()
                    && extracted.completion_tokens.is_none()
                    && extracted.total_tokens.is_none()
                    && extracted.categories
                        == crate::plugins::utils::ai_providers::UsageCategories::default()
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
        }

        final_usage
    }

    /// The `(prompt, completion)` rates for a response: the first
    /// `model_pricing` entry whose glob matches the publishable model, else the
    /// flat rates.
    fn rates_for_model(&self, model: Option<&str>) -> (Option<f64>, Option<f64>) {
        if let Some(model) = model.filter(|model| is_publishable_model_name(model))
            && let Some(price) = self
                .model_pricing
                .iter()
                .find(|price| matches_model_glob(&price.model, model))
        {
            return (price.cost_per_prompt_token, price.cost_per_completion_token);
        }
        (self.cost_per_prompt_token, self.cost_per_completion_token)
    }

    fn calculate_cost(
        &self,
        prompt_tokens: Option<u64>,
        completion_tokens: Option<u64>,
        model: Option<&str>,
    ) -> Option<(f64, AiCost)> {
        let (prompt_rate, completion_rate) = self.rates_for_model(model);
        let prompt_cost = prompt_tokens
            .zip(prompt_rate)
            .map(|(tokens, rate)| tokens as f64 * rate);
        let completion_cost = completion_tokens
            .zip(completion_rate)
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
        // The typed federation snapshot carries no model, so federated usage
        // is priced at the flat rates.
        let Some((total_cost, cost)) =
            self.calculate_cost(usage.prompt_tokens, usage.completion_tokens, None)
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
        ctx.metadata.remove(&self.unmetered_reason_key);
        // The model string is backend-controlled; only a bounded,
        // control-free value is published or used to select a price.
        let model = usage
            .model
            .as_deref()
            .filter(|model| is_publishable_model_name(model));
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
            && let Some(model) = model
        {
            ctx.metadata
                .insert(self.model_key.clone(), model.to_string());
        }

        // Public per-request metadata retains its six-decimal contract, while
        // the typed export keeps a sub-micro remainder for cumulative metrics.
        let cost = self
            .calculate_cost(usage.prompt_tokens, usage.completion_tokens, model)
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

    /// An explicitly configured provider labels extractor-observed usage, as
    /// it does for buffered JSON responses.
    fn label_stream_usage(&self, mut usage: AiTokenUsage) -> AiTokenUsage {
        if let Some(provider) = self.fixed_provider {
            usage.provider = Some(provider);
        }
        usage
    }

    /// Label a 2xx response this instance could not meter.
    fn record_unmetered(&self, ctx: &mut RequestContext, reason: &'static str) {
        debug!(reason, "ai_token_metrics: response not metered");
        ctx.metadata
            .insert(self.unmetered_reason_key.clone(), reason.to_string());
    }

    /// Whether the ORIGIN response of a stream was a usage-bearing streaming
    /// representation, so a missing observation is worth labelling.
    fn origin_stream_is_meterable(ctx: &RequestContext) -> bool {
        ctx.metadata
            .get(crate::proxy::ORIGINAL_RESPONSE_CONTENT_TYPE_METADATA_KEY)
            .is_some_and(|content_type| stream_usage_format(content_type).is_some())
    }
}

/// Whether extracted usage carries at least one usable counter (explicit zero
/// included). Malformed categories can invalidate every counter of a report
/// that was nonetheless observed.
fn has_usable_counter(usage: &AiTokenUsage) -> bool {
    usage.prompt_tokens.is_some()
        || usage.completion_tokens.is_some()
        || usage.total_tokens.is_some()
}

/// Incremental usage framing for a streamed response content type.
fn stream_usage_format(content_type: &str) -> Option<UsageStreamFormat> {
    if is_event_stream_content_type(content_type) {
        Some(UsageStreamFormat::Sse)
    } else if is_aws_event_stream_content_type(content_type) {
        Some(UsageStreamFormat::AwsEventStream)
    } else {
        None
    }
}

/// Validate one optional cost rate (`null` or omitted disables it). Negative,
/// non-finite, or oversized rates are refused: they would produce nonsensical
/// cost metrics that pollute observability pipelines and chargeback
/// accounting. `location` prefixes the field name for nested entries.
fn cost_rate(config: &Value, field: &'static str, location: &str) -> Result<Option<f64>, String> {
    let rate = optional_f64(config, field)
        .map_err(|_| format!("ai_token_metrics: `{location}{field}` must be a number"))?;
    if let Some(rate) = rate
        && (rate < 0.0 || !rate.is_finite() || rate > MAX_COST_RATE)
    {
        return Err(format!(
            "ai_token_metrics: `{location}{field}` must be a non-negative finite number no greater than {MAX_COST_RATE}, got \"{rate}\""
        ));
    }
    Ok(rate)
}

/// Parse the optional ordered `model_pricing` array.
fn parse_model_pricing(config: &Value) -> Result<Vec<ModelPrice>, String> {
    let Some(value) = config.get("model_pricing") else {
        return Ok(Vec::new());
    };
    let entries = value
        .as_array()
        .ok_or_else(|| "ai_token_metrics: `model_pricing` must be an array".to_string())?;
    if entries.len() > MAX_MODEL_PATTERNS_PER_PROVIDER {
        return Err(format!(
            "ai_token_metrics: `model_pricing` admits at most {MAX_MODEL_PATTERNS_PER_PROVIDER} entries"
        ));
    }
    let mut prices = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let location = format!("model_pricing[{index}].");
        let object = entry.as_object().ok_or_else(|| {
            format!("ai_token_metrics: `model_pricing[{index}]` must be an object")
        })?;
        if let Some(unknown) = object
            .keys()
            .find(|key| !ALLOWED_MODEL_PRICE_KEYS.contains(&key.as_str()))
        {
            return Err(format!(
                "ai_token_metrics: unknown key {unknown:?} in `model_pricing[{index}]`; allowed keys: `{}`",
                ALLOWED_MODEL_PRICE_KEYS.join("`, `")
            ));
        }
        let model = object
            .get("model")
            .and_then(Value::as_str)
            .filter(|pattern| is_valid_model_pattern(pattern))
            .ok_or_else(|| {
                format!(
                    "ai_token_metrics: `{location}model` must be a 1-256 byte model glob of ASCII letters, digits, `.`, `_`, `-`, `:`, `/`, `+`, or `*` without `..`"
                )
            })?
            .to_string();
        let cost_per_prompt_token = cost_rate(entry, "cost_per_prompt_token", &location)?;
        let cost_per_completion_token = cost_rate(entry, "cost_per_completion_token", &location)?;
        if cost_per_prompt_token.is_none() && cost_per_completion_token.is_none() {
            return Err(format!(
                "ai_token_metrics: `model_pricing[{index}]` must set `cost_per_prompt_token` or `cost_per_completion_token`"
            ));
        }
        prices.push(ModelPrice {
            model,
            cost_per_prompt_token,
            cost_per_completion_token,
        });
    }
    Ok(prices)
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
        .ok_or_else(|| format!("ai_token_metrics: `{field}` must be a string"))
}

fn optional_bool(config: &Value, field: &'static str) -> Result<Option<bool>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| format!("ai_token_metrics: `{field}` must be a boolean"))
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
        .ok_or_else(|| format!("ai_token_metrics: `{field}` must be a number"))
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
        // Request hints avoid buffering before headers. When no hint exists,
        // the response-header and retry-release hooks also recognize origin SSE.
        if !self.buffer_streaming_responses && self.request_prefers_streaming(ctx) {
            return false;
        }
        true
    }

    fn may_release_response_body_under_retries(&self, ctx: &RequestContext) -> bool {
        !self.buffer_streaming_responses && self.should_buffer_response_body(ctx)
    }

    fn should_release_response_body_under_retries(
        &self,
        ctx: &RequestContext,
        _response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        // Confirm every streamed representation the observer meters (SSE and
        // AWS event-stream), so a retry-enabled route keeps live delivery for
        // Bedrock streams as well as SSE.
        self.may_release_response_body_under_retries(ctx)
            && header_value(response_headers, "content-type")
                .is_some_and(|content_type| stream_usage_format(content_type).is_some())
    }

    fn should_buffer_response_body_for_content_type(
        &self,
        ctx: &RequestContext,
        content_type: Option<&str>,
        response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        // `on_response_body` never inspects a non-2xx body, so collecting one
        // (an upstream error storm included) would only retain and delay it.
        (200..300).contains(&response_status)
            && self.should_buffer_response_body(ctx)
            && content_type.is_some_and(|ct| {
                if is_event_stream_content_type(ct) {
                    self.buffer_streaming_responses
                } else {
                    is_json_content_type(ct)
                }
            })
    }

    fn requires_response_stream_hooks(&self) -> bool {
        // A metered AI response can stream on any of H1/H2/H3. The per-response
        // factory below declines everything that is not a 2xx usage-bearing
        // stream, so unrelated streams pay only that check.
        true
    }

    /// Attach a pass-through usage observer to a streamed 2xx SSE or AWS
    /// event-stream response.
    ///
    /// Every chunk is forwarded unchanged and immediately while the shared
    /// bounded [`UsageStreamExtractor`] parses it, so live delivery is
    /// unaffected. Per-stream retention is one bounded parser carry plus a
    /// fixed-size accumulator, and the process-wide observer count is capped by
    /// [`MAX_CONCURRENT_STREAM_OBSERVATIONS`]. A content-coded origin stream is
    /// not a framing the parser can read and is left unobserved.
    fn response_stream_inspector(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        content_type: Option<&str>,
    ) -> Option<Box<dyn ResponseStreamInspector>> {
        if !(200..300).contains(&response_status)
            || ctx
                .metadata
                .contains_key(crate::proxy::SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY)
            || ctx
                .metadata
                .contains_key(crate::proxy::ORIGIN_ENCODED_RESPONSE_METADATA_KEY)
        {
            return None;
        }
        let format = stream_usage_format(content_type?)?;
        let handoff = ctx.response_stream_handoff()?;
        let Some(permit) = StreamObservationPermit::acquire() else {
            let refused = STREAM_OBSERVATION_REFUSALS.fetch_add(1, Ordering::Relaxed);
            if refused.is_multiple_of(STREAM_OBSERVATION_REFUSAL_LOG_INTERVAL) {
                warn!(
                    plugin = "ai_token_metrics",
                    limit = MAX_CONCURRENT_STREAM_OBSERVATIONS,
                    refused_total = refused.saturating_add(1),
                    "streaming token observation at capacity; streams are left unmetered until it drains"
                );
            }
            return None;
        };
        let shared = Arc::new(StreamUsageHandoff::default());
        handoff.publish(self.stream_usage_handoff_key, Arc::clone(&shared));
        Some(Box::new(UsageObserver {
            extractor: UsageStreamExtractor::new(format, self.fixed_provider),
            shared,
            _permit: permit,
        }))
    }

    /// Publish a streamed response's observed usage exactly once, before the
    /// transaction summary is logged. Runs on every terminal outcome —
    /// completion, backend error, and client disconnect — and publishes
    /// whatever usage the provider had already reported.
    async fn on_response_stream_terminated(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        _outcome: &crate::proxy::deferred_log::BodyOutcome,
    ) {
        let captured = ctx
            .response_stream_handoff()
            .and_then(|handoff| handoff.take::<StreamUsageHandoff>(self.stream_usage_handoff_key));
        if !(200..300).contains(&response_status)
            || ctx
                .metadata
                .contains_key(crate::proxy::SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY)
        {
            return;
        }
        let Some(shared) = captured else {
            if Self::origin_stream_is_meterable(ctx) {
                self.record_unmetered(ctx, UNMETERED_STREAM_NOT_INSPECTED);
            }
            return;
        };
        let accumulated = match shared.usage.lock() {
            Ok(usage) => usage.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        let usage = self.label_stream_usage(accumulated.token_usage());
        // A report that malformed categories invalidated is observed but
        // carries no usable counter; it is unmetered, not a success.
        if !has_usable_counter(&usage) {
            self.record_unmetered(ctx, UNMETERED_STREAM_WITHOUT_USAGE);
            return;
        }
        self.write_metadata(ctx, &usage);
        ctx.metadata
            .insert(self.streaming_key.clone(), "true".to_string());
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
        // (priority 4200, after this plugin) — both must agree that a
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
        // collect an SSE body even when this instance did not opt in. A
        // collected body never reaches the stream observer, so it is metered
        // here regardless of `buffer_streaming_responses`; otherwise a
        // sibling's buffering would silently drop the request's usage.
        let is_sse = is_event_stream_content_type(content_type);
        let is_aws_event_stream = is_aws_event_stream_content_type(content_type);
        if !is_sse && !is_aws_event_stream && !is_json_content_type(content_type) {
            debug!(
                "ai_token_metrics: skipping non-JSON response (content-type: {})",
                content_type
            );
            return PluginResult::Continue;
        }

        if body.is_empty() {
            self.record_unmetered(ctx, UNMETERED_NO_USAGE);
            return PluginResult::Continue;
        }

        if body.len() > MAX_INSPECTION_BYTES {
            debug!(
                "ai_token_metrics: encoded response body exceeds inspection limit of {} bytes",
                MAX_INSPECTION_BYTES
            );
            self.record_unmetered(ctx, UNMETERED_BODY_TOO_LARGE);
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
                self.record_unmetered(ctx, UNMETERED_DECODE_FAILED);
                return PluginResult::Continue;
            }
        };

        // Handle SSE streaming responses
        if is_sse {
            debug!("ai_token_metrics: parsing SSE streaming response");
            if let Some(usage) = self
                .extract_from_sse(&inspection_body)
                .filter(has_usable_counter)
            {
                self.write_metadata(ctx, &usage);
                ctx.metadata
                    .insert(self.streaming_key.clone(), "true".to_string());
            } else {
                self.record_unmetered(ctx, UNMETERED_NO_USAGE);
            }
            return PluginResult::Continue;
        }

        // A collected AWS event-stream body (a sibling, a route policy, or a
        // retry decision buffered it) is parsed with the same bounded
        // extractor the live observer uses.
        if is_aws_event_stream {
            let mut extractor =
                UsageStreamExtractor::new(UsageStreamFormat::AwsEventStream, self.fixed_provider);
            extractor.push(&inspection_body);
            extractor.finish();
            let usage = self.label_stream_usage(extractor.usage().token_usage());
            if has_usable_counter(&usage) {
                self.write_metadata(ctx, &usage);
                ctx.metadata
                    .insert(self.streaming_key.clone(), "true".to_string());
            } else {
                self.record_unmetered(ctx, UNMETERED_NO_USAGE);
            }
            return PluginResult::Continue;
        }

        // Parse the response body as JSON
        let json: Value = match serde_json::from_slice(&inspection_body) {
            Ok(v) => v,
            Err(e) => {
                debug!("ai_token_metrics: failed to parse response JSON: {}", e);
                self.record_unmetered(ctx, UNMETERED_MALFORMED_BODY);
                return PluginResult::Continue;
            }
        };

        // Determine the provider
        let provider = match self.fixed_provider {
            Some(provider) => provider,
            None => match detect_response_provider(&json) {
                Some(provider) => provider,
                None => {
                    self.record_unmetered(ctx, UNMETERED_PROVIDER_UNDETECTED);
                    return PluginResult::Continue;
                }
            },
        };

        // Extract token usage and write to metadata
        let usage = extract_response_usage(&json, provider);
        if usage.prompt_tokens.is_none()
            && usage.completion_tokens.is_none()
            && usage.total_tokens.is_none()
        {
            self.record_unmetered(ctx, UNMETERED_NO_USAGE);
            return PluginResult::Continue;
        }
        self.write_metadata(ctx, &usage);

        PluginResult::Continue
    }
}

// ---------------------------------------------------------------------------
// Streaming usage observation
// ---------------------------------------------------------------------------

/// RAII slot in the process-wide [`MAX_CONCURRENT_STREAM_OBSERVATIONS`]
/// budget. Acquisition is a bounded CAS loop, so a burst of concurrent streams
/// can never push the live observer count past the cap, and the slot returns
/// when the observer drops — including on client disconnect.
struct StreamObservationPermit;

impl StreamObservationPermit {
    fn acquire() -> Option<Self> {
        let mut current = ACTIVE_STREAM_OBSERVATIONS.load(Ordering::Relaxed);
        loop {
            if current >= MAX_CONCURRENT_STREAM_OBSERVATIONS {
                return None;
            }
            match ACTIVE_STREAM_OBSERVATIONS.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(Self),
                Err(observed) => current = observed,
            }
        }
    }
}

impl Drop for StreamObservationPermit {
    fn drop(&mut self) {
        ACTIVE_STREAM_OBSERVATIONS.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Usage captured by one stream observer, handed to
/// [`Plugin::on_response_stream_terminated`] through the request-owned stream
/// handoff. Locked only when the observer publishes at its end and when the
/// terminal hook reads it — never per chunk.
#[derive(Debug, Default)]
struct StreamUsageHandoff {
    usage: std::sync::Mutex<UsageAccumulator>,
}

/// Pass-through stream inspector that extracts provider usage.
///
/// Every chunk is forwarded byte-for-byte and immediately — the observer never
/// holds a window, so SSE event latency and H1/H2/H3 backpressure are what they
/// would be with no plugin attached — and it never terminates the stream.
struct UsageObserver {
    extractor: UsageStreamExtractor,
    shared: Arc<StreamUsageHandoff>,
    _permit: StreamObservationPermit,
}

impl UsageObserver {
    /// Flush a final unterminated event and publish the accumulated usage.
    /// Idempotent: `finish` only applies bytes already received.
    fn publish(&mut self) {
        self.extractor.finish();
        let usage = self.extractor.usage().clone();
        match self.shared.usage.lock() {
            Ok(mut slot) => *slot = usage,
            Err(poisoned) => *poisoned.into_inner() = usage,
        }
    }
}

#[async_trait]
impl ResponseStreamInspector for UsageObserver {
    async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction {
        self.extractor.push(chunk);
        ResponseStreamAction::Forward(bytes::Bytes::copy_from_slice(chunk))
    }

    async fn on_end(&mut self) -> ResponseStreamAction {
        self.publish();
        ResponseStreamAction::Forward(bytes::Bytes::new())
    }

    /// A later inspector cut the stream: the bytes already parsed are still
    /// what the provider generated, so their usage is published.
    fn on_downstream_terminated(&mut self) {
        self.publish();
    }

    /// Publish before the owning task wakes the terminal hooks, so a stream
    /// that ends by client disconnect (no `on_end`) still hands back the usage
    /// the provider had already reported.
    fn on_before_drop(&mut self) {
        self.publish();
    }
}

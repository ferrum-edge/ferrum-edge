use serde_json::Value;

/// Shared AI provider identifiers for response parsing helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiProvider {
    OpenAi,
    Anthropic,
    Google,
    Cohere,
    Mistral,
    Bedrock,
    /// Hugging Face Text Generation Inference native `/generate` and
    /// `/generate_stream` shapes, whose only authoritative usage signal is
    /// `details.generated_tokens` (plus an optional `details.prefill` token
    /// array when the caller asked for input details). TGI's OpenAI-compatible
    /// `/v1/chat/completions` surface reports an ordinary `usage` block and is
    /// still detected as [`AiProvider::OpenAi`].
    Tgi,
}

impl AiProvider {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
            Self::Anthropic => "anthropic",
            Self::Google => "google",
            Self::Cohere => "cohere",
            Self::Mistral => "mistral",
            Self::Bedrock => "bedrock",
            Self::Tgi => "tgi",
        }
    }
}

/// Token/model metadata extracted from an AI provider response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AiTokenUsage {
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
    pub model: Option<String>,
    pub provider: Option<AiProvider>,
}

impl AiTokenUsage {
    /// Merge a newer cumulative/partial provider usage snapshot.
    ///
    /// Present fields in the newer snapshot are authoritative; omitted fields
    /// retain the last known value. Components are never added across events,
    /// because supported streaming providers report cumulative counts. A total
    /// is recomputed only with checked arithmetic when both components exist.
    pub fn merge_cumulative(&mut self, newer: Self) {
        if self.provider.is_some() && newer.provider.is_some() && self.provider != newer.provider {
            return;
        }

        let component_updated = newer.prompt_tokens.is_some() || newer.completion_tokens.is_some();
        if newer.prompt_tokens.is_some() {
            self.prompt_tokens = newer.prompt_tokens;
        }
        if newer.completion_tokens.is_some() {
            self.completion_tokens = newer.completion_tokens;
        }
        self.total_tokens = if let Some(total) = newer.total_tokens {
            Some(total)
        } else if component_updated {
            sum_pair(self.prompt_tokens, self.completion_tokens).or(self.total_tokens)
        } else {
            self.total_tokens
        };
        if newer.model.is_some() {
            self.model = newer.model;
        }
        if newer.provider.is_some() {
            self.provider = newer.provider;
        }
    }

    /// Resolve the configured `count_mode` counter.
    ///
    /// Prompt/completion modes return `None` when the selected counter was not
    /// explicitly reported. `Some(0)` is preserved only for an explicit numeric
    /// zero. Total mode may combine or fall back to a single reported component,
    /// but only when at least one component or an explicit total was present.
    /// Callers that reconcile a pre-reservation must pair this with
    /// [`Self::is_complete_for_mode`]: a partial component is an authoritative
    /// lower bound, not authority to release the unreported portion.
    pub fn total_for_mode(&self, count_mode: &str) -> Option<u64> {
        match count_mode {
            "prompt_tokens" => self.prompt_tokens,
            "completion_tokens" => self.completion_tokens,
            _ => self
                .total_tokens
                .or_else(|| match (self.prompt_tokens, self.completion_tokens) {
                    (Some(prompt), Some(completion)) => prompt.checked_add(completion),
                    (Some(prompt), None) => Some(prompt),
                    (None, Some(completion)) => Some(completion),
                    _ => None,
                }),
        }
    }

    /// Whether the selected counter fully represents the configured mode.
    ///
    /// A single prompt or completion component is complete for its own mode but
    /// only a lower bound for `total_tokens`. The total is complete when the
    /// provider supplied it explicitly or both components are present.
    pub fn is_complete_for_mode(&self, count_mode: &str) -> bool {
        match count_mode {
            "prompt_tokens" => self.prompt_tokens.is_some(),
            "completion_tokens" => self.completion_tokens.is_some(),
            _ => {
                self.total_tokens.is_some()
                    || (self.prompt_tokens.is_some() && self.completion_tokens.is_some())
            }
        }
    }
}

pub fn parse_ai_provider(provider: &str) -> Option<AiProvider> {
    match provider {
        "openai" => Some(AiProvider::OpenAi),
        "anthropic" => Some(AiProvider::Anthropic),
        "google" => Some(AiProvider::Google),
        "cohere" => Some(AiProvider::Cohere),
        "mistral" => Some(AiProvider::Mistral),
        "bedrock" => Some(AiProvider::Bedrock),
        "tgi" => Some(AiProvider::Tgi),
        _ => None,
    }
}

pub fn detect_response_provider(json: &Value) -> Option<AiProvider> {
    if json
        .get("usageMetadata")
        .and_then(|usage| usage.get("promptTokenCount"))
        .is_some()
    {
        return Some(AiProvider::Google);
    }

    // OpenAI Responses objects use the same `input_tokens` spelling as
    // Anthropic but carry an unambiguous top-level object discriminator.
    if json.get("object").and_then(Value::as_str) == Some("response")
        && json.get("usage").is_some_and(|usage| {
            usage.get("input_tokens").is_some() || usage.get("output_tokens").is_some()
        })
    {
        return Some(AiProvider::OpenAi);
    }

    if json
        .get("usage")
        .and_then(|usage| usage.get("input_tokens"))
        .is_some()
    {
        return Some(AiProvider::Anthropic);
    }

    // Cohere v2 (`/v2/chat`, the format `ai_federation` uses by default)
    // reports `{"usage": {"tokens": {"input_tokens": ..., "output_tokens": ...}}}`.
    // Cohere v1 (`/v1/generate`) reported it under `meta.tokens.*`. Accept
    // both — place this above the OpenAI / Bedrock branches so any future
    // broadening of those checks (which also key off `usage.*`) can't
    // accidentally claim a v2 response. Canonical shapes are disjoint today.
    if json
        .get("usage")
        .and_then(|usage| usage.get("tokens"))
        .and_then(|tokens| tokens.get("input_tokens"))
        .is_some()
    {
        return Some(AiProvider::Cohere);
    }

    if json
        .get("meta")
        .and_then(|meta| meta.get("tokens"))
        .is_some()
    {
        return Some(AiProvider::Cohere);
    }

    // Hugging Face TGI native `/generate` and the terminal `/generate_stream`
    // event both report the generated-token count under `details`. No other
    // supported provider uses that path, so it is an unambiguous discriminator.
    if json
        .get("details")
        .and_then(|details| details.get("generated_tokens"))
        .is_some()
    {
        return Some(AiProvider::Tgi);
    }

    if json
        .get("usage")
        .and_then(|usage| usage.get("inputTokens"))
        .is_some()
    {
        return Some(AiProvider::Bedrock);
    }

    // Bedrock `InvokeModelWithResponseStream` reports the authoritative billed
    // counts in the terminal chunk's `amazon-bedrock-invocationMetrics` object
    // rather than a `usage` block.
    if json.get("amazon-bedrock-invocationMetrics").is_some() {
        return Some(AiProvider::Bedrock);
    }

    if json.get("inputTextTokenCount").is_some() {
        return Some(AiProvider::Bedrock);
    }

    if json
        .get("usage")
        .and_then(|usage| usage.get("prompt_tokens"))
        .is_some()
    {
        return Some(AiProvider::OpenAi);
    }

    None
}

pub fn detect_sse_provider(json: &Value) -> Option<AiProvider> {
    // Check streaming-specific provider shapes before the buffered-response
    // fallback below. Anthropic uses underscore-separated event types
    // (`message_start` / `message_delta` / `message_stop` /
    // `content_block_start` / `content_block_delta` / `content_block_stop` /
    // `ping`); Cohere v2 uses hyphen-separated types (`message-start` /
    // `message-end` / `content-start` / `content-delta` / `content-end`).
    // Match on the exact separator so v2 streams don't get mis-classified as
    // Anthropic (the previous `starts_with("message")` swallowed both).
    if json
        .get("type")
        .and_then(|value| value.as_str())
        .is_some_and(|t| {
            t.starts_with("message_") || t.starts_with("content_block_") || t == "ping"
        })
    {
        return Some(AiProvider::Anthropic);
    }

    if json
        .get("type")
        .and_then(|value| value.as_str())
        .is_some_and(|t| t.starts_with("message-") || t.starts_with("content-"))
    {
        return Some(AiProvider::Cohere);
    }

    if json
        .get("object")
        .and_then(|value| value.as_str())
        .is_some_and(|value| value.contains("chat.completion") || value == "response")
    {
        return Some(AiProvider::OpenAi);
    }

    if json.get("candidates").is_some() {
        return Some(AiProvider::Google);
    }

    detect_response_provider(json)
}

pub fn extract_response_usage(json: &Value, provider: AiProvider) -> AiTokenUsage {
    match provider {
        AiProvider::OpenAi | AiProvider::Mistral => extract_openai_usage(json, provider),
        AiProvider::Anthropic => extract_anthropic_usage(json),
        AiProvider::Google => extract_google_usage(json),
        AiProvider::Cohere => extract_cohere_usage(json),
        AiProvider::Bedrock => extract_bedrock_usage(json),
        AiProvider::Tgi => extract_tgi_usage(json),
    }
}

#[cfg(test)]
fn extract_response_texts(json: &Value) -> Vec<&str> {
    let mut texts = Vec::new();

    if let Some(choices) = json.get("choices").and_then(|value| value.as_array()) {
        for choice in choices {
            if let Some(content) = choice
                .get("message")
                .and_then(|message| message.get("content"))
                .and_then(|value| value.as_str())
            {
                texts.push(content);
            }
            if let Some(content) = choice
                .get("delta")
                .and_then(|delta| delta.get("content"))
                .and_then(|value| value.as_str())
            {
                texts.push(content);
            }
        }
    }

    if let Some(content) = json.get("content").and_then(|value| value.as_array()) {
        for block in content {
            if block.get("type").and_then(|value| value.as_str()) == Some("text")
                && let Some(text) = block.get("text").and_then(|value| value.as_str())
            {
                texts.push(text);
            }
        }
    }

    if let Some(candidates) = json.get("candidates").and_then(|value| value.as_array()) {
        for candidate in candidates {
            if let Some(parts) = candidate
                .get("content")
                .and_then(|content| content.get("parts"))
                .and_then(|value| value.as_array())
            {
                for part in parts {
                    if let Some(text) = part.get("text").and_then(|value| value.as_str()) {
                        texts.push(text);
                    }
                }
            }
        }
    }

    if let Some(content) = json
        .get("message")
        .and_then(|message| message.get("content"))
        .and_then(|value| value.as_array())
    {
        for block in content {
            if let Some(text) = block.get("text").and_then(|value| value.as_str()) {
                texts.push(text);
            }
        }
    }

    if let Some(content) = json
        .get("output")
        .and_then(|output| output.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(|value| value.as_array())
    {
        for block in content {
            if let Some(text) = block.get("text").and_then(|value| value.as_str()) {
                texts.push(text);
            }
        }
    }

    texts
}

#[cfg(test)]
fn for_each_response_text_mut(json: &mut Value, mut apply: impl FnMut(&mut String)) {
    if let Some(choices) = json
        .get_mut("choices")
        .and_then(|value| value.as_array_mut())
    {
        for choice in choices {
            if let Some(message) = choice
                .get_mut("message")
                .and_then(|value| value.as_object_mut())
                && let Some(Value::String(content)) = message.get_mut("content")
            {
                apply(content);
            }
            if let Some(delta) = choice
                .get_mut("delta")
                .and_then(|value| value.as_object_mut())
                && let Some(Value::String(content)) = delta.get_mut("content")
            {
                apply(content);
            }
        }
    }

    if let Some(content) = json
        .get_mut("content")
        .and_then(|value| value.as_array_mut())
    {
        for block in content {
            let is_text = block.get("type").and_then(|value| value.as_str()) == Some("text");
            if is_text
                && let Some(block) = block.as_object_mut()
                && let Some(Value::String(text)) = block.get_mut("text")
            {
                apply(text);
            }
        }
    }

    if let Some(candidates) = json
        .get_mut("candidates")
        .and_then(|value| value.as_array_mut())
    {
        for candidate in candidates {
            if let Some(parts) = candidate
                .get_mut("content")
                .and_then(|content| content.get_mut("parts"))
                .and_then(|value| value.as_array_mut())
            {
                for part in parts {
                    if let Some(part) = part.as_object_mut()
                        && let Some(Value::String(text)) = part.get_mut("text")
                    {
                        apply(text);
                    }
                }
            }
        }
    }

    if let Some(content) = json
        .get_mut("message")
        .and_then(|message| message.get_mut("content"))
        .and_then(|value| value.as_array_mut())
    {
        for block in content {
            if let Some(block) = block.as_object_mut()
                && let Some(Value::String(text)) = block.get_mut("text")
            {
                apply(text);
            }
        }
    }

    if let Some(content) = json
        .get_mut("output")
        .and_then(|output| output.get_mut("message"))
        .and_then(|message| message.get_mut("content"))
        .and_then(|value| value.as_array_mut())
    {
        for block in content {
            if let Some(block) = block.as_object_mut()
                && let Some(Value::String(text)) = block.get_mut("text")
            {
                apply(text);
            }
        }
    }
}

fn extract_openai_usage(json: &Value, provider: AiProvider) -> AiTokenUsage {
    let usage = json.get("usage");
    let prompt = usage
        .and_then(|value| value.get("prompt_tokens"))
        .and_then(|value| value.as_u64())
        .or_else(|| {
            usage
                .and_then(|value| value.get("input_tokens"))
                .and_then(|value| value.as_u64())
        });
    let completion = usage
        .and_then(|value| value.get("completion_tokens"))
        .and_then(|value| value.as_u64())
        .or_else(|| {
            usage
                .and_then(|value| value.get("output_tokens"))
                .and_then(|value| value.as_u64())
        });

    AiTokenUsage {
        prompt_tokens: prompt,
        completion_tokens: completion,
        total_tokens: usage
            .and_then(|value| value.get("total_tokens"))
            .and_then(|value| value.as_u64())
            .or_else(|| sum_pair(prompt, completion)),
        model: json
            .get("model")
            .and_then(|value| value.as_str())
            .map(String::from),
        provider: Some(provider),
    }
}

fn extract_anthropic_usage(json: &Value) -> AiTokenUsage {
    let usage = json.get("usage");
    let prompt = anthropic_input_tokens(usage);
    let completion = usage
        .and_then(|value| value.get("output_tokens"))
        .and_then(|value| value.as_u64());
    AiTokenUsage {
        prompt_tokens: prompt,
        completion_tokens: completion,
        total_tokens: sum_pair(prompt, completion),
        model: json
            .get("model")
            .and_then(|value| value.as_str())
            .map(String::from),
        provider: Some(AiProvider::Anthropic),
    }
}

fn extract_google_usage(json: &Value) -> AiTokenUsage {
    let usage = json.get("usageMetadata");
    let counts = gemini_usage_counts(usage);
    AiTokenUsage {
        prompt_tokens: counts.prompt,
        completion_tokens: counts.completion,
        total_tokens: counts.total,
        model: json
            .get("modelVersion")
            .and_then(|value| value.as_str())
            .map(String::from),
        provider: Some(AiProvider::Google),
    }
}

fn extract_cohere_usage(json: &Value) -> AiTokenUsage {
    // Cohere v2 buffered (`/v2/chat`) returns counts at `usage.tokens.*`.
    // Cohere v2 streaming nests them under the `message-end` event's
    // `delta.usage.tokens.*`. Cohere v1 (`/v1/generate`) returned them at
    // `meta.tokens.*`. Try buffered v2 first, then streaming v2, then v1 so
    // legacy deployments continue to report usage.
    let tokens = json
        .get("usage")
        .and_then(|value| value.get("tokens"))
        .or_else(|| {
            json.get("delta")
                .and_then(|delta| delta.get("usage"))
                .and_then(|usage| usage.get("tokens"))
        })
        .or_else(|| json.get("meta").and_then(|value| value.get("tokens")));
    let prompt = tokens
        .and_then(|value| value.get("input_tokens"))
        .and_then(|value| value.as_u64());
    let completion = tokens
        .and_then(|value| value.get("output_tokens"))
        .and_then(|value| value.as_u64());
    AiTokenUsage {
        prompt_tokens: prompt,
        completion_tokens: completion,
        total_tokens: sum_pair(prompt, completion),
        model: json
            .get("model")
            .and_then(|value| value.as_str())
            .map(String::from),
        provider: Some(AiProvider::Cohere),
    }
}

fn extract_bedrock_usage(json: &Value) -> AiTokenUsage {
    let usage = json.get("usage");
    // Converse reports uncached input separately from prompt-cache reads and
    // writes; the billed input is their sum (AWS: `total input tokens =
    // inputTokens + cacheReadInputTokens + cacheWriteInputTokens`).
    let converse_prompt = usage
        .and_then(|value| value.get("inputTokens"))
        .and_then(|value| value.as_u64())
        .map(|input| {
            add_optional_counts(
                input,
                [
                    usage_count(usage, "cacheReadInputTokens"),
                    usage_count(usage, "cacheWriteInputTokens"),
                ],
            )
        });
    let converse_completion = usage
        .and_then(|value| value.get("outputTokens"))
        .and_then(|value| value.as_u64());
    let titan_prompt = json
        .get("inputTextTokenCount")
        .and_then(|value| value.as_u64());
    // Titan Text InvokeModel returns exactly one result for one invocation.
    // More than one result is ambiguous, so do not sum it or select one.
    let titan_completion = json
        .get("results")
        .and_then(|value| value.as_array())
        .filter(|results| results.len() == 1)
        .and_then(|results| results[0].get("tokenCount"))
        .and_then(|value| value.as_u64());
    // `InvokeModelWithResponseStream` terminal chunk. AWS documents these as the
    // billed counts for the invocation, so they are authoritative for a native
    // Bedrock event stream that carries no `usage` block at all.
    let metrics = json.get("amazon-bedrock-invocationMetrics");
    let metrics_prompt = metrics
        .and_then(|value| value.get("inputTokenCount"))
        .and_then(|value| value.as_u64());
    let metrics_completion = metrics
        .and_then(|value| value.get("outputTokenCount"))
        .and_then(|value| value.as_u64());
    let prompt = converse_prompt.or(titan_prompt).or(metrics_prompt);
    let completion = converse_completion
        .or(titan_completion)
        .or(metrics_completion);
    AiTokenUsage {
        prompt_tokens: prompt,
        completion_tokens: completion,
        total_tokens: authoritative_total(
            usage
                .and_then(|value| value.get("totalTokens"))
                .and_then(|value| value.as_u64()),
            prompt,
            completion,
        ),
        model: None,
        provider: Some(AiProvider::Bedrock),
    }
}

/// Hugging Face TGI native usage.
///
/// `details.generated_tokens` is the only counter TGI always reports, and it is
/// the completion count. `details.prefill` is the input-token array, present
/// only when the caller requested input details — an EMPTY array is TGI's
/// default "not reported" representation, so it must not be read as a prompt
/// count of zero. Treating it as zero would let a `prompt_tokens`-mode budget
/// charge nothing for an arbitrarily large prompt; leaving it absent instead
/// routes the response through the configured `on_unmetered_response` policy.
fn extract_tgi_usage(json: &Value) -> AiTokenUsage {
    let details = json.get("details");
    let completion = details
        .and_then(|value| value.get("generated_tokens"))
        .and_then(|value| value.as_u64());
    let prompt = details
        .and_then(|value| value.get("prefill"))
        .and_then(|value| value.as_array())
        .filter(|tokens| !tokens.is_empty())
        .map(|tokens| tokens.len() as u64);
    AiTokenUsage {
        prompt_tokens: prompt,
        completion_tokens: completion,
        total_tokens: sum_pair(prompt, completion),
        model: None,
        provider: Some(AiProvider::Tgi),
    }
}

fn usage_count(usage: Option<&Value>, field: &str) -> Option<u64> {
    usage
        .and_then(|value| value.get(field))
        .and_then(Value::as_u64)
}

/// Add optional token categories to a reported base count. An omitted
/// category contributes nothing; the sum saturates so a provider-controlled
/// overflow charges the maximum rather than wrapping to a small number.
fn add_optional_counts<const N: usize>(base: u64, extras: [Option<u64>; N]) -> u64 {
    extras.into_iter().flatten().fold(base, u64::saturating_add)
}

/// A provider total stays authoritative (it may cover a category this parser
/// does not model), but it is never allowed to fall below the components the
/// same document reports.
fn authoritative_total(
    reported: Option<u64>,
    prompt: Option<u64>,
    completion: Option<u64>,
) -> Option<u64> {
    match (reported, sum_pair(prompt, completion)) {
        (Some(reported), Some(derived)) => Some(reported.max(derived)),
        (reported, derived) => reported.or(derived),
    }
}

/// Billed input of an Anthropic Messages `usage` object.
///
/// `input_tokens` counts only the tokens after the last cache breakpoint; the
/// prompt-cache writes (`cache_creation_input_tokens`) and reads
/// (`cache_read_input_tokens`) are reported separately and are part of the
/// input the request consumed (Anthropic: `total_input_tokens =
/// cache_read_input_tokens + cache_creation_input_tokens + input_tokens`).
/// `None` when `input_tokens` itself was not reported, so a usage fragment
/// that carries only output counts never overwrites a known prompt.
pub(crate) fn anthropic_input_tokens(usage: Option<&Value>) -> Option<u64> {
    let input = usage_count(usage, "input_tokens")?;
    Some(add_optional_counts(
        input,
        [
            usage_count(usage, "cache_creation_input_tokens"),
            usage_count(usage, "cache_read_input_tokens"),
        ],
    ))
}

/// Normalized Gemini / Vertex `usageMetadata` counts.
pub(crate) struct GeminiUsageCounts {
    pub prompt: Option<u64>,
    pub completion: Option<u64>,
    pub total: Option<u64>,
}

/// Fold Gemini's separately reported categories into prompt/completion the
/// same way the `ai_stream_router` normalizer does: `toolUsePromptTokenCount`
/// is input-side, `thoughtsTokenCount` is billed output that is NOT part of
/// `candidatesTokenCount`. `totalTokenCount` (documented as prompt + tool-use
/// prompt + thoughts + candidates) stays authoritative but never below the
/// folded components. proto3 JSON omits zero-valued counters, so an omitted
/// category is zero when a sibling on the same side was reported.
pub(crate) fn gemini_usage_counts(usage: Option<&Value>) -> GeminiUsageCounts {
    let side = |base: Option<u64>, extra: Option<u64>| match (base, extra) {
        (None, None) => None,
        (base, extra) => Some(base.unwrap_or(0).saturating_add(extra.unwrap_or(0))),
    };
    let prompt = side(
        usage_count(usage, "promptTokenCount"),
        usage_count(usage, "toolUsePromptTokenCount"),
    );
    let completion = side(
        usage_count(usage, "candidatesTokenCount"),
        usage_count(usage, "thoughtsTokenCount"),
    );
    GeminiUsageCounts {
        prompt,
        completion,
        total: authoritative_total(usage_count(usage, "totalTokenCount"), prompt, completion),
    }
}

fn sum_pair(prompt: Option<u64>, completion: Option<u64>) -> Option<u64> {
    match (prompt, completion) {
        (Some(prompt), Some(completion)) => prompt.checked_add(completion),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AiProvider, AiTokenUsage, detect_response_provider, detect_sse_provider,
        extract_response_texts, extract_response_usage, for_each_response_text_mut,
    };
    use serde_json::json;

    #[test]
    fn total_for_mode_distinguishes_absent_from_explicit_zero() {
        let absent = AiTokenUsage::default();
        assert_eq!(absent.total_for_mode("prompt_tokens"), None);
        assert_eq!(absent.total_for_mode("completion_tokens"), None);
        assert_eq!(absent.total_for_mode("total_tokens"), None);

        let explicit_zero = AiTokenUsage {
            prompt_tokens: Some(0),
            completion_tokens: Some(0),
            total_tokens: Some(0),
            ..Default::default()
        };
        assert_eq!(explicit_zero.total_for_mode("prompt_tokens"), Some(0));
        assert_eq!(explicit_zero.total_for_mode("completion_tokens"), Some(0));
        assert_eq!(explicit_zero.total_for_mode("total_tokens"), Some(0));

        let partial = AiTokenUsage {
            prompt_tokens: Some(12),
            completion_tokens: None,
            total_tokens: None,
            ..Default::default()
        };
        assert_eq!(partial.total_for_mode("prompt_tokens"), Some(12));
        assert_eq!(partial.total_for_mode("completion_tokens"), None);
        assert_eq!(partial.total_for_mode("total_tokens"), Some(12));
        assert!(partial.is_complete_for_mode("prompt_tokens"));
        assert!(!partial.is_complete_for_mode("completion_tokens"));
        assert!(!partial.is_complete_for_mode("total_tokens"));
        assert!(explicit_zero.is_complete_for_mode("total_tokens"));
    }

    #[test]
    fn detects_supported_provider_shapes() {
        assert_eq!(
            detect_response_provider(&json!({"usageMetadata": {"promptTokenCount": 1}})),
            Some(AiProvider::Google)
        );
        assert_eq!(
            detect_response_provider(&json!({"usage": {"input_tokens": 1}})),
            Some(AiProvider::Anthropic)
        );
        // Cohere v1 (`/v1/generate`)
        assert_eq!(
            detect_response_provider(&json!({"meta": {"tokens": {"input_tokens": 1}}})),
            Some(AiProvider::Cohere)
        );
        // Cohere v2 (`/v2/chat` — what `ai_federation` uses by default)
        assert_eq!(
            detect_response_provider(
                &json!({"usage": {"tokens": {"input_tokens": 1, "output_tokens": 2}}})
            ),
            Some(AiProvider::Cohere)
        );
        assert_eq!(
            detect_response_provider(&json!({"usage": {"inputTokens": 1}})),
            Some(AiProvider::Bedrock)
        );
        assert_eq!(
            detect_response_provider(&json!({"usage": {"prompt_tokens": 1}})),
            Some(AiProvider::OpenAi)
        );
    }

    #[test]
    fn extracts_cohere_v2_usage_from_usage_tokens_path() {
        // Canonical Cohere v2 `/v2/chat` body — model identity is returned via
        // HTTP response headers, not the body, so `model` is absent here.
        let usage = extract_response_usage(
            &json!({
                "id": "abc-123",
                "finish_reason": "COMPLETE",
                "usage": {
                    "tokens": {
                        "input_tokens": 17,
                        "output_tokens": 9
                    }
                }
            }),
            AiProvider::Cohere,
        );

        assert_eq!(usage.prompt_tokens, Some(17));
        assert_eq!(usage.completion_tokens, Some(9));
        assert_eq!(usage.total_tokens, Some(26));
        assert!(usage.model.is_none());
    }

    #[test]
    fn extracts_cohere_v2_model_when_body_includes_it() {
        // Some OpenAI-compatible wrappers in front of Cohere v2 echo `model`
        // into the body. The extractor is intentionally tolerant — if the
        // field is present, surface it.
        let usage = extract_response_usage(
            &json!({
                "usage": {
                    "tokens": {
                        "input_tokens": 17,
                        "output_tokens": 9
                    }
                },
                "model": "command-r-plus"
            }),
            AiProvider::Cohere,
        );

        assert_eq!(usage.model.as_deref(), Some("command-r-plus"));
    }

    #[test]
    fn extracts_cohere_v2_streaming_usage_from_message_end() {
        // Cohere v2 streaming `message-end` event nests counts under
        // `delta.usage.tokens.*` instead of root `usage`.
        let usage = extract_response_usage(
            &json!({
                "type": "message-end",
                "delta": {
                    "finish_reason": "COMPLETE",
                    "usage": {
                        "tokens": {
                            "input_tokens": 23,
                            "output_tokens": 41
                        }
                    }
                }
            }),
            AiProvider::Cohere,
        );

        assert_eq!(usage.prompt_tokens, Some(23));
        assert_eq!(usage.completion_tokens, Some(41));
        assert_eq!(usage.total_tokens, Some(64));
        assert!(usage.model.is_none());
    }

    #[test]
    fn sse_detection_distinguishes_anthropic_underscores_from_cohere_v2_hyphens() {
        // Anthropic SSE event types use underscore separators.
        assert_eq!(
            detect_sse_provider(&json!({"type": "message_start"})),
            Some(AiProvider::Anthropic)
        );
        assert_eq!(
            detect_sse_provider(&json!({"type": "message_delta"})),
            Some(AiProvider::Anthropic)
        );
        assert_eq!(
            detect_sse_provider(&json!({"type": "content_block_delta"})),
            Some(AiProvider::Anthropic)
        );
        assert_eq!(
            detect_sse_provider(&json!({"type": "ping"})),
            Some(AiProvider::Anthropic)
        );

        // Cohere v2 SSE event types use hyphen separators. Regression guard
        // for the previous `starts_with("message")` check that swallowed
        // `message-start` / `message-end` as Anthropic.
        assert_eq!(
            detect_sse_provider(&json!({"type": "message-start"})),
            Some(AiProvider::Cohere)
        );
        assert_eq!(
            detect_sse_provider(&json!({"type": "message-end"})),
            Some(AiProvider::Cohere)
        );
        assert_eq!(
            detect_sse_provider(&json!({"type": "content-delta"})),
            Some(AiProvider::Cohere)
        );
    }

    #[test]
    fn extracts_cohere_v1_usage_from_meta_tokens_path() {
        // Backwards compatibility: legacy `/v1/generate` callers.
        let usage = extract_response_usage(
            &json!({
                "meta": {
                    "tokens": {
                        "input_tokens": 3,
                        "output_tokens": 4
                    }
                },
                "model": "command-light"
            }),
            AiProvider::Cohere,
        );

        assert_eq!(usage.prompt_tokens, Some(3));
        assert_eq!(usage.completion_tokens, Some(4));
        assert_eq!(usage.total_tokens, Some(7));
        assert_eq!(usage.model.as_deref(), Some("command-light"));
    }

    #[test]
    fn extracts_usage_and_model_fallbacks() {
        let usage = extract_response_usage(
            &json!({
                "usageMetadata": {
                    "promptTokenCount": 11,
                    "candidatesTokenCount": 7
                },
                "modelVersion": "gemini-2.5-pro"
            }),
            AiProvider::Google,
        );

        assert_eq!(usage.prompt_tokens, Some(11));
        assert_eq!(usage.completion_tokens, Some(7));
        assert_eq!(usage.total_tokens, Some(18));
        assert_eq!(usage.model.as_deref(), Some("gemini-2.5-pro"));
    }

    #[test]
    fn collects_and_mutates_supported_response_text_shapes() {
        let mut json = json!({
            "choices": [{"message": {"content": "openai"}}],
            "content": [{"type": "text", "text": "anthropic"}],
            "candidates": [{"content": {"parts": [{"text": "google"}]}}],
            "message": {"content": [{"text": "cohere"}]},
            "output": {"message": {"content": [{"text": "bedrock"}]}}
        });

        assert_eq!(
            extract_response_texts(&json),
            vec!["openai", "anthropic", "google", "cohere", "bedrock"]
        );

        for_each_response_text_mut(&mut json, |text| text.make_ascii_uppercase());

        assert_eq!(
            extract_response_texts(&json),
            vec!["OPENAI", "ANTHROPIC", "GOOGLE", "COHERE", "BEDROCK"]
        );
    }
}

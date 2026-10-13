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
    /// Raw provider token categories behind `prompt_tokens` /
    /// `completion_tokens`, for providers that report the billed input or
    /// output as several separately omittable counters. Cumulative merging
    /// combines these field by field before folding, so an update that omits
    /// a category never erases one an earlier event reported.
    pub categories: UsageCategories,
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
        let has_categories = newer.categories.family.is_some();
        let newer = self.categories.absorb(newer);
        if has_categories {
            // A malformed or overflowing side invalidates the stale count and
            // the total that depended on it, instead of keeping them complete.
            let (prompt_invalid, completion_invalid) = self.categories.invalid_sides();
            if prompt_invalid {
                self.prompt_tokens = None;
            }
            if completion_invalid {
                self.completion_tokens = None;
            }
            if prompt_invalid || completion_invalid {
                self.total_tokens = None;
            }
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

    // Bedrock Converse `usage` uses camelCase counters no other supported
    // provider shares; any one of them (a total-only or cache-only update
    // included) identifies the format.
    if json.get("usage").is_some_and(|usage| {
        [
            "inputTokens",
            "outputTokens",
            "totalTokens",
            "cacheReadInputTokens",
            "cacheWriteInputTokens",
        ]
        .iter()
        .any(|field| usage.get(field).is_some())
    }) {
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
        ..Default::default()
    }
}

fn extract_anthropic_usage(json: &Value) -> AiTokenUsage {
    let categories = UsageCategories::anthropic(json.get("usage"));
    let mut usage = AiTokenUsage {
        model: json
            .get("model")
            .and_then(|value| value.as_str())
            .map(String::from),
        provider: Some(AiProvider::Anthropic),
        ..Default::default()
    };
    usage.apply_categories(categories);
    usage
}

fn extract_google_usage(json: &Value) -> AiTokenUsage {
    let categories = UsageCategories::gemini(json.get("usageMetadata"));
    let mut usage = AiTokenUsage {
        model: json
            .get("modelVersion")
            .and_then(|value| value.as_str())
            .map(String::from),
        provider: Some(AiProvider::Google),
        ..Default::default()
    };
    usage.apply_categories(categories);
    usage
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
        ..Default::default()
    }
}

fn extract_bedrock_usage(json: &Value) -> AiTokenUsage {
    let usage = json.get("usage");
    // Converse reports uncached input separately from prompt-cache reads and
    // writes; the billed input is their sum (AWS: `total input tokens =
    // inputTokens + cacheReadInputTokens + cacheWriteInputTokens`).
    if let Some(categories) = UsageCategories::bedrock_converse(usage) {
        let mut converse = AiTokenUsage {
            provider: Some(AiProvider::Bedrock),
            ..Default::default()
        };
        converse.apply_categories(categories);
        return converse;
    }
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
    // It may also carry `cacheReadInputTokenCount` / `cacheWriteInputTokenCount`
    // beside an uncached `inputTokenCount`, the same layout as the Anthropic
    // body the stream wraps, so it folds (and merges) as that layout.
    if let Some(metrics) = json.get("amazon-bedrock-invocationMetrics")
        && titan_prompt.is_none()
        && titan_completion.is_none()
    {
        let mut invoke = AiTokenUsage {
            provider: Some(AiProvider::Bedrock),
            ..Default::default()
        };
        invoke.apply_categories(UsageCategories::bedrock_invocation_metrics(Some(metrics)));
        return invoke;
    }
    let prompt = titan_prompt;
    let completion = titan_completion;
    AiTokenUsage {
        prompt_tokens: prompt,
        completion_tokens: completion,
        total_tokens: sum_pair(prompt, completion),
        model: None,
        provider: Some(AiProvider::Bedrock),
        ..Default::default()
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
        ..Default::default()
    }
}

/// The Anthropic `message_start` usage carrier with its `output_tokens`
/// removed. That count is an initial placeholder (commonly 1); the cumulative
/// output arrives on `message_delta`. Treating it as the completion count
/// would make a stream interrupted before the terminal delta look complete.
pub fn anthropic_message_start_usage(message: &Value) -> Value {
    let mut usage = message.get("usage").cloned().unwrap_or(Value::Null);
    if let Some(object) = usage.as_object_mut() {
        object.remove("output_tokens");
    }
    serde_json::json!({ "usage": usage })
}

/// One raw provider counter. `Invalid` (present but not a non-negative
/// integer) is kept distinct from `Absent` so a malformed field can never be
/// read as "omitted, therefore zero".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Counter {
    #[default]
    Absent,
    Value(u64),
    Invalid,
}

impl Counter {
    /// `null` is absence: Anthropic types its cache counters as nullable.
    fn read(usage: Option<&Value>, field: &str) -> Self {
        match usage.and_then(|value| value.get(field)) {
            None | Some(Value::Null) => Self::Absent,
            Some(value) => value.as_u64().map_or(Self::Invalid, Self::Value),
        }
    }

    fn merge(&mut self, newer: Self) {
        if newer != Self::Absent {
            *self = newer;
        }
    }

    fn is_reported(self) -> bool {
        self != Self::Absent
    }
}

/// Which provider's category layout a [`UsageCategories`] carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CategoryFamily {
    /// `input_tokens` + `cache_creation_input_tokens` +
    /// `cache_read_input_tokens`; `output_tokens`.
    Anthropic,
    /// `promptTokenCount` + `toolUsePromptTokenCount`; `candidatesTokenCount`
    /// + `thoughtsTokenCount`; `totalTokenCount`. proto3 JSON omits zero
    /// counters, so an omitted base is zero when a sibling on its side is
    /// reported.
    Gemini,
    /// `inputTokens` + `cacheReadInputTokens` + `cacheWriteInputTokens`;
    /// `outputTokens`; `totalTokens`.
    BedrockConverse,
}

/// Raw token categories behind a folded prompt/completion pair.
///
/// The billed input of an Anthropic Messages or Bedrock Converse request is
/// the uncached input PLUS prompt-cache writes and reads, which those
/// providers report beside the base counter rather than inside it (Anthropic:
/// `total_input_tokens = cache_read_input_tokens + cache_creation_input_tokens
/// + input_tokens`; AWS: `inputTokens + cacheReadInputTokens +
/// cacheWriteInputTokens`). Gemini bills `toolUsePromptTokenCount` as input
/// and `thoughtsTokenCount` as output outside `candidatesTokenCount`, and
/// documents `totalTokenCount` as prompt + tool-use prompt + thoughts +
/// candidates. Folding here is the single rule every metering surface uses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsageCategories {
    family: Option<CategoryFamily>,
    prompt_base: Counter,
    prompt_extras: [Counter; 2],
    completion_base: Counter,
    completion_extra: Counter,
    reported_total: Counter,
}

impl UsageCategories {
    fn anthropic(usage: Option<&Value>) -> Self {
        Self {
            family: Some(CategoryFamily::Anthropic),
            prompt_base: Counter::read(usage, "input_tokens"),
            prompt_extras: [
                Counter::read(usage, "cache_creation_input_tokens"),
                Counter::read(usage, "cache_read_input_tokens"),
            ],
            completion_base: Counter::read(usage, "output_tokens"),
            completion_extra: Counter::Absent,
            reported_total: Counter::Absent,
        }
    }

    fn gemini(usage: Option<&Value>) -> Self {
        let candidates = match Counter::read(usage, "candidatesTokenCount") {
            Counter::Absent => Counter::read(usage, "completionTokenCount"),
            reported => reported,
        };
        Self {
            family: Some(CategoryFamily::Gemini),
            prompt_base: Counter::read(usage, "promptTokenCount"),
            prompt_extras: [
                Counter::read(usage, "toolUsePromptTokenCount"),
                Counter::Absent,
            ],
            completion_base: candidates,
            completion_extra: Counter::read(usage, "thoughtsTokenCount"),
            reported_total: Counter::read(usage, "totalTokenCount"),
        }
    }

    /// `None` when the document carries no Converse `usage` counters at all.
    fn bedrock_converse(usage: Option<&Value>) -> Option<Self> {
        let categories = Self {
            family: Some(CategoryFamily::BedrockConverse),
            prompt_base: Counter::read(usage, "inputTokens"),
            prompt_extras: [
                Counter::read(usage, "cacheReadInputTokens"),
                Counter::read(usage, "cacheWriteInputTokens"),
            ],
            completion_base: Counter::read(usage, "outputTokens"),
            completion_extra: Counter::Absent,
            reported_total: Counter::read(usage, "totalTokens"),
        };
        let reported = categories.prompt_base.is_reported()
            || categories.prompt_extras.iter().any(|c| c.is_reported())
            || categories.completion_base.is_reported()
            || categories.reported_total.is_reported();
        reported.then_some(categories)
    }

    /// `amazon-bedrock-invocationMetrics`, in the Anthropic layout (uncached
    /// input + cache write + cache read; output), so terminal metrics merge
    /// with the Anthropic events of the same InvokeModel stream instead of
    /// replacing their cache categories.
    fn bedrock_invocation_metrics(metrics: Option<&Value>) -> Self {
        Self {
            family: Some(CategoryFamily::Anthropic),
            prompt_base: Counter::read(metrics, "inputTokenCount"),
            prompt_extras: [
                Counter::read(metrics, "cacheWriteInputTokenCount"),
                Counter::read(metrics, "cacheReadInputTokenCount"),
            ],
            completion_base: Counter::read(metrics, "outputTokenCount"),
            completion_extra: Counter::Absent,
            reported_total: Counter::Absent,
        }
    }

    fn zero_omitted_base(&self) -> bool {
        self.family == Some(CategoryFamily::Gemini)
    }

    fn merge(&mut self, newer: &Self) {
        if self.family != newer.family {
            *self = newer.clone();
            return;
        }
        self.prompt_base.merge(newer.prompt_base);
        for (current, newer) in self.prompt_extras.iter_mut().zip(newer.prompt_extras) {
            current.merge(newer);
        }
        self.completion_base.merge(newer.completion_base);
        self.completion_extra.merge(newer.completion_extra);
        self.reported_total.merge(newer.reported_total);
    }

    /// Fold one side. `Absent` when the side was not reported (or only a
    /// category was reported for a provider that always sends the base);
    /// `Invalid` when any of its counters is malformed or their sum overflows
    /// — never publish a partial or wrapped count as complete.
    fn side(&self, base: Counter, extras: &[Counter]) -> Counter {
        if base == Counter::Invalid || extras.contains(&Counter::Invalid) {
            return Counter::Invalid;
        }
        let base = match base {
            Counter::Value(base) => base,
            Counter::Absent
                if self.zero_omitted_base() && extras.iter().any(|c| c.is_reported()) =>
            {
                0
            }
            _ => return Counter::Absent,
        };
        let mut sum = base;
        for counter in extras {
            if let Counter::Value(value) = counter {
                match sum.checked_add(*value) {
                    Some(next) => sum = next,
                    None => return Counter::Invalid,
                }
            }
        }
        Counter::Value(sum)
    }

    /// `(prompt invalid, completion invalid)` for the merged state.
    ///
    /// A malformed provider TOTAL invalidates both: the components can then no
    /// longer be trusted to rebuild a complete total, so the usage is
    /// unmetered as a whole rather than resynthesized from them.
    pub(crate) fn invalid_sides(&self) -> (bool, bool) {
        if self.reported_total == Counter::Invalid {
            return (true, true);
        }
        (
            self.side(self.prompt_base, &self.prompt_extras) == Counter::Invalid,
            self.side(self.completion_base, &[self.completion_extra]) == Counter::Invalid,
        )
    }

    fn fold(&self) -> (Option<u64>, Option<u64>, Option<u64>) {
        let prompt = self.side(self.prompt_base, &self.prompt_extras);
        let completion = self.side(self.completion_base, &[self.completion_extra]);
        let value = |side: Counter| match side {
            Counter::Value(value) => Some(value),
            _ => None,
        };
        // A malformed or overflowing side also invalidates the total: the
        // whole usage is then unmetered rather than partially counted.
        if self.reported_total == Counter::Invalid {
            return (None, None, None);
        }
        if prompt == Counter::Invalid || completion == Counter::Invalid {
            return (value(prompt), value(completion), None);
        }
        let (prompt, completion) = (value(prompt), value(completion));
        let total = match self.reported_total {
            // The provider total stays authoritative (it may cover a category
            // this parser does not model) but never below the components the
            // same usage reports, even when only one side is present.
            Counter::Value(reported) => {
                let known = match (prompt, completion) {
                    (None, None) => Some(0),
                    (p, c) => p.unwrap_or(0).checked_add(c.unwrap_or(0)),
                };
                known.map(|known| reported.max(known))
            }
            // Without a provider total, only both sides make a complete one.
            _ => match (prompt, completion) {
                (Some(p), Some(c)) => p.checked_add(c),
                _ => None,
            },
        };
        (prompt, completion, total)
    }

    /// Merge `newer`'s categories into this running state and return `newer`
    /// with its counters replaced by the fold of the MERGED categories, so a
    /// cumulative consumer sees the whole billed count even when this update
    /// restated only some categories. A usage without categories passes
    /// through unchanged.
    pub(crate) fn absorb(&mut self, mut newer: AiTokenUsage) -> AiTokenUsage {
        if newer.categories.family.is_none() {
            return newer;
        }
        self.merge(&newer.categories);
        let (prompt, completion, total) = self.fold();
        newer.prompt_tokens = prompt;
        newer.completion_tokens = completion;
        newer.total_tokens = total;
        newer
    }
}

impl AiTokenUsage {
    fn apply_categories(&mut self, categories: UsageCategories) {
        let (prompt, completion, total) = categories.fold();
        self.prompt_tokens = prompt;
        self.completion_tokens = completion;
        self.total_tokens = total;
        self.categories = categories;
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

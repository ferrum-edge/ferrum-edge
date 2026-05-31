//! AI Semantic Cache Plugin
//!
//! Caches LLM responses keyed by normalized prompts to avoid redundant API calls.
//! When the same (or equivalently formatted) prompt arrives again within the TTL,
//! the cached response is returned immediately without contacting the backend.
//!
//! # v1 — Normalized Exact Match
//!
//! Prompts are normalized before hashing:
//! - Messages array is sorted by role, then by content
//! - Content text is lowercased and whitespace-collapsed
//! - Model name is included in the key (different models = different cache entries)
//! - Temperature, top_p, and other sampling parameters are optionally included
//!
//! This catches the most common duplicate case: identical or trivially reformatted
//! prompts from different users/requests.
//!
//! # v2 — Optional Semantic Similarity
//!
//! When `semantic_similarity_enabled` is set, exact Redis/local lookups still run
//! first. On an exact miss, the plugin computes an embedding through a
//! configurable embedding provider, searches a local HNSW vector index
//! (`instant-distance`), and returns cached responses whose cosine similarity is
//! above the configured threshold. Semantic matches are scoped by the same
//! safety-critical request dimensions as exact keys (proxy, consumer, model,
//! params, tools, response format, stream flag, system prompt, and
//! system/developer message instructions).
//!
//! # Storage
//!
//! - **local** (default): In-memory `DashMap` with TTL-based eviction
//! - **redis**: Centralized cache via Redis/Valkey for multi-instance deployments,
//!   using the shared `RedisRateLimitClient` infrastructure

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use instant_distance::{Builder as HnswBuilder, HnswMap, Point as HnswPoint, Search as HnswSearch};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::mem;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tracing::debug;

use super::utils::body_transform::is_json_content_type;
use super::utils::cache_headers::sanitize_cached_headers;
use super::utils::redis_rate_limiter::{RedisConfig, RedisRateLimitClient};
use super::{Plugin, PluginHttpClient, PluginResult, RequestContext};

const VECTOR_REBUILD_INTERVAL_SECONDS: u64 = 30;

const RESPONSE_SHAPE_FIELDS: &[&str] = &[
    "tools",
    "tool_choice",
    "response_format",
    "seed",
    "logit_bias",
    "n",
    "stop",
    "presence_penalty",
    "frequency_penalty",
    "logprobs",
    "top_logprobs",
    "parallel_tool_calls",
    "reasoning_effort",
    "modalities",
    "prediction",
    "service_tier",
];

/// A cached LLM response.
#[derive(Debug, Clone)]
struct CacheEntry {
    status_code: u16,
    headers: HashMap<String, String>,
    body: Bytes,
    inserted_at: Instant,
    approx_size: usize,
    semantic_scope_key: Option<String>,
    embedding: Option<EmbeddingPoint>,
}

struct CachedResponse {
    status_code: u16,
    headers: HashMap<String, String>,
    body: Bytes,
}

#[derive(Debug, Clone)]
struct SemanticConfig {
    provider: EmbeddingProvider,
    endpoint: String,
    model: Option<String>,
    api_key: Option<String>,
    auth_header: String,
    auth_scheme: String,
    input_type: Option<String>,
    output_dimension: Option<usize>,
    similarity_threshold: f32,
    max_candidates: usize,
    request_timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EmbeddingProvider {
    OpenAi,
    AzureOpenAi,
    Mistral,
    Voyage,
    Cohere,
    GoogleGemini,
    GoogleVertex,
    BedrockTitan,
    BedrockCohere,
}

impl EmbeddingProvider {
    fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "openai" | "openai_compatible" | "openai-compatible" => Ok(Self::OpenAi),
            "azure" | "azure_openai" | "azure-openai" => Ok(Self::AzureOpenAi),
            "mistral" => Ok(Self::Mistral),
            "voyage" | "voyageai" | "voyage_ai" | "anthropic" | "claude" => Ok(Self::Voyage),
            "cohere" => Ok(Self::Cohere),
            "google" | "google_gemini" | "google-gemini" | "gemini" => Ok(Self::GoogleGemini),
            "google_vertex" | "google-vertex" | "vertex" | "vertex_ai" | "vertex-ai" => {
                Ok(Self::GoogleVertex)
            }
            "bedrock_titan" | "bedrock-titan" | "amazon_titan" | "amazon-titan" => {
                Ok(Self::BedrockTitan)
            }
            "bedrock_cohere" | "bedrock-cohere" | "cohere_bedrock" | "cohere-bedrock" => {
                Ok(Self::BedrockCohere)
            }
            other => Err(format!(
                "ai_semantic_cache: unknown 'semantic_embedding_provider' value '{other}' \
                 (expected openai, azure_openai, mistral, voyage, cohere, google_gemini, \
                 google_vertex, bedrock_titan, or bedrock_cohere)"
            )),
        }
    }

    fn default_auth_header(self) -> &'static str {
        match self {
            Self::AzureOpenAi => "api-key",
            Self::GoogleGemini => "x-goog-api-key",
            _ => "Authorization",
        }
    }

    fn default_auth_scheme(self) -> &'static str {
        match self {
            Self::AzureOpenAi | Self::GoogleGemini => "",
            _ => "Bearer",
        }
    }
}

#[derive(Debug, Clone)]
struct EmbeddingPoint {
    values: Vec<f32>,
}

impl EmbeddingPoint {
    fn from_raw(values: Vec<f32>) -> Result<Self, String> {
        if values.is_empty() {
            return Err("embedding vector must not be empty".to_string());
        }

        let mut norm_squared = 0.0_f32;
        for value in &values {
            if !value.is_finite() {
                return Err("embedding vector contains a non-finite value".to_string());
            }
            norm_squared += value * value;
        }

        if norm_squared <= f32::EPSILON {
            return Err("embedding vector must not have zero length".to_string());
        }

        let norm = norm_squared.sqrt();
        Ok(Self {
            values: values.into_iter().map(|value| value / norm).collect(),
        })
    }

    fn to_vec(&self) -> Vec<f32> {
        self.values.clone()
    }

    fn approx_size(&self) -> usize {
        mem::size_of::<Self>() + self.values.capacity() * mem::size_of::<f32>()
    }
}

impl HnswPoint for EmbeddingPoint {
    fn distance(&self, other: &Self) -> f32 {
        if self.values.len() != other.values.len() {
            return 2.0;
        }

        let dot = self
            .values
            .iter()
            .zip(&other.values)
            .fold(0.0_f32, |acc, (left, right)| acc + left * right);
        (1.0 - dot).clamp(0.0, 2.0)
    }
}

#[derive(Debug, Clone)]
struct VectorEntry {
    cache_key: String,
    scope_key: String,
}

struct VectorSnapshot {
    index: HnswMap<EmbeddingPoint, VectorEntry>,
}

pub struct AiSemanticCache {
    /// Cache TTL.
    ttl: Duration,
    /// Maximum number of cached entries.
    max_entries: usize,
    /// Maximum size of a single cached response body in bytes.
    max_entry_size_bytes: usize,
    /// Maximum total cache size in bytes.
    max_total_size_bytes: usize,
    /// Whether to include the model name in the cache key.
    include_model_in_key: bool,
    /// Whether to include sampling parameters (temperature, top_p) in the cache key.
    include_params_in_key: bool,
    /// Whether to scope cache entries by authenticated consumer.
    scope_by_consumer: bool,
    /// Optional semantic-similarity configuration.
    semantic: Option<SemanticConfig>,
    /// Shared outbound HTTP client for embedding calls.
    http_client: PluginHttpClient,
    /// Local in-memory cache.
    cache: Arc<DashMap<String, CacheEntry>>,
    /// Immutable HNSW snapshot for semantic lookup.
    vector_index: Arc<ArcSwapOption<VectorSnapshot>>,
    /// Total approximate size of all cached entries.
    total_size: Arc<AtomicUsize>,
    /// Optional Redis client for centralized caching.
    redis_client: Option<Arc<RedisRateLimitClient>>,
    /// Counter for periodic cleanup scheduling.
    last_cleanup: AtomicU64,
    /// Last time the semantic vector snapshot was rebuilt.
    last_vector_rebuild: Arc<AtomicU64>,
    /// Whether local semantic entries changed since the latest vector rebuild.
    vector_index_dirty: Arc<AtomicBool>,
    /// Guards detached HNSW rebuild scheduling.
    vector_index_rebuild_running: Arc<AtomicBool>,
}

/// Serializable form of CacheEntry for Redis storage.
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
struct SerializableCacheEntry {
    status_code: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    semantic_scope_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    embedding: Option<Vec<f32>>,
}

impl AiSemanticCache {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        if !config.is_object() {
            return Err("ai_semantic_cache: config must be an object".to_string());
        }

        let ttl_seconds = optional_positive_u64(config, "ttl_seconds")?.unwrap_or(300);
        let ttl = Duration::from_secs(ttl_seconds);

        let max_entries = optional_positive_usize(config, "max_entries")?.unwrap_or(10_000);
        let max_entry_size_bytes =
            optional_positive_usize(config, "max_entry_size_bytes")?.unwrap_or(1_048_576); // 1 MiB default
        let max_total_size_bytes =
            optional_positive_usize(config, "max_total_size_bytes")?.unwrap_or(104_857_600); // 100 MiB default

        let include_model_in_key = optional_bool(config, "include_model_in_key")?.unwrap_or(true);
        // SECURITY: Default `true` so two requests that differ only in
        // sampling parameters (temperature, top_p, max_tokens) cannot collapse
        // to the same cache entry and serve a wrong-shape response. Operators
        // who explicitly want cross-parameter cache reuse must set this to
        // `false`.
        let include_params_in_key = optional_bool(config, "include_params_in_key")?.unwrap_or(true);
        // SECURITY: Default `true` so cached responses are not replayed across
        // different authenticated consumers. Operators who explicitly want a
        // shared cache (e.g., a public LLM proxy with no per-tenant data)
        // must set this to `false`.
        let scope_by_consumer = optional_bool(config, "scope_by_consumer")?.unwrap_or(true);
        let semantic = parse_semantic_config(config)?;

        // Build optional Redis client
        let default_redis_prefix = default_redis_key_prefix(http_client.namespace());
        let redis_client =
            RedisConfig::from_plugin_config(config, &default_redis_prefix)?.map(|redis_config| {
                let dns_cache = http_client.dns_cache();
                let tls_no_verify = http_client.tls_no_verify();
                let tls_ca_bundle_path = http_client.tls_ca_bundle_path();
                Arc::new(RedisRateLimitClient::new(
                    redis_config,
                    dns_cache.cloned(),
                    tls_no_verify,
                    tls_ca_bundle_path,
                ))
            });

        Ok(Self {
            ttl,
            max_entries,
            max_entry_size_bytes,
            max_total_size_bytes,
            include_model_in_key,
            include_params_in_key,
            scope_by_consumer,
            semantic,
            http_client,
            cache: Arc::new(DashMap::new()),
            vector_index: Arc::new(ArcSwapOption::empty()),
            total_size: Arc::new(AtomicUsize::new(0)),
            redis_client,
            last_cleanup: AtomicU64::new(0),
            last_vector_rebuild: Arc::new(AtomicU64::new(0)),
            vector_index_dirty: Arc::new(AtomicBool::new(false)),
            vector_index_rebuild_running: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Build a normalized cache key from the request body.
    ///
    /// Normalization steps:
    /// 1. Parse the JSON request body
    /// 2. Optionally scope by proxy and authenticated consumer
    /// 3. Optionally include model name and sampling parameters
    /// 4. Lowercase and collapse whitespace in `messages[*].content`
    /// 5. Include the Anthropic top-level `system` prompt (string or array form)
    /// 6. Include `tools` / `tool_choice` / `response_format` / `seed` /
    ///    `logit_bias` / `stream` when present — any change to these fields
    ///    materially changes the response and must not collapse to the same key
    /// 7. SHA-256 hash the normalized representation
    fn build_cache_key(&self, ctx: &RequestContext, body: &Value) -> Option<String> {
        let mut key_input = String::with_capacity(512);
        let mut has_part = false;

        // Proxy scope
        if let Some(ref proxy) = ctx.matched_proxy {
            start_key_part(&mut key_input, &mut has_part);
            key_input.push_str(&proxy.id);
        }

        // Consumer scope
        if self.scope_by_consumer
            && let Some(identity) = ctx.effective_identity()
        {
            start_key_part(&mut key_input, &mut has_part);
            let _ = write!(&mut key_input, "{identity}");
        }

        // Model
        if self.include_model_in_key
            && let Some(model) = body.get("model").and_then(|m| m.as_str())
        {
            start_key_part(&mut key_input, &mut has_part);
            key_input.push_str("m:");
            push_ascii_lowercase(&mut key_input, model);
        }

        // Sampling parameters
        if self.include_params_in_key {
            if let Some(temp) = body.get("temperature") {
                start_key_part(&mut key_input, &mut has_part);
                key_input.push_str("t:");
                key_input.push_str(&canonical_param_value(temp));
            }
            if let Some(top_p) = body.get("top_p") {
                start_key_part(&mut key_input, &mut has_part);
                key_input.push_str("p:");
                key_input.push_str(&canonical_param_value(top_p));
            }
            if let Some(max_tokens) = body.get("max_tokens").and_then(|t| t.as_u64()) {
                start_key_part(&mut key_input, &mut has_part);
                let _ = write!(&mut key_input, "mt:{max_tokens}");
            }
        }

        // Messages — the core of the cache key
        if let Some(messages) = body.get("messages").and_then(|m| m.as_array()) {
            start_key_part(&mut key_input, &mut has_part);
            for (index, msg) in messages.iter().enumerate() {
                if index > 0 {
                    key_input.push('|');
                }
                let role = msg
                    .get("role")
                    .and_then(|r| r.as_str())
                    .unwrap_or("unknown");
                let content = self.extract_message_content(msg);
                key_input.push_str(role);
                key_input.push(':');
                key_input.push_str(&content);
            }
            // Sort for order-independence (optional — most LLM APIs are order-sensitive,
            // but we sort to catch trivial reorderings of system/user messages)
            // Actually, message order matters for conversation context, so we preserve order
            // and only normalize content within each message.
        } else {
            // No messages array — not a chat completion request, skip caching
            return None;
        }

        // Top-level `system` prompt (Anthropic Messages API). Included AFTER
        // the messages section so two requests that differ only in their
        // system prompt cannot collapse to the same cache key. Anthropic
        // accepts either a string or an array of content blocks (e.g.
        // `[{"type": "text", "text": "..."}]`); we normalize both forms here.
        if let Some(system) = body.get("system") {
            let normalized = normalize_system_value(system);
            start_key_part(&mut key_input, &mut has_part);
            key_input.push_str("sys:");
            key_input.push_str(&normalized);
        }

        // Other request fields that materially change the response shape or
        // selection. Including these prevents cross-prompt poisoning where two
        // distinct requests differing only in tool/format/seed/logit-bias/stream
        // configuration would collapse to the same cache entry. We use the
        // canonical JSON serialization (sort_keys not required at this level
        // because it's the user-supplied payload) so any byte-level change
        // breaks the key.
        for field in RESPONSE_SHAPE_FIELDS {
            if let Some(value) = body.get(field) {
                start_key_part(&mut key_input, &mut has_part);
                key_input.push_str(field);
                key_input.push(':');
                let _ = write!(&mut key_input, "{value}");
            }
        }

        // `stream`: stream:true and stream:false produce different wire
        // formats (SSE vs single JSON), so cached non-stream responses must
        // not be replayed to a stream:true caller (or vice versa). We don't
        // actually cache SSE responses (see `on_final_response_body`), but
        // including this prevents a non-streaming MISS-then-store from being
        // served to a streaming client whose stored entry would be wrongly
        // formatted.
        if let Some(stream) = body.get("stream").and_then(|s| s.as_bool()) {
            start_key_part(&mut key_input, &mut has_part);
            let _ = write!(&mut key_input, "stream:{stream}");
        }

        // Hash the key parts into a fixed-size cache key
        let hash = Sha256::digest(key_input.as_bytes());
        Some(hex::encode(hash))
    }

    /// Extract and normalize message content text.
    fn extract_message_content(&self, msg: &Value) -> String {
        let raw = if let Some(content) = msg.get("content").and_then(|c| c.as_str()) {
            content.to_string()
        } else if let Some(parts) = msg.get("content").and_then(|c| c.as_array()) {
            // Multimodal: extract text parts only
            let mut texts = Vec::new();
            for part in parts {
                if part.get("type").and_then(|t| t.as_str()) == Some("text")
                    && let Some(text) = part.get("text").and_then(|t| t.as_str())
                {
                    texts.push(text.to_string());
                }
            }
            texts.join(" ")
        } else {
            String::new()
        };

        // Normalize: lowercase and collapse whitespace
        normalize_text(&raw)
    }

    fn build_semantic_scope_key(&self, ctx: &RequestContext, body: &Value) -> Option<String> {
        let messages = body.get("messages").and_then(|m| m.as_array())?;
        let mut key_input = String::with_capacity(512);
        let mut has_part = false;

        if let Some(ref proxy) = ctx.matched_proxy {
            start_key_part(&mut key_input, &mut has_part);
            key_input.push_str(&proxy.id);
        }

        if self.scope_by_consumer
            && let Some(identity) = ctx.effective_identity()
        {
            start_key_part(&mut key_input, &mut has_part);
            let _ = write!(&mut key_input, "{identity}");
        }

        if self.include_model_in_key
            && let Some(model) = body.get("model").and_then(|m| m.as_str())
        {
            start_key_part(&mut key_input, &mut has_part);
            key_input.push_str("m:");
            push_ascii_lowercase(&mut key_input, model);
        }

        if self.include_params_in_key {
            if let Some(temp) = body.get("temperature") {
                start_key_part(&mut key_input, &mut has_part);
                key_input.push_str("t:");
                key_input.push_str(&canonical_param_value(temp));
            }
            if let Some(top_p) = body.get("top_p") {
                start_key_part(&mut key_input, &mut has_part);
                key_input.push_str("p:");
                key_input.push_str(&canonical_param_value(top_p));
            }
            if let Some(max_tokens) = body.get("max_tokens").and_then(|t| t.as_u64()) {
                start_key_part(&mut key_input, &mut has_part);
                let _ = write!(&mut key_input, "mt:{max_tokens}");
            }
        }

        start_key_part(&mut key_input, &mut has_part);
        key_input.push_str("roles:");
        for (index, msg) in messages.iter().enumerate() {
            if index > 0 {
                key_input.push('|');
            }
            let role = msg
                .get("role")
                .and_then(|r| r.as_str())
                .unwrap_or("unknown");
            push_ascii_lowercase(&mut key_input, role);
        }

        let mut has_instruction_message = false;
        for msg in messages {
            let role = msg
                .get("role")
                .and_then(|r| r.as_str())
                .unwrap_or("unknown");
            if !matches!(role.to_ascii_lowercase().as_str(), "system" | "developer") {
                continue;
            }
            let content = self.extract_message_content(msg);
            if content.is_empty() {
                continue;
            }
            if !has_instruction_message {
                start_key_part(&mut key_input, &mut has_part);
                key_input.push_str("instructions:");
                has_instruction_message = true;
            } else {
                key_input.push('|');
            }
            push_ascii_lowercase(&mut key_input, role);
            key_input.push(':');
            let hash = Sha256::digest(content.as_bytes());
            key_input.push_str(&hex::encode(hash));
        }

        if let Some(system) = body.get("system") {
            start_key_part(&mut key_input, &mut has_part);
            key_input.push_str("sys:");
            key_input.push_str(&normalize_system_value(system));
        }

        append_response_shape_fields(body, &mut key_input, &mut has_part);

        let hash = Sha256::digest(key_input.as_bytes());
        Some(hex::encode(hash))
    }

    fn build_semantic_input(&self, body: &Value) -> Option<String> {
        let messages = body.get("messages").and_then(|m| m.as_array())?;
        let mut input = String::with_capacity(512);

        if let Some(system) = body.get("system") {
            let system = normalize_system_value(system);
            if !system.is_empty() {
                input.push_str("system: ");
                input.push_str(&system);
                input.push('\n');
            }
        }

        for msg in messages {
            let role = msg
                .get("role")
                .and_then(|r| r.as_str())
                .unwrap_or("unknown");
            let content = self.extract_message_content(msg);
            if content.is_empty() {
                continue;
            }
            push_ascii_lowercase(&mut input, role);
            input.push_str(": ");
            input.push_str(&content);
            input.push('\n');
        }

        let normalized = input.trim();
        if normalized.is_empty() {
            None
        } else {
            Some(normalized.to_string())
        }
    }

    async fn compute_embedding(&self, input: &str) -> Result<EmbeddingPoint, String> {
        let semantic = self
            .semantic
            .as_ref()
            .ok_or_else(|| "semantic similarity is disabled".to_string())?;

        let payload = build_embedding_request_payload(semantic, input);

        let mut request = self
            .http_client
            .get()
            .post(&semantic.endpoint)
            .timeout(semantic.request_timeout)
            .json(&payload);

        if let Some(api_key) = &semantic.api_key {
            let header_value = if semantic.auth_scheme.is_empty() {
                api_key.clone()
            } else {
                format!("{} {}", semantic.auth_scheme, api_key)
            };
            request = request.header(semantic.auth_header.as_str(), header_value);
        }

        let response = self
            .http_client
            .execute(request, "ai_semantic_cache_embedding")
            .await
            .map_err(|err| format!("embedding request failed: {err}"))?;

        if !response.status().is_success() {
            return Err(format!(
                "embedding endpoint returned HTTP {}",
                response.status()
            ));
        }

        let body: Value = response
            .json()
            .await
            .map_err(|err| format!("embedding response parse failed: {err}"))?;
        parse_embedding_response(&body)
            .and_then(EmbeddingPoint::from_raw)
            .map_err(|err| format!("embedding response invalid: {err}"))
    }

    fn lookup_semantic(
        &self,
        scope_key: &str,
        embedding: &EmbeddingPoint,
    ) -> Option<(CachedResponse, f32, String)> {
        let semantic = self.semantic.as_ref()?;
        let snapshot = self.vector_index.load_full()?;
        let mut search = HnswSearch::default();
        let now = Instant::now();

        for item in snapshot.index.search(embedding, &mut search) {
            let similarity = 1.0 - item.distance;
            if similarity < semantic.similarity_threshold {
                break;
            }
            // The HNSW snapshot is shared by all scopes, so nearest-neighbor
            // search can surface other tenants/models first. Keep the exact
            // scope check; the tradeoff is a safe false miss when same-scope
            // candidates fall outside the configured search window.
            if item.value.scope_key != scope_key {
                continue;
            }
            let Some(entry) = self.cache.get(&item.value.cache_key) else {
                continue;
            };
            if now.duration_since(entry.inserted_at) >= self.ttl {
                continue;
            }
            return Some((
                CachedResponse {
                    status_code: entry.status_code,
                    headers: entry.headers.clone(),
                    body: entry.body.clone(),
                },
                similarity,
                item.value.cache_key.clone(),
            ));
        }

        None
    }

    fn mark_vector_index_dirty(&self) {
        if self.semantic.is_some() {
            self.vector_index_dirty.store(true, Ordering::Relaxed);
        }
    }

    async fn build_vector_snapshot(
        cache: Arc<DashMap<String, CacheEntry>>,
        ttl: Duration,
        max_candidates: usize,
    ) -> Result<Option<HnswMap<EmbeddingPoint, VectorEntry>>, tokio::task::JoinError> {
        tokio::task::spawn_blocking(move || {
            // HnswMap is immutable, so local semantic inserts/removals are
            // made visible in batches. The dirty flag is cleared before this
            // snapshot; any concurrent insert that races this scan re-dirties
            // the index and schedules a later rebuild.
            let now = Instant::now();
            let mut points = Vec::new();
            let mut values = Vec::new();

            for entry in cache.iter() {
                if now.duration_since(entry.inserted_at) >= ttl {
                    continue;
                }
                let (Some(scope_key), Some(embedding)) =
                    (entry.semantic_scope_key.clone(), entry.embedding.clone())
                else {
                    continue;
                };
                points.push(embedding);
                values.push(VectorEntry {
                    cache_key: entry.key().clone(),
                    scope_key,
                });
            }

            if points.is_empty() {
                return None;
            }

            Some(
                HnswBuilder::default()
                    .ef_search(max_candidates)
                    .ef_construction(max_candidates.max(100))
                    .seed(0)
                    .build(points, values),
            )
        })
        .await
    }

    fn store_vector_snapshot_result(
        build_result: Result<Option<HnswMap<EmbeddingPoint, VectorEntry>>, tokio::task::JoinError>,
        vector_index: &ArcSwapOption<VectorSnapshot>,
        dirty: &AtomicBool,
    ) {
        match build_result {
            Ok(Some(index)) => {
                vector_index.store(Some(Arc::new(VectorSnapshot { index })));
            }
            Ok(None) => {
                vector_index.store(None);
            }
            Err(err) => {
                dirty.store(true, Ordering::Release);
                debug!(
                    error = %err,
                    "ai_semantic_cache: semantic vector index rebuild task failed"
                );
            }
        }
    }

    #[allow(dead_code)] // Used by external tests through crate::_test_support; the bin target has no such caller.
    pub(crate) async fn rebuild_vector_index_for_tests(&self) {
        let Some(semantic) = self.semantic.as_ref() else {
            return;
        };

        while self
            .vector_index_rebuild_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            tokio::task::yield_now().await;
        }

        self.vector_index_dirty.store(false, Ordering::Release);
        let build_result =
            Self::build_vector_snapshot(Arc::clone(&self.cache), self.ttl, semantic.max_candidates)
                .await;
        Self::store_vector_snapshot_result(
            build_result,
            self.vector_index.as_ref(),
            self.vector_index_dirty.as_ref(),
        );
        self.last_vector_rebuild
            .store(current_epoch_seconds(), Ordering::Release);
        self.vector_index_rebuild_running
            .store(false, Ordering::Release);
    }

    fn refresh_vector_index_if_due(&self) {
        let Some(semantic) = self.semantic.as_ref() else {
            return;
        };
        if !self.vector_index_dirty.load(Ordering::Acquire) {
            return;
        }

        let now_epoch = current_epoch_seconds();
        let has_snapshot = self.vector_index.load().is_some();
        let last = self.last_vector_rebuild.load(Ordering::Relaxed);
        if has_snapshot && now_epoch.saturating_sub(last) < VECTOR_REBUILD_INTERVAL_SECONDS {
            return;
        }

        if self
            .vector_index_rebuild_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        if !self.vector_index_dirty.swap(false, Ordering::AcqRel) {
            self.vector_index_rebuild_running
                .store(false, Ordering::Release);
            return;
        }

        self.last_vector_rebuild.store(now_epoch, Ordering::Release);
        let cache = Arc::clone(&self.cache);
        let vector_index = Arc::clone(&self.vector_index);
        let dirty = Arc::clone(&self.vector_index_dirty);
        let rebuild_running = Arc::clone(&self.vector_index_rebuild_running);
        let ttl = self.ttl;
        let max_candidates = semantic.max_candidates;

        tokio::spawn(async move {
            let build_result = Self::build_vector_snapshot(cache, ttl, max_candidates).await;
            Self::store_vector_snapshot_result(build_result, vector_index.as_ref(), dirty.as_ref());
            rebuild_running.store(false, Ordering::Release);
        });
    }

    /// Periodic cleanup of expired entries.
    fn cleanup_expired(&self) {
        let now_epoch = current_epoch_seconds();

        let last = self.last_cleanup.load(Ordering::Relaxed);
        if now_epoch.saturating_sub(last) < 30 {
            return;
        }
        if self
            .last_cleanup
            .compare_exchange(last, now_epoch, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let now = Instant::now();
        let mut removed_size = 0usize;
        let mut removed_semantic_entry = false;
        self.cache.retain(|_, entry| {
            if now.duration_since(entry.inserted_at) >= self.ttl {
                removed_size += entry.approx_size;
                removed_semantic_entry |= entry.embedding.is_some();
                false
            } else {
                true
            }
        });
        if removed_size > 0 {
            self.total_size.fetch_sub(removed_size, Ordering::Relaxed);
            if removed_semantic_entry {
                self.mark_vector_index_dirty();
            }
        }

        // Enforce max entries by removing oldest. Use partial-select
        // (`select_nth_unstable_by_key`, average O(n)) instead of a full
        // sort (O(n log n)) — we only need to identify the k oldest, not
        // sort the entire cache.
        if self.cache.len() > self.max_entries {
            let mut entries_with_time: Vec<(String, Instant)> = self
                .cache
                .iter()
                .map(|entry| (entry.key().clone(), entry.value().inserted_at))
                .collect();

            let to_remove = self.cache.len().saturating_sub(self.max_entries);
            if to_remove > 0 && to_remove < entries_with_time.len() {
                // After this call, indices [0..to_remove) hold the
                // `to_remove` oldest entries (in unspecified order among
                // themselves), which is all we need for eviction.
                entries_with_time.select_nth_unstable_by_key(to_remove - 1, |(_, t)| *t);
            }

            let mut removed_semantic_entry = false;
            for (key, _) in entries_with_time.into_iter().take(to_remove) {
                if let Some((_, removed)) = self.cache.remove(&key) {
                    removed_semantic_entry |= removed.embedding.is_some();
                    self.total_size
                        .fetch_sub(removed.approx_size, Ordering::Relaxed);
                }
            }
            if removed_semantic_entry {
                self.mark_vector_index_dirty();
            }
        }
    }
}

fn start_key_part(buffer: &mut String, has_part: &mut bool) {
    if *has_part {
        buffer.push('\n');
    } else {
        *has_part = true;
    }
}

fn current_epoch_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn push_ascii_lowercase(buffer: &mut String, value: &str) {
    for ch in value.chars() {
        buffer.push(ch.to_ascii_lowercase());
    }
}

fn canonical_param_value(value: &Value) -> String {
    value.to_string()
}

fn cache_entry_approx_size(
    body_len: usize,
    headers: &HashMap<String, String>,
    semantic_scope_key: Option<&String>,
    embedding: Option<&EmbeddingPoint>,
) -> usize {
    let header_size = headers
        .iter()
        .map(|(name, value)| name.len().saturating_add(value.len()))
        .sum::<usize>();
    let scope_size = semantic_scope_key.map(|scope| scope.len()).unwrap_or(0);
    let embedding_size = embedding.map(EmbeddingPoint::approx_size).unwrap_or(0);

    // This bounds retained response entries, including their semantic vector
    // copy. The detached HNSW snapshot keeps a separate vector/graph copy and
    // is documented as additional local memory outside this entry budget.
    mem::size_of::<CacheEntry>()
        .saturating_add(body_len)
        .saturating_add(header_size)
        .saturating_add(scope_size)
        .saturating_add(embedding_size)
}

fn append_response_shape_fields(body: &Value, buffer: &mut String, has_part: &mut bool) {
    for field in RESPONSE_SHAPE_FIELDS {
        if let Some(value) = body.get(field) {
            start_key_part(buffer, has_part);
            buffer.push_str(field);
            buffer.push(':');
            let _ = write!(buffer, "{value}");
        }
    }

    if let Some(stream) = body.get("stream").and_then(|s| s.as_bool()) {
        start_key_part(buffer, has_part);
        let _ = write!(buffer, "stream:{stream}");
    }
}

fn insert_optional_model(payload: &mut Value, model: &Option<String>) {
    if let (Value::Object(map), Some(model)) = (payload, model) {
        map.insert("model".to_string(), Value::String(model.clone()));
    }
}

fn insert_optional_string(payload: &mut Value, field: &str, value: &Option<String>) {
    if let (Value::Object(map), Some(value)) = (payload, value) {
        map.insert(field.to_string(), Value::String(value.clone()));
    }
}

fn insert_optional_dimension(payload: &mut Value, field: &str, value: Option<usize>) {
    if let (Value::Object(map), Some(value)) = (payload, value) {
        map.insert(field.to_string(), json!(value));
    }
}

fn build_openai_embedding_payload(semantic: &SemanticConfig, input: &str) -> Value {
    let mut payload = json!({ "input": input });
    insert_optional_model(&mut payload, &semantic.model);
    insert_optional_dimension(&mut payload, "dimensions", semantic.output_dimension);
    payload
}

fn build_embedding_request_payload(semantic: &SemanticConfig, input: &str) -> Value {
    match semantic.provider {
        EmbeddingProvider::OpenAi | EmbeddingProvider::AzureOpenAi | EmbeddingProvider::Mistral => {
            build_openai_embedding_payload(semantic, input)
        }
        EmbeddingProvider::Voyage => {
            let mut payload = json!({ "input": input });
            insert_optional_model(&mut payload, &semantic.model);
            insert_optional_string(&mut payload, "input_type", &semantic.input_type);
            insert_optional_dimension(&mut payload, "output_dimension", semantic.output_dimension);
            payload
        }
        EmbeddingProvider::Cohere => {
            let input_type = semantic
                .input_type
                .as_deref()
                .unwrap_or("search_query")
                .to_string();
            let mut payload = json!({
                "texts": [input],
                "input_type": input_type,
                "embedding_types": ["float"],
            });
            insert_optional_model(&mut payload, &semantic.model);
            insert_optional_dimension(&mut payload, "output_dimension", semantic.output_dimension);
            payload
        }
        EmbeddingProvider::GoogleGemini => {
            let mut payload = json!({
                "content": {
                    "parts": [
                        { "text": input }
                    ]
                }
            });
            insert_optional_model(&mut payload, &semantic.model);
            insert_optional_string(&mut payload, "taskType", &semantic.input_type);
            insert_optional_dimension(
                &mut payload,
                "outputDimensionality",
                semantic.output_dimension,
            );
            payload
        }
        EmbeddingProvider::GoogleVertex => {
            let mut instance = json!({ "content": input });
            insert_optional_string(&mut instance, "task_type", &semantic.input_type);

            let mut payload = json!({ "instances": [instance] });
            if let Some(output_dimension) = semantic.output_dimension
                && let Value::Object(map) = &mut payload
            {
                map.insert(
                    "parameters".to_string(),
                    json!({ "outputDimensionality": output_dimension }),
                );
            }
            payload
        }
        EmbeddingProvider::BedrockTitan => {
            let mut payload = json!({ "inputText": input });
            insert_optional_dimension(&mut payload, "dimensions", semantic.output_dimension);
            payload
        }
        EmbeddingProvider::BedrockCohere => {
            let input_type = semantic
                .input_type
                .as_deref()
                .unwrap_or("search_query")
                .to_string();
            let mut payload = json!({
                "texts": [input],
                "input_type": input_type,
                "embedding_types": ["float"],
            });
            insert_optional_dimension(&mut payload, "output_dimension", semantic.output_dimension);
            payload
        }
    }
}

fn normalize_system_value(system: &Value) -> String {
    if let Some(s) = system.as_str() {
        normalize_text(s)
    } else if let Some(parts) = system.as_array() {
        let mut texts = Vec::with_capacity(parts.len());
        for part in parts {
            if part.get("type").and_then(|t| t.as_str()) == Some("text")
                && let Some(text) = part.get("text").and_then(|t| t.as_str())
            {
                texts.push(text);
            }
        }
        normalize_text(&texts.join(" "))
    } else {
        normalize_text(&system.to_string())
    }
}

fn embedding_array_candidate(value: &Value) -> Option<&Value> {
    let array = value.as_array()?;
    if let Some(first) = array.first()
        && first.as_array().is_some()
    {
        return Some(first);
    }
    Some(value)
}

fn first_embedding_array(body: &Value) -> Option<(&Value, &'static str)> {
    for (path, label) in [
        ("/data/0/embedding", "data[0].embedding"),
        ("/embedding/values", "embedding.values"),
        ("/embedding", "embedding"),
        ("/embeddings/0/values", "embeddings[0].values"),
        ("/embeddings/0", "embeddings[0]"),
        ("/embeddings/float", "embeddings.float[0]"),
        (
            "/predictions/0/embeddings/values",
            "predictions[0].embeddings.values",
        ),
        (
            "/predictions/0/embeddings/float",
            "predictions[0].embeddings.float[0]",
        ),
        ("/embeddingsByType/float", "embeddingsByType.float"),
        ("/embeddingByTypes/float", "embeddingByTypes.float"),
        ("/embeddings_by_type/float", "embeddings_by_type.float"),
        ("/results/0/embedding", "results[0].embedding"),
    ] {
        if let Some(value) = body.pointer(path).and_then(embedding_array_candidate) {
            return Some((value, label));
        }
    }
    None
}

fn parse_embedding_response(body: &Value) -> Result<Vec<f32>, String> {
    let (embedding, label) = first_embedding_array(body).ok_or_else(|| {
        "missing embedding array at data[0].embedding, embedding, embedding.values, \
         embeddings[0], embeddings.float[0], predictions[0].embeddings.values, \
         embeddingsByType.float, or results[0].embedding"
            .to_string()
    })?;

    let values = embedding
        .as_array()
        .ok_or_else(|| format!("embedding field at {label} must be an array"))?;
    let mut result = Vec::with_capacity(values.len());
    for value in values {
        let Some(number) = value.as_f64() else {
            return Err(format!("embedding array values at {label} must be numbers"));
        };
        if !number.is_finite() || number < f32::MIN as f64 || number > f32::MAX as f64 {
            return Err(format!(
                "embedding array at {label} contains an out-of-range value"
            ));
        }
        result.push(number as f32);
    }
    Ok(result)
}

/// Normalize text: lowercase, collapse whitespace to single spaces, trim.
///
/// Single-pass: previously called `to_ascii_lowercase()` first (one extra
/// allocation) then iterated chars to collapse whitespace. The lowercase
/// step is now folded into the iteration so the function does one pass and
/// one allocation instead of two.
fn normalize_text(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut prev_was_space = true; // trim leading
    for ch in text.chars() {
        if ch.is_whitespace() {
            if !prev_was_space {
                result.push(' ');
                prev_was_space = true;
            }
        } else {
            result.push(ch.to_ascii_lowercase());
            prev_was_space = false;
        }
    }
    // Trim trailing space
    if result.ends_with(' ') {
        result.pop();
    }
    result
}

#[async_trait]
impl Plugin for AiSemanticCache {
    fn name(&self) -> &str {
        "ai_semantic_cache"
    }

    fn priority(&self) -> u16 {
        super::priority::AI_SEMANTIC_CACHE
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_ONLY_PROTOCOLS
    }

    fn requires_request_body_before_before_proxy(&self) -> bool {
        true
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        ctx.method == "POST"
            && ctx
                .headers
                .get("content-type")
                .is_some_and(|ct| is_json_content_type(ct))
    }

    fn requires_response_body_buffering(&self) -> bool {
        true
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Only cache POST requests with JSON body
        if ctx.method != "POST" {
            return PluginResult::Continue;
        }

        let content_type = headers
            .get("content-type")
            .map(|s| s.as_str())
            .unwrap_or("");
        if !is_json_content_type(content_type) {
            return PluginResult::Continue;
        }

        // Get request body
        let body_str = match ctx.metadata.get("request_body") {
            Some(b) if !b.is_empty() => b.as_str(),
            _ => return PluginResult::Continue,
        };

        let json: Value = match serde_json::from_str(body_str) {
            Ok(v) => v,
            Err(_) => return PluginResult::Continue,
        };

        // Build cache key
        let cache_key = match self.build_cache_key(ctx, &json) {
            Some(k) => k,
            None => return PluginResult::Continue,
        };

        // Periodic cleanup
        self.cleanup_expired();

        // Check Redis first (centralized cache across instances)
        if let Some(ref redis) = self.redis_client
            && redis.is_available()
        {
            let redis_key = redis.make_key(&[&cache_key]);
            if let Ok(Some(data)) = redis.get_bytes(&redis_key).await
                && let Ok(entry) = serde_json::from_slice::<SerializableCacheEntry>(&data)
            {
                debug!(
                    cache_key = %cache_key,
                    "ai_semantic_cache: Redis cache HIT, returning cached response"
                );
                let mut response_headers = entry.headers.clone();
                response_headers.insert("x-ai-cache-status".to_string(), "HIT".to_string());
                ctx.metadata
                    .insert("ai_cache_status".to_string(), "HIT".to_string());
                return PluginResult::RejectBinary {
                    status_code: entry.status_code,
                    body: Bytes::from(entry.body),
                    headers: response_headers,
                };
            }
        }

        // Check local cache
        if let Some(entry) = self.cache.get(&cache_key) {
            if Instant::now().duration_since(entry.inserted_at) < self.ttl {
                debug!(
                    cache_key = %cache_key,
                    "ai_semantic_cache: cache HIT, returning cached response"
                );
                let mut response_headers = entry.headers.clone();
                response_headers.insert("x-ai-cache-status".to_string(), "HIT".to_string());
                ctx.metadata
                    .insert("ai_cache_status".to_string(), "HIT".to_string());
                return PluginResult::RejectBinary {
                    status_code: entry.status_code,
                    body: entry.body.clone(),
                    headers: response_headers,
                };
            }
            // Expired — remove
            drop(entry);
            if let Some((_, removed)) = self.cache.remove(&cache_key) {
                self.total_size
                    .fetch_sub(removed.approx_size, Ordering::Relaxed);
                if removed.embedding.is_some() {
                    self.mark_vector_index_dirty();
                    self.refresh_vector_index_if_due();
                }
            }
        }

        self.refresh_vector_index_if_due();

        if self.semantic.is_some()
            && let (Some(scope_key), Some(input)) = (
                self.build_semantic_scope_key(ctx, &json),
                self.build_semantic_input(&json),
            )
        {
            match self.compute_embedding(&input).await {
                Ok(embedding) => {
                    if let Some((entry, similarity, matched_key)) =
                        self.lookup_semantic(&scope_key, &embedding)
                    {
                        debug!(
                            cache_key = %matched_key,
                            similarity = similarity,
                            "ai_semantic_cache: semantic cache HIT, returning cached response"
                        );
                        let mut response_headers = entry.headers.clone();
                        response_headers.insert("x-ai-cache-status".to_string(), "HIT".to_string());
                        response_headers
                            .insert("x-ai-cache-match".to_string(), "semantic".to_string());
                        ctx.metadata
                            .insert("ai_cache_status".to_string(), "HIT".to_string());
                        ctx.metadata
                            .insert("ai_cache_match".to_string(), "semantic".to_string());
                        ctx.metadata.insert(
                            "ai_cache_similarity".to_string(),
                            format!("{similarity:.6}"),
                        );
                        return PluginResult::RejectBinary {
                            status_code: entry.status_code,
                            body: entry.body.clone(),
                            headers: response_headers,
                        };
                    }

                    ctx.ai_semantic_cache_embedding = Some(embedding.to_vec());
                    ctx.ai_semantic_cache_scope_key = Some(scope_key);
                }
                Err(err) => {
                    debug!(
                        error = %err,
                        "ai_semantic_cache: semantic embedding unavailable; continuing exact-cache miss"
                    );
                }
            }
        }

        // Cache miss — store the key for on_final_response_body
        debug!(
            cache_key = %cache_key,
            "ai_semantic_cache: cache MISS"
        );
        ctx.metadata.insert("_ai_cache_key".to_string(), cache_key);
        ctx.metadata
            .insert("ai_cache_status".to_string(), "MISS".to_string());

        PluginResult::Continue
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Inject cache status header
        if let Some(status) = ctx.metadata.get("ai_cache_status") {
            response_headers.insert("x-ai-cache-status".to_string(), status.clone());
        }
        PluginResult::Continue
    }

    async fn on_final_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Only cache successful JSON responses
        if !(200..300).contains(&response_status) {
            return PluginResult::Continue;
        }

        let cache_key = match ctx.metadata.get("_ai_cache_key") {
            Some(k) => k.clone(),
            None => return PluginResult::Continue,
        };

        // Don't cache streaming responses
        let content_type = response_headers
            .get("content-type")
            .map(|s| s.as_str())
            .unwrap_or("");
        if content_type.contains("event-stream") {
            debug!("ai_semantic_cache: skipping SSE streaming response");
            return PluginResult::Continue;
        }

        // Size checks
        if body.len() > self.max_entry_size_bytes {
            debug!(
                cache_key = %cache_key,
                body_size = body.len(),
                max_size = self.max_entry_size_bytes,
                "ai_semantic_cache: response exceeds max_entry_size_bytes, skipping"
            );
            return PluginResult::Continue;
        }

        // Strip security-sensitive headers before caching. Cookies, auth
        // tokens, per-request trace IDs, and rate-limit counters from the
        // original response would otherwise be replayed verbatim to every
        // cache-hit consumer — leaking session state and misleading
        // downstream clients about their own rate-limit/trace context.
        let safe_headers = sanitize_cached_headers(response_headers);
        let semantic_scope_key = ctx.ai_semantic_cache_scope_key.take();
        let embedding = ctx
            .ai_semantic_cache_embedding
            .take()
            .and_then(|values| EmbeddingPoint::from_raw(values).ok());
        let approx_size = cache_entry_approx_size(
            body.len(),
            &safe_headers,
            semantic_scope_key.as_ref(),
            embedding.as_ref(),
        );

        let current_total = self.total_size.load(Ordering::Relaxed);
        if current_total.saturating_add(approx_size) > self.max_total_size_bytes {
            debug!(
                cache_key = %cache_key,
                entry_size = approx_size,
                max_total = self.max_total_size_bytes,
                "ai_semantic_cache: total cache size would exceed limit, skipping"
            );
            return PluginResult::Continue;
        }

        let entry = CacheEntry {
            status_code: response_status,
            headers: safe_headers.clone(),
            body: Bytes::from(body.to_vec()),
            inserted_at: Instant::now(),
            approx_size,
            semantic_scope_key: semantic_scope_key.clone(),
            embedding: embedding.clone(),
        };

        let mut replaced_semantic_entry = false;
        // Remove old entry size if replacing
        if let Some((_, old)) = self.cache.remove(&cache_key) {
            replaced_semantic_entry = old.embedding.is_some();
            self.total_size
                .fetch_sub(old.approx_size, Ordering::Relaxed);
        }
        self.total_size
            .fetch_add(entry.approx_size, Ordering::Relaxed);
        self.cache.insert(cache_key.clone(), entry);
        if replaced_semantic_entry || embedding.is_some() {
            self.mark_vector_index_dirty();
            self.refresh_vector_index_if_due();
        }

        // Also store in Redis if configured
        if let Some(ref redis) = self.redis_client
            && redis.is_available()
        {
            let serializable = SerializableCacheEntry {
                status_code: response_status,
                headers: safe_headers,
                body: body.to_vec(),
                semantic_scope_key: None,
                embedding: None,
            };
            if let Ok(data) = serde_json::to_vec(&serializable) {
                let redis_key = redis.make_key(&[&cache_key]);
                let ttl_seconds = self.ttl.as_secs().max(1);
                let _ = redis
                    .set_bytes_with_expire(&redis_key, &data, ttl_seconds)
                    .await;
            }
        }

        PluginResult::Continue
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        if let Some(ref redis) = self.redis_client {
            redis.warmup_hostname().into_iter().collect()
        } else {
            Vec::new()
        }
    }

    fn tracked_keys_count(&self) -> Option<usize> {
        Some(self.cache.len())
    }
}

fn optional_positive_u64(config: &Value, field: &'static str) -> Result<Option<u64>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(value) = value.as_u64() else {
        return Err(format!(
            "ai_semantic_cache: '{field}' must be an integer greater than zero"
        ));
    };
    if value == 0 {
        return Err(format!(
            "ai_semantic_cache: '{field}' must be greater than zero"
        ));
    }
    Ok(Some(value))
}

fn optional_positive_usize(config: &Value, field: &'static str) -> Result<Option<usize>, String> {
    let Some(value) = optional_positive_u64(config, field)? else {
        return Ok(None);
    };
    usize::try_from(value)
        .map(Some)
        .map_err(|_| format!("ai_semantic_cache: '{field}' is too large for this platform"))
}

fn optional_bool(config: &Value, field: &'static str) -> Result<Option<bool>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| format!("ai_semantic_cache: '{field}' must be a boolean"))
}

fn optional_string(config: &Value, field: &'static str) -> Result<Option<String>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_str()
        .map(|value| Some(value.to_string()))
        .ok_or_else(|| format!("ai_semantic_cache: '{field}' must be a string"))
}

fn optional_non_empty_string(
    config: &Value,
    field: &'static str,
) -> Result<Option<String>, String> {
    let Some(value) = optional_string(config, field)? else {
        return Ok(None);
    };
    if value.trim().is_empty() {
        return Err(format!("ai_semantic_cache: '{field}' must not be empty"));
    }
    Ok(Some(value))
}

fn optional_threshold(config: &Value, field: &'static str) -> Result<Option<f32>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(number) = value.as_f64() else {
        return Err(format!(
            "ai_semantic_cache: '{field}' must be a number greater than 0 and at most 1"
        ));
    };
    if !number.is_finite() || number <= 0.0 || number > 1.0 {
        return Err(format!(
            "ai_semantic_cache: '{field}' must be greater than 0 and at most 1"
        ));
    }
    Ok(Some(number as f32))
}

fn parse_semantic_config(config: &Value) -> Result<Option<SemanticConfig>, String> {
    let enabled = optional_bool(config, "semantic_similarity_enabled")?.unwrap_or(false);
    let provider = optional_non_empty_string(config, "semantic_embedding_provider")?
        .as_deref()
        .map(EmbeddingProvider::parse)
        .transpose()?
        .unwrap_or(EmbeddingProvider::OpenAi);
    let endpoint = optional_non_empty_string(config, "semantic_embedding_endpoint")?;
    let model = optional_non_empty_string(config, "semantic_embedding_model")?;
    let api_key = optional_non_empty_string(config, "semantic_embedding_api_key")?;
    let auth_header = optional_non_empty_string(config, "semantic_embedding_auth_header")?
        .unwrap_or_else(|| provider.default_auth_header().to_string());
    let auth_scheme = optional_string(config, "semantic_embedding_auth_scheme")?
        .unwrap_or_else(|| provider.default_auth_scheme().to_string());
    let input_type = optional_non_empty_string(config, "semantic_embedding_input_type")?;
    let output_dimension = optional_positive_usize(config, "semantic_embedding_output_dimension")?;
    let similarity_threshold =
        optional_threshold(config, "semantic_similarity_threshold")?.unwrap_or(0.95);
    let max_candidates =
        optional_positive_usize(config, "semantic_vector_max_candidates")?.unwrap_or(16);
    let timeout_ms =
        optional_positive_u64(config, "semantic_embedding_timeout_ms")?.unwrap_or(5_000);

    reqwest::header::HeaderName::from_bytes(auth_header.as_bytes()).map_err(|_| {
        "ai_semantic_cache: 'semantic_embedding_auth_header' must be a valid HTTP header name"
            .to_string()
    })?;

    if !enabled {
        return Ok(None);
    }

    let endpoint = endpoint.ok_or_else(|| {
        "ai_semantic_cache: 'semantic_embedding_endpoint' is required when semantic_similarity_enabled=true"
            .to_string()
    })?;
    let parsed_endpoint = url::Url::parse(&endpoint)
        .map_err(|_| "ai_semantic_cache: 'semantic_embedding_endpoint' must be a valid URL")?;
    if !matches!(parsed_endpoint.scheme(), "http" | "https") {
        return Err(
            "ai_semantic_cache: 'semantic_embedding_endpoint' must use http or https".to_string(),
        );
    }

    Ok(Some(SemanticConfig {
        provider,
        endpoint,
        model,
        api_key,
        auth_header,
        auth_scheme,
        input_type,
        output_dimension,
        similarity_threshold,
        max_candidates,
        request_timeout: Duration::from_millis(timeout_ms),
    }))
}

fn default_redis_key_prefix(namespace: &str) -> String {
    let mut prefix = String::with_capacity(namespace.len() + 9);
    prefix.push_str(namespace);
    prefix.push_str(":ai_cache");
    prefix
}

#[cfg(test)]
mod tests {
    //! Inline tests that need access to private fields (the cache map and
    //! the gated `cleanup_expired` helper).
    use super::*;
    use crate::plugins::PluginHttpClient;
    use serde_json::json;

    /// Insert a synthetic cache entry directly so tests can populate the
    /// cache without driving the full request/response lifecycle.
    fn insert_synthetic(plugin: &AiSemanticCache, key: &str, inserted_at: Instant) {
        let entry = CacheEntry {
            status_code: 200,
            body: Bytes::from_static(b"\x00\x00\x00\x00\x00\x00\x00\x00"),
            headers: HashMap::new(),
            inserted_at,
            approx_size: 8,
            semantic_scope_key: None,
            embedding: None,
        };
        plugin
            .total_size
            .fetch_add(entry.approx_size, Ordering::Relaxed);
        plugin.cache.insert(key.to_string(), entry);
    }

    /// Force cleanup to run regardless of the 30-second cooldown gate by
    /// resetting the gate before the call.
    fn force_cleanup(plugin: &AiSemanticCache) {
        plugin.last_cleanup.store(0, Ordering::Relaxed);
        plugin.cleanup_expired();
    }

    #[test]
    fn eviction_keeps_newest_when_max_entries_exceeded() {
        // Verifies the partial-select eviction (`select_nth_unstable_by_key`)
        // preserves oldest-first semantics: when the cache exceeds
        // `max_entries`, the oldest are evicted and the newest are kept.
        let plugin = AiSemanticCache::new(
            &json!({"ttl_seconds": 600, "max_entries": 3}),
            PluginHttpClient::default(),
        )
        .unwrap_or_else(|err| panic!("test config should be valid: {err}"));

        let now = Instant::now();
        // Insert oldest → newest. Use 100ms spacing so ordering is well-defined
        // without needing real wall-clock waits.
        for (i, name) in ["a", "b", "c", "d", "e"].iter().enumerate() {
            let ts = now - Duration::from_millis(500 - (i as u64) * 100);
            insert_synthetic(&plugin, name, ts);
        }
        assert_eq!(plugin.cache.len(), 5);

        force_cleanup(&plugin);

        assert!(
            plugin.cache.len() <= 3,
            "max_entries=3 must be honored after eviction (got {})",
            plugin.cache.len()
        );
        // The two oldest entries ('a' and 'b') must be evicted.
        assert!(
            !plugin.cache.contains_key("a"),
            "oldest 'a' must be evicted"
        );
        assert!(
            !plugin.cache.contains_key("b"),
            "second-oldest 'b' must be evicted"
        );
        // The newest entries must survive.
        assert!(
            plugin.cache.contains_key("e"),
            "newest 'e' must be retained"
        );
    }

    #[test]
    fn normalize_text_collapses_whitespace_and_lowercases() {
        // Sanity-check the optimized single-pass normalize_text.
        assert_eq!(normalize_text("  Hello   World  "), "hello world");
        assert_eq!(
            normalize_text("MULTIPLE\nLINES\tof\rtext"),
            "multiple lines of text"
        );
        assert_eq!(normalize_text(""), "");
        assert_eq!(normalize_text("   "), "");
    }

    #[test]
    fn embedding_provider_aliases_cover_major_plugin_families() {
        assert_eq!(
            EmbeddingProvider::parse("openai-compatible").unwrap(),
            EmbeddingProvider::OpenAi
        );
        assert_eq!(
            EmbeddingProvider::parse("azure_openai").unwrap(),
            EmbeddingProvider::AzureOpenAi
        );
        assert_eq!(
            EmbeddingProvider::parse("mistral").unwrap(),
            EmbeddingProvider::Mistral
        );
        assert_eq!(
            EmbeddingProvider::parse("claude").unwrap(),
            EmbeddingProvider::Voyage
        );
        assert_eq!(
            EmbeddingProvider::parse("anthropic").unwrap(),
            EmbeddingProvider::Voyage
        );
        assert_eq!(
            EmbeddingProvider::parse("google_vertex").unwrap(),
            EmbeddingProvider::GoogleVertex
        );
        assert_eq!(
            EmbeddingProvider::parse("bedrock_cohere").unwrap(),
            EmbeddingProvider::BedrockCohere
        );
        assert!(EmbeddingProvider::parse("unknown").is_err());
    }

    fn semantic_config_for(provider: EmbeddingProvider) -> SemanticConfig {
        SemanticConfig {
            provider,
            endpoint: "http://127.0.0.1:1/embeddings".to_string(),
            model: Some("test-embedding-model".to_string()),
            api_key: Some("test-key".to_string()),
            auth_header: provider.default_auth_header().to_string(),
            auth_scheme: provider.default_auth_scheme().to_string(),
            input_type: Some("SEMANTIC_SIMILARITY".to_string()),
            output_dimension: Some(256),
            similarity_threshold: 0.95,
            max_candidates: 16,
            request_timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn embedding_request_payloads_match_provider_shapes() {
        let input = "user: where is paris?";

        let openai =
            build_embedding_request_payload(&semantic_config_for(EmbeddingProvider::OpenAi), input);
        assert_eq!(openai["input"], input);
        assert_eq!(openai["model"], "test-embedding-model");
        assert_eq!(openai["dimensions"], 256);

        let cohere =
            build_embedding_request_payload(&semantic_config_for(EmbeddingProvider::Cohere), input);
        assert_eq!(cohere["texts"][0], input);
        assert_eq!(cohere["input_type"], "SEMANTIC_SIMILARITY");
        assert_eq!(cohere["embedding_types"][0], "float");
        assert_eq!(cohere["output_dimension"], 256);

        let gemini = build_embedding_request_payload(
            &semantic_config_for(EmbeddingProvider::GoogleGemini),
            input,
        );
        assert_eq!(gemini["content"]["parts"][0]["text"], input);
        assert_eq!(gemini["taskType"], "SEMANTIC_SIMILARITY");
        assert_eq!(gemini["outputDimensionality"], 256);

        let vertex = build_embedding_request_payload(
            &semantic_config_for(EmbeddingProvider::GoogleVertex),
            input,
        );
        assert_eq!(vertex["instances"][0]["content"], input);
        assert_eq!(vertex["instances"][0]["task_type"], "SEMANTIC_SIMILARITY");
        assert_eq!(vertex["parameters"]["outputDimensionality"], 256);

        let titan = build_embedding_request_payload(
            &semantic_config_for(EmbeddingProvider::BedrockTitan),
            input,
        );
        assert_eq!(titan["inputText"], input);
        assert_eq!(titan["dimensions"], 256);
    }

    #[test]
    fn embedding_response_parser_accepts_major_provider_shapes() {
        for body in [
            json!({"data": [{"embedding": [1.0, 2.0, 3.0]}]}),
            json!({"embedding": [1.0, 2.0, 3.0]}),
            json!({"embedding": {"values": [1.0, 2.0, 3.0]}}),
            json!({"embeddings": [[1.0, 2.0, 3.0]]}),
            json!({"embeddings": [{"values": [1.0, 2.0, 3.0]}]}),
            json!({"embeddings": {"float": [[1.0, 2.0, 3.0]]}}),
            json!({"predictions": [{"embeddings": {"values": [1.0, 2.0, 3.0]}}]}),
            json!({"embeddingsByType": {"float": [1.0, 2.0, 3.0]}}),
            json!({"results": [{"embedding": [1.0, 2.0, 3.0]}]}),
        ] {
            assert_eq!(
                parse_embedding_response(&body).unwrap(),
                vec![1.0, 2.0, 3.0]
            );
        }
    }

    #[test]
    fn redis_serialized_cache_entry_omits_semantic_vector_fields_when_empty() {
        let entry = SerializableCacheEntry {
            status_code: 200,
            headers: HashMap::new(),
            body: b"cached".to_vec(),
            semantic_scope_key: None,
            embedding: None,
        };

        let value = serde_json::to_value(&entry).unwrap();
        assert!(value.get("semantic_scope_key").is_none());
        assert!(value.get("embedding").is_none());
    }
}

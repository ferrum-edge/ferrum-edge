//! AI Semantic Cache Plugin
//!
//! Caches LLM responses keyed by normalized prompts to avoid redundant API calls.
//! When the same (or equivalently formatted) prompt arrives again within the TTL,
//! the cached response is returned immediately without contacting the backend.
//!
//! # Request families
//!
//! Exact and semantic paths classify each JSON body into one exclusive provider
//! family (OpenAI Chat / Anthropic Messages, OpenAI Responses, Gemini/Vertex,
//! Cohere v1, legacy completions, TGI, or Titan). Unknown or ambiguous shapes
//! bypass caching rather than guessing.
//!
//! # v1 — Normalized Exact Match
//!
//! Prompts are normalized before hashing:
//! - Message order is preserved while role/content text is normalized
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
use url::Host;

use super::utils::body_transform::{is_event_stream_content_type, is_json_content_type};
use super::utils::cache_headers::sanitize_cached_headers;
use super::utils::redis_rate_limiter::{
    REDIS_PLUGIN_CONFIG_KEYS, RedisConfig, RedisRateLimitClient,
};
use super::{Plugin, PluginHttpClient, PluginResult, RequestContext};
use crate::util::unknown_keys::reject_unknown_keys;

const AI_CACHE_KEY_METADATA: &str = "_ai_cache_key";

/// Fixed-shape retention, isolation, size, and keying fields at the plugin root.
pub const AI_SEMANTIC_CACHE_ROOT_POLICY_KEYS: &[&str] = &[
    "ttl_seconds",
    "max_entries",
    "max_entry_size_bytes",
    "max_total_size_bytes",
    "include_model_in_key",
    "include_params_in_key",
    "scope_by_consumer",
    "cache_multimodal",
];

/// Fixed-shape semantic similarity / embedding policy fields at the plugin root.
pub const AI_SEMANTIC_CACHE_SEMANTIC_POLICY_KEYS: &[&str] = &[
    "semantic_similarity_enabled",
    "semantic_embedding_provider",
    "semantic_embedding_endpoint",
    "semantic_embedding_model",
    "semantic_embedding_input_type",
    "semantic_embedding_output_dimension",
    "semantic_embedding_api_key",
    "semantic_embedding_auth_header",
    "semantic_embedding_auth_scheme",
    "semantic_similarity_threshold",
    "semantic_vector_max_candidates",
    "semantic_embedding_timeout_ms",
];

/// Suffix appended to `FERRUM_NAMESPACE` when `redis_key_prefix` is omitted.
///
/// The full runtime default is `{FERRUM_NAMESPACE}:ai_cache` (for example
/// `ferrum:ai_cache` when the namespace is `ferrum`).
pub const AI_SEMANTIC_CACHE_DEFAULT_REDIS_KEY_SUFFIX: &str = "ai_cache";

/// Every accepted top-level `ai_semantic_cache` configuration property.
///
/// Union of root retention/isolation/size keys, semantic-policy keys, and the
/// shared Redis sync keys. There are no intentionally open maps on this plugin.
pub const AI_SEMANTIC_CACHE_CONFIG_KEYS: &[&str] = &[
    // Root retention / isolation / size / keying
    "ttl_seconds",
    "max_entries",
    "max_entry_size_bytes",
    "max_total_size_bytes",
    "include_model_in_key",
    "include_params_in_key",
    "scope_by_consumer",
    "cache_multimodal",
    // Semantic policy
    "semantic_similarity_enabled",
    "semantic_embedding_provider",
    "semantic_embedding_endpoint",
    "semantic_embedding_model",
    "semantic_embedding_input_type",
    "semantic_embedding_output_dimension",
    "semantic_embedding_api_key",
    "semantic_embedding_auth_header",
    "semantic_embedding_auth_scheme",
    "semantic_similarity_threshold",
    "semantic_vector_max_candidates",
    "semantic_embedding_timeout_ms",
    // Shared Redis sync (see REDIS_PLUGIN_CONFIG_KEYS)
    "sync_mode",
    "redis_url",
    "redis_tls",
    "redis_key_prefix",
    "redis_pool_size",
    "redis_connect_timeout_seconds",
    "redis_health_check_interval_seconds",
    "redis_username",
    "redis_password",
];

const VECTOR_REBUILD_INTERVAL_SECONDS: u64 = 30;

/// Minimum interval between expired-entry cleanup passes, measured against a
/// monotonic clock so the throttle is immune to wall-clock jumps.
const CLEANUP_INTERVAL_SECONDS: u64 = 30;

const RESPONSE_SHAPE_FIELDS: &[&str] = &[
    "tools",
    "tool_choice",
    "toolConfig",
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
    "reasoning",
    "text",
    "max_tool_calls",
    "truncation",
    "verbosity",
    "audio",
    "web_search_options",
    "thinking",
    "stop_sequences",
    "additionalModelRequestFields",
];

/// Provider-native tool / response-shape fields for Gemini / Vertex requests.
const GEMINI_SHAPE_FIELDS: &[&str] = &[
    "tools",
    "toolConfig",
    "tool_config",
    "functionDeclarations",
    "safetySettings",
    "safety_settings",
];

/// Provider-native tool / response-shape fields for Cohere v1 chat requests.
const COHERE_SHAPE_FIELDS: &[&str] = &[
    "tools",
    "tool_choice",
    "tool_results",
    "documents",
    "response_format",
    "seed",
];

/// Schema family used for exact-key / semantic-scope / semantic-input extraction.
///
/// Classification is exclusive: competing prompt containers make the body
/// ambiguous and deliberately bypass caching rather than guessing a family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CacheRequestFamily {
    /// OpenAI Chat Completions and Anthropic Messages (`messages` + optional
    /// top-level `system` / `preamble`).
    Messages,
    /// OpenAI Responses API (`input` / `instructions` / `previous_response_id`).
    Responses,
    /// Google Gemini / Vertex (`contents` + optional `systemInstruction`).
    Gemini,
    /// Cohere v1 chat (`chat_history` / `message` + optional `preamble`).
    Cohere,
    /// Legacy text completions (`prompt`).
    LegacyPrompt,
    /// Hugging Face TGI / text-generation (`inputs`).
    Tgi,
    /// Amazon Titan text-generation (`inputText`).
    Titan,
}

impl CacheRequestFamily {
    fn as_str(self) -> &'static str {
        match self {
            Self::Messages => "messages",
            Self::Responses => "responses",
            Self::Gemini => "gemini",
            Self::Cohere => "cohere",
            Self::LegacyPrompt => "legacy_prompt",
            Self::Tgi => "tgi",
            Self::Titan => "titan",
        }
    }
}

/// A cached LLM response.
#[derive(Clone)]
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

#[derive(Clone)]
struct SemanticConfig {
    provider: EmbeddingProvider,
    endpoint: String,
    /// Lowercased domain hostname used for DNS pre-warming, or `None` when
    /// the endpoint uses a literal IP and requires no DNS lookup.
    warmup_hostname: Option<String>,
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
enum MultimodalCacheMode {
    /// Bypass caching for requests that include non-text content parts.
    Reject,
    /// Cache exact multimodal matches with fingerprints, but do not use
    /// text-only semantic embeddings for multimodal cache hits.
    ExactOnly,
    /// Include multimodal fingerprints in semantic scope keys so semantic hits
    /// can only reuse entries with the same non-text content.
    IncludeFingerprints,
}

impl MultimodalCacheMode {
    fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "reject" => Ok(Self::Reject),
            "exact_only" | "exact-only" => Ok(Self::ExactOnly),
            "include_fingerprints" | "include-fingerprints" => Ok(Self::IncludeFingerprints),
            other => Err(format!(
                "ai_semantic_cache: unknown 'cache_multimodal' value '{other}' \
                 (expected reject, exact_only, or include_fingerprints)"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::ExactOnly => "exact_only",
            Self::IncludeFingerprints => "include_fingerprints",
        }
    }
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
    /// Approximate (soft) ceiling on the total cache size in bytes for
    /// **different-key** concurrent admits. The total is checked without a
    /// lock before each insert, so concurrent stores of distinct keys may
    /// briefly exceed the cap by up to
    /// `(concurrent inserts) * max_entry_size_bytes` before periodic
    /// `cleanup_expired` reconciliation (TTL expiry / max-entries eviction)
    /// brings it back down. It is not a hard guarantee, but that overshoot is
    /// bounded and self-healing.
    ///
    /// Same-key replacement is different: size-delta accounting uses the value
    /// returned by the winning `DashMap::insert`, so `total_size` never retains
    /// phantom bytes for an overwritten entry.
    max_total_size_bytes: usize,
    /// Whether to include the model name in the cache key.
    include_model_in_key: bool,
    /// Whether to include sampling parameters (temperature, top_p) in the cache key.
    include_params_in_key: bool,
    /// Whether to scope cache entries by authenticated consumer.
    scope_by_consumer: bool,
    /// Multimodal cache behavior for requests with non-text content parts.
    cache_multimodal: MultimodalCacheMode,
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
    /// Monotonic reference instant captured at construction. Cleanup
    /// scheduling measures elapsed time against this rather than the wall
    /// clock so a backward/forward `SystemTime` jump cannot stall or
    /// spuriously trigger cleanup.
    created_at: Instant,
    /// Seconds elapsed (against `created_at`) at the last cleanup pass, used to
    /// throttle cleanup to once per `CLEANUP_INTERVAL_SECONDS`.
    last_cleanup: AtomicU64,
    /// Last time the semantic vector snapshot was rebuilt.
    last_vector_rebuild: Arc<AtomicU64>,
    /// Whether local semantic entries changed since the latest vector rebuild.
    vector_index_dirty: Arc<AtomicBool>,
    /// Guards detached HNSW rebuild scheduling.
    vector_index_rebuild_running: Arc<AtomicBool>,
    /// Optional test-only callback after soft-cap admission succeeds and before
    /// size credit / `DashMap` insert. Production keeps this empty; the
    /// `ArcSwap` load of `None` is lock-free on the store path.
    store_post_admit_hook: Arc<ArcSwapOption<StorePostAdmitHook>>,
}

/// Test-only rendezvous wrapper for deterministic concurrent store races.
struct StorePostAdmitHook {
    callback: Arc<dyn Fn() + Send + Sync + 'static>,
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
        let object = config
            .as_object()
            .ok_or_else(|| "ai_semantic_cache: config must be an object".to_string())?;
        // Debug assertion keeps the documented key groups aligned with the
        // closed root allowlist used for admission and OpenAPI parity.
        debug_assert!(
            AI_SEMANTIC_CACHE_ROOT_POLICY_KEYS
                .iter()
                .chain(AI_SEMANTIC_CACHE_SEMANTIC_POLICY_KEYS.iter())
                .chain(REDIS_PLUGIN_CONFIG_KEYS.iter())
                .all(|key| AI_SEMANTIC_CACHE_CONFIG_KEYS.contains(key))
                && AI_SEMANTIC_CACHE_CONFIG_KEYS.len()
                    == AI_SEMANTIC_CACHE_ROOT_POLICY_KEYS.len()
                        + AI_SEMANTIC_CACHE_SEMANTIC_POLICY_KEYS.len()
                        + REDIS_PLUGIN_CONFIG_KEYS.len()
        );
        reject_unknown_keys(
            object,
            "config",
            AI_SEMANTIC_CACHE_CONFIG_KEYS,
            "ai_semantic_cache: ",
        )?;

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
        let cache_multimodal = parse_multimodal_cache_mode(config)?;
        let semantic = parse_semantic_config(config, http_client.backend_allow_ips())?;

        // Build optional Redis client. Unknown Redis key typos are rejected by
        // the root allowlist above; the shared parser does not close the object
        // so other Redis-backed plugins keep their own root keys.
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

        let sync_mode = if redis_client.is_some() {
            "redis"
        } else {
            "local"
        };
        let semantic_similarity_enabled = semantic.is_some();
        debug!(
            ttl_seconds,
            max_entries,
            max_entry_size_bytes,
            max_total_size_bytes,
            include_model_in_key,
            include_params_in_key,
            scope_by_consumer,
            cache_multimodal = cache_multimodal.as_str(),
            semantic_similarity_enabled,
            sync_mode,
            "ai_semantic_cache: admitted with effective retention and storage posture"
        );

        Ok(Self {
            ttl,
            max_entries,
            max_entry_size_bytes,
            max_total_size_bytes,
            include_model_in_key,
            include_params_in_key,
            scope_by_consumer,
            cache_multimodal,
            semantic,
            http_client,
            cache: Arc::new(DashMap::new()),
            vector_index: Arc::new(ArcSwapOption::empty()),
            total_size: Arc::new(AtomicUsize::new(0)),
            redis_client,
            created_at: Instant::now(),
            // Sentinel: never cleaned, so the first cleanup pass always runs.
            last_cleanup: AtomicU64::new(u64::MAX),
            last_vector_rebuild: Arc::new(AtomicU64::new(0)),
            vector_index_dirty: Arc::new(AtomicBool::new(false)),
            vector_index_rebuild_running: Arc::new(AtomicBool::new(false)),
            store_post_admit_hook: Arc::new(ArcSwapOption::empty()),
        })
    }

    /// Build a normalized cache key from the request body.
    ///
    /// Normalization steps:
    /// 1. Classify the JSON body into an exclusive provider request family
    /// 2. Optionally scope by proxy and authenticated consumer
    /// 3. Optionally include model name and family-correct generation controls
    /// 4. Canonicalize family-correct prompt text (lowercase + collapse whitespace)
    /// 5. Include hashed fingerprints for non-text multimodal / native tool blocks
    /// 6. Include family instruction state (`system`, `instructions`,
    ///    `systemInstruction`, `preamble`, `previous_response_id`, ...)
    /// 7. Include family tool / response-shape fields and `stream` when present
    /// 8. SHA-256 hash the normalized representation
    ///
    /// Unknown or ambiguous shapes return `None` so the request bypasses caching.
    fn build_cache_key(
        &self,
        ctx: &RequestContext,
        body: &Value,
        multimodal_fingerprint: Option<&str>,
    ) -> Option<String> {
        let family = classify_cache_request_family(body)?;
        let mut key_input = String::with_capacity(512);
        let mut has_part = false;

        append_identity_key_parts(self, ctx, body, family, &mut key_input, &mut has_part);
        append_family_prompt_exact_key(family, body, &mut key_input, &mut has_part)?;
        append_family_conversation_state(family, body, &mut key_input, &mut has_part)?;
        append_family_instruction_exact_key(family, body, &mut key_input, &mut has_part);

        if let Some(fingerprint) = multimodal_fingerprint {
            start_key_part(&mut key_input, &mut has_part);
            key_input.push_str("mm:");
            key_input.push_str(fingerprint);
        }

        append_family_shape_fields(family, body, &mut key_input, &mut has_part);

        let hash = Sha256::digest(key_input.as_bytes());
        Some(hex::encode(hash))
    }

    fn build_semantic_scope_key(
        &self,
        ctx: &RequestContext,
        body: &Value,
        multimodal_fingerprint: Option<&str>,
    ) -> Option<String> {
        let family = classify_cache_request_family(body)?;
        let mut key_input = String::with_capacity(512);
        let mut has_part = false;

        append_identity_key_parts(self, ctx, body, family, &mut key_input, &mut has_part);
        append_family_semantic_role_scope(family, body, &mut key_input, &mut has_part)?;
        append_family_conversation_state(family, body, &mut key_input, &mut has_part)?;
        append_family_instruction_scope(family, body, &mut key_input, &mut has_part);

        if let Some(fingerprint) = multimodal_fingerprint {
            start_key_part(&mut key_input, &mut has_part);
            key_input.push_str("mm:");
            key_input.push_str(fingerprint);
        }

        append_family_shape_fields(family, body, &mut key_input, &mut has_part);

        let hash = Sha256::digest(key_input.as_bytes());
        Some(hex::encode(hash))
    }

    /// Build the embedding input from family-correct user/prompt text only.
    ///
    /// Instruction, tool, model, and generation-control state stay in the
    /// semantic scope key so similar prompts cannot cross incompatible
    /// policy/output contexts.
    fn build_semantic_input(&self, body: &Value) -> Option<String> {
        let family = classify_cache_request_family(body)?;
        let input = build_family_semantic_input(family, body)?;
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

    /// Synchronously rebuild the semantic vector snapshot. Used only by the
    /// external test crate via `_test_support::rebuild_ai_semantic_cache_vector_index`.
    /// The `--lib --tests` build cannot see that caller (it lives in a separate
    /// integration-test crate), so it would otherwise flag this as dead code
    /// and fail `clippy -D warnings`; `allow(dead_code)` documents the real
    /// (external) use site.
    #[allow(dead_code)]
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

    /// Tracked `total_size` and the sum of retained entry `approx_size` values.
    /// External tests assert these stay equal after concurrent same-key stores.
    #[allow(dead_code)]
    pub(crate) fn size_accounting_snapshot_for_tests(&self) -> (usize, usize) {
        let tracked = self.total_size.load(Ordering::Relaxed);
        let actual = self
            .cache
            .iter()
            .map(|entry| entry.approx_size)
            .fold(0usize, usize::saturating_add);
        (tracked, actual)
    }

    /// Whether the semantic vector snapshot is marked dirty. Used to prove
    /// same-key replacement still dirties when embeddings are gained or lost.
    #[allow(dead_code)]
    pub(crate) fn vector_index_dirty_for_tests(&self) -> bool {
        self.vector_index_dirty.load(Ordering::Relaxed)
    }

    /// Clear the dirty flag without rebuilding so tests can assert a subsequent
    /// store re-dirties the index.
    #[allow(dead_code)]
    pub(crate) fn clear_vector_index_dirty_for_tests(&self) {
        self.vector_index_dirty.store(false, Ordering::Release);
    }

    /// Hold or release the detached rebuild guard so tests can observe the
    /// dirtying side effect without racing the asynchronous rebuild that
    /// normally consumes the flag immediately.
    #[allow(dead_code)]
    pub(crate) fn set_vector_index_rebuild_blocked_for_tests(&self, blocked: bool) {
        self.vector_index_rebuild_running
            .store(blocked, Ordering::Release);
    }

    /// Backdate every retained entry past TTL so a forced cleanup pass expires
    /// them without sleeping on the wall clock.
    #[allow(dead_code)]
    pub(crate) fn expire_all_entries_for_tests(&self) {
        let age = self.ttl.saturating_add(Duration::from_secs(1));
        let past = Instant::now().checked_sub(age).unwrap_or_else(Instant::now);
        for mut entry in self.cache.iter_mut() {
            entry.inserted_at = past;
        }
    }

    /// Bypass the cleanup throttle and run `cleanup_expired` immediately.
    #[allow(dead_code)]
    pub(crate) fn force_cleanup_for_tests(&self) {
        self.last_cleanup.store(u64::MAX, Ordering::Relaxed);
        self.cleanup_expired();
    }

    /// Install (or clear) a callback that runs after soft-cap admission and
    /// before size credit / insert. Used by external tests to park concurrent
    /// stores so distinct-key soft-cap overshoot is deterministic.
    #[allow(dead_code)]
    pub(crate) fn set_store_post_admit_hook_for_tests(
        &self,
        hook: Option<Arc<dyn Fn() + Send + Sync + 'static>>,
    ) {
        self.store_post_admit_hook
            .store(hook.map(|callback| Arc::new(StorePostAdmitHook { callback })));
    }

    fn run_store_post_admit_hook(&self) {
        if let Some(hook) = self.store_post_admit_hook.load_full() {
            (hook.callback)();
        }
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
    ///
    /// Throttled to once per `CLEANUP_INTERVAL_SECONDS` using a monotonic
    /// elapsed-seconds clock (`created_at`) rather than the wall clock, so a
    /// `SystemTime` jump cannot stall or spuriously trigger cleanup. The CAS
    /// guarantees exactly one caller wins per interval; concurrent callers
    /// that lose the race return without scanning.
    fn cleanup_expired(&self) {
        let now = Instant::now();
        let now_secs = now.saturating_duration_since(self.created_at).as_secs();

        // `last_cleanup` starts at `u64::MAX` (never cleaned) so the first
        // call always runs; afterwards it holds the monotonic second at which
        // the most recent pass ran.
        let last = self.last_cleanup.load(Ordering::Relaxed);
        if last != u64::MAX && now_secs.saturating_sub(last) < CLEANUP_INTERVAL_SECONDS {
            return;
        }
        if self
            .last_cleanup
            .compare_exchange(last, now_secs, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            // Another caller already claimed this interval.
            return;
        }

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

/// Classify a request body into exactly one supported cache family.
///
/// Returns `None` for unknown shapes and for bodies that simultaneously claim
/// multiple exclusive prompt containers (for example both `messages` and
/// `contents`). Callers must bypass caching rather than guess.
fn classify_cache_request_family(body: &Value) -> Option<CacheRequestFamily> {
    let object = body.as_object()?;

    let has_messages = object.get("messages").is_some_and(|value| value.is_array());
    let has_gemini_markers = object.contains_key("contents")
        || object.contains_key("systemInstruction")
        || object.contains_key("system_instruction")
        || object.contains_key("generationConfig");
    let has_chat_history = object.get("chat_history").is_some_and(Value::is_array);
    // Cohere v1 current-turn field. Do not treat it as Cohere when a `messages`
    // array is present — that body belongs to the Messages family (OpenAI /
    // Anthropic / Cohere v2).
    let has_cohere_message = object.get("message").is_some_and(Value::is_string) && !has_messages;
    let has_prompt = object.contains_key("prompt");
    let has_inputs = object.contains_key("inputs");
    let has_titan_markers =
        object.contains_key("inputText") || object.contains_key("textGenerationConfig");
    let has_responses_markers = object.contains_key("input")
        || object.contains_key("instructions")
        || object.contains_key("previous_response_id");
    // Responses markers only claim the Responses family when no chat `messages`
    // array is present (mirroring `ai_request_guard::is_responses_shape`).
    // A body that mixes `messages` with Responses markers is ambiguous and
    // bypasses rather than guessing Chat vs Responses.
    if has_messages && has_responses_markers {
        return None;
    }
    let has_responses = !has_messages && has_responses_markers;

    let mut family = None;
    let mut set_family = |candidate: CacheRequestFamily| -> bool {
        if family.is_some_and(|existing| existing != candidate) {
            return false;
        }
        family = Some(candidate);
        true
    };

    if has_messages && !set_family(CacheRequestFamily::Messages) {
        return None;
    }
    if has_responses && !set_family(CacheRequestFamily::Responses) {
        return None;
    }
    if has_gemini_markers && !set_family(CacheRequestFamily::Gemini) {
        return None;
    }
    if (has_chat_history || has_cohere_message) && !set_family(CacheRequestFamily::Cohere) {
        return None;
    }
    if has_prompt && !set_family(CacheRequestFamily::LegacyPrompt) {
        return None;
    }
    if has_inputs && !set_family(CacheRequestFamily::Tgi) {
        return None;
    }
    if has_titan_markers && !set_family(CacheRequestFamily::Titan) {
        return None;
    }

    family
}

fn append_identity_key_parts(
    plugin: &AiSemanticCache,
    ctx: &RequestContext,
    body: &Value,
    family: CacheRequestFamily,
    key_input: &mut String,
    has_part: &mut bool,
) {
    start_key_part(key_input, has_part);
    key_input.push_str("fam:");
    key_input.push_str(family.as_str());

    if let Some(ref proxy) = ctx.matched_proxy {
        start_key_part(key_input, has_part);
        key_input.push_str(&proxy.id);
    }

    if plugin.scope_by_consumer
        && let Some(identity) = ctx.effective_identity()
    {
        start_key_part(key_input, has_part);
        let _ = write!(key_input, "{identity}");
    }

    if plugin.include_model_in_key
        && let Some(model) = body.get("model").and_then(|m| m.as_str())
    {
        start_key_part(key_input, has_part);
        key_input.push_str("m:");
        push_ascii_lowercase(key_input, model);
    }

    if plugin.include_params_in_key {
        append_family_generation_controls(family, body, key_input, has_part);
    }
}

fn append_json_field(body: &Value, field: &str, key_input: &mut String, has_part: &mut bool) {
    if let Some(value) = body.get(field) {
        start_key_part(key_input, has_part);
        key_input.push_str(field);
        key_input.push(':');
        let _ = write!(key_input, "{value}");
    }
}

fn append_family_generation_controls(
    family: CacheRequestFamily,
    body: &Value,
    key_input: &mut String,
    has_part: &mut bool,
) {
    match family {
        CacheRequestFamily::Messages
        | CacheRequestFamily::Responses
        | CacheRequestFamily::Cohere
        | CacheRequestFamily::LegacyPrompt => {
            if let Some(temp) = body.get("temperature") {
                start_key_part(key_input, has_part);
                key_input.push_str("t:");
                key_input.push_str(&canonical_param_value(temp));
            }
            let top_p = if matches!(family, CacheRequestFamily::Cohere) {
                body.get("top_p").or_else(|| body.get("p"))
            } else {
                body.get("top_p")
            };
            if let Some(top_p) = top_p {
                start_key_part(key_input, has_part);
                key_input.push_str("p:");
                key_input.push_str(&canonical_param_value(top_p));
            }
            for (field, prefix) in [
                ("max_tokens", "mt"),
                ("max_completion_tokens", "mct"),
                ("max_output_tokens", "mot"),
                ("max_new_tokens", "mnt"),
            ] {
                if let Some(max_tokens) = body.get(field).and_then(|t| t.as_u64()) {
                    start_key_part(key_input, has_part);
                    let _ = write!(key_input, "{prefix}:{max_tokens}");
                }
            }
            if matches!(family, CacheRequestFamily::Messages) {
                append_json_field(body, "top_k", key_input, has_part);
                append_json_field(body, "inferenceConfig", key_input, has_part);
            }
            if matches!(family, CacheRequestFamily::Cohere) {
                for field in [
                    "k",
                    "stop_sequences",
                    "frequency_penalty",
                    "presence_penalty",
                    "raw_prompting",
                    "return_likelihoods",
                    "safety_mode",
                    "prompt_truncation",
                    "max_input_tokens",
                ] {
                    append_json_field(body, field, key_input, has_part);
                }
            }
        }
        CacheRequestFamily::Gemini => {
            append_json_field(body, "generationConfig", key_input, has_part);
        }
        CacheRequestFamily::Tgi => {
            append_json_field(body, "parameters", key_input, has_part);
        }
        CacheRequestFamily::Titan => {
            append_json_field(body, "textGenerationConfig", key_input, has_part);
        }
    }
}

fn append_family_shape_fields(
    family: CacheRequestFamily,
    body: &Value,
    key_input: &mut String,
    has_part: &mut bool,
) {
    match family {
        CacheRequestFamily::Messages
        | CacheRequestFamily::Responses
        | CacheRequestFamily::LegacyPrompt => {
            for field in RESPONSE_SHAPE_FIELDS {
                append_json_field(body, field, key_input, has_part);
            }
        }
        CacheRequestFamily::Gemini => {
            for field in GEMINI_SHAPE_FIELDS {
                append_json_field(body, field, key_input, has_part);
            }
        }
        CacheRequestFamily::Cohere => {
            for field in COHERE_SHAPE_FIELDS {
                append_json_field(body, field, key_input, has_part);
            }
        }
        CacheRequestFamily::Tgi | CacheRequestFamily::Titan => {}
    }

    // `stream`: stream:true and stream:false produce different wire formats
    // (SSE vs single JSON), so cached non-stream responses must not be
    // replayed to a stream:true caller (or vice versa).
    if let Some(stream) = body.get("stream").and_then(|s| s.as_bool()) {
        start_key_part(key_input, has_part);
        let _ = write!(key_input, "stream:{stream}");
    }
}

/// Append provider-native conversation structure that is not prompt text.
///
/// This keeps assistant tool calls, tool-result identifiers, message names,
/// Responses item types/roles, and other sibling state in both the exact key
/// and semantic scope. Text-bearing fields stay out of this fragment because
/// exact prompt extraction and the embedding input own them; non-text content
/// parts are isolated by the multimodal fingerprint.
fn append_family_conversation_state(
    family: CacheRequestFamily,
    body: &Value,
    key_input: &mut String,
    has_part: &mut bool,
) -> Option<()> {
    start_key_part(key_input, has_part);
    key_input.push_str("state:");

    match family {
        CacheRequestFamily::Messages => {
            key_input.push_str("messages:");
            append_object_array_state(body.get("messages")?, &["content"], key_input)?;
        }
        CacheRequestFamily::Responses => {
            key_input.push_str("responses:");
            match body.get("input") {
                None => key_input.push_str("none"),
                Some(Value::String(_)) => key_input.push_str("string"),
                Some(Value::Object(object)) => {
                    key_input.push_str("object:");
                    append_object_state(object, &["content", "text"], key_input);
                }
                Some(Value::Array(items)) => {
                    key_input.push_str("array:");
                    for item in items {
                        match item {
                            Value::String(_) => key_input.push_str("string;"),
                            Value::Object(object) => {
                                key_input.push_str("object:");
                                append_object_state(object, &["content", "text"], key_input);
                            }
                            _ => return None,
                        }
                    }
                }
                Some(_) => return None,
            }
        }
        CacheRequestFamily::Gemini => {
            key_input.push_str("contents:");
            append_object_array_state(body.get("contents")?, &["parts"], key_input)?;
        }
        CacheRequestFamily::Cohere => {
            key_input.push_str("cohere:");
            if let Some(history) = body.get("chat_history") {
                append_object_array_state(history, &["message", "content"], key_input)?;
            } else {
                key_input.push_str("no_history;");
            }
            key_input.push_str(if body.get("message").is_some() {
                "current_message"
            } else {
                "no_current_message"
            });
        }
        CacheRequestFamily::LegacyPrompt => {
            append_value_shape(body.get("prompt")?, key_input);
        }
        CacheRequestFamily::Tgi => {
            append_value_shape(body.get("inputs")?, key_input);
        }
        CacheRequestFamily::Titan => key_input.push_str("string"),
    }
    Some(())
}

fn append_object_array_state(
    value: &Value,
    excluded_fields: &[&str],
    key_input: &mut String,
) -> Option<()> {
    let items = value.as_array()?;
    let _ = write!(key_input, "{}:", items.len());
    for item in items {
        let object = item.as_object()?;
        append_object_state(object, excluded_fields, key_input);
    }
    Some(())
}

fn append_object_state(
    object: &serde_json::Map<String, Value>,
    excluded_fields: &[&str],
    key_input: &mut String,
) {
    key_input.push('{');
    for (field, value) in object {
        if excluded_fields.contains(&field.as_str()) {
            continue;
        }
        append_len_prefixed(key_input, field);
        key_input.push('=');
        let _ = write!(key_input, "{value}");
        key_input.push(';');
    }
    key_input.push('}');
}

fn append_value_shape(value: &Value, key_input: &mut String) {
    match value {
        Value::String(_) => key_input.push_str("string"),
        Value::Array(items) => {
            let _ = write!(key_input, "array:{}:", items.len());
            for item in items {
                append_value_shape(item, key_input);
                key_input.push(';');
            }
        }
        Value::Object(_) => key_input.push_str("object"),
        Value::Number(_) => key_input.push_str("number"),
        Value::Bool(_) => key_input.push_str("bool"),
        Value::Null => key_input.push_str("null"),
    }
}

fn extract_message_content(msg: &Value) -> String {
    let raw = if let Some(content) = msg.get("content").and_then(|c| c.as_str()) {
        content.to_string()
    } else if let Some(parts) = msg.get("content").and_then(|c| c.as_array()) {
        let mut texts = Vec::new();
        for part in parts {
            if is_openai_text_content_part(part)
                && let Some(text) = part.get("text").and_then(|t| t.as_str())
            {
                texts.push(text);
            }
        }
        texts.join(" ")
    } else {
        String::new()
    };
    normalize_text(&raw)
}

fn extract_gemini_parts_text(parts: &[Value]) -> String {
    let mut texts = Vec::new();
    for part in parts {
        if is_gemini_text_part(part)
            && let Some(text) = part.get("text").and_then(|t| t.as_str())
        {
            texts.push(text);
        }
    }
    normalize_text(&texts.join(" "))
}

fn extract_responses_input_text(input: &Value) -> String {
    match input {
        Value::String(text) => normalize_text(text),
        Value::Array(items) => {
            let mut texts = Vec::new();
            for item in items {
                push_responses_item_text(item, &mut texts);
            }
            normalize_text(&texts.join(" "))
        }
        Value::Object(_) => {
            let mut texts = Vec::new();
            push_responses_item_text(input, &mut texts);
            normalize_text(&texts.join(" "))
        }
        _ => String::new(),
    }
}

fn append_responses_prompt_exact_key(input: &Value, key_input: &mut String) -> Option<()> {
    match input {
        Value::String(text) => {
            key_input.push_str("string:");
            append_len_prefixed(key_input, &normalize_text(text));
        }
        Value::Array(items) => {
            let _ = write!(key_input, "array:{}:", items.len());
            for item in items {
                append_responses_prompt_item(item, key_input)?;
            }
        }
        Value::Object(_) => {
            key_input.push_str("object:");
            append_responses_prompt_item(input, key_input)?;
        }
        _ => return None,
    }
    Some(())
}

fn append_responses_prompt_item(item: &Value, key_input: &mut String) -> Option<()> {
    if let Some(text) = item.as_str() {
        key_input.push_str("string:");
        append_len_prefixed(key_input, &normalize_text(text));
        return Some(());
    }
    let object = item.as_object()?;
    key_input.push_str("item:");
    append_len_prefixed(
        key_input,
        object
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("input"),
    );
    append_len_prefixed(key_input, &extract_responses_input_text(item));
    Some(())
}

fn push_responses_item_text<'a>(item: &'a Value, texts: &mut Vec<&'a str>) {
    if let Some(text) = item.as_str() {
        texts.push(text);
        return;
    }
    let Some(object) = item.as_object() else {
        return;
    };

    if let Some(text) = object.get("content").and_then(|c| c.as_str()) {
        texts.push(text);
    } else if let Some(parts) = object.get("content").and_then(|c| c.as_array()) {
        for part in parts {
            if is_openai_text_content_part(part)
                && let Some(text) = part.get("text").and_then(|t| t.as_str())
            {
                texts.push(text);
            }
        }
    }

    if let Some(text) = object.get("text").and_then(|t| t.as_str()) {
        let item_type = object.get("type").and_then(|t| t.as_str());
        if item_type.is_none() || matches!(item_type, Some("input_text" | "text" | "output_text")) {
            texts.push(text);
        }
    }
}

fn append_family_prompt_exact_key(
    family: CacheRequestFamily,
    body: &Value,
    key_input: &mut String,
    has_part: &mut bool,
) -> Option<()> {
    match family {
        CacheRequestFamily::Messages => {
            let messages = body.get("messages").and_then(|m| m.as_array())?;
            start_key_part(key_input, has_part);
            key_input.push_str("messages:");
            for msg in messages {
                msg.as_object()?;
                let role = msg
                    .get("role")
                    .and_then(|r| r.as_str())
                    .unwrap_or("unknown");
                let content = extract_message_content(msg);
                append_len_prefixed(key_input, role);
                append_len_prefixed(key_input, &content);
            }
            Some(())
        }
        CacheRequestFamily::Responses => {
            start_key_part(key_input, has_part);
            key_input.push_str("input:");
            if let Some(input) = body.get("input") {
                append_responses_prompt_exact_key(input, key_input)?;
            }
            Some(())
        }
        CacheRequestFamily::Gemini => {
            let contents = body.get("contents").and_then(|c| c.as_array())?;
            start_key_part(key_input, has_part);
            key_input.push_str("contents:");
            for content in contents {
                content.as_object()?;
                let role = content
                    .get("role")
                    .and_then(|r| r.as_str())
                    .unwrap_or("user");
                let text = content
                    .get("parts")
                    .and_then(|p| p.as_array())
                    .map(|parts| extract_gemini_parts_text(parts))
                    .unwrap_or_default();
                append_len_prefixed(key_input, role);
                append_len_prefixed(key_input, &text);
            }
            Some(())
        }
        CacheRequestFamily::Cohere => {
            start_key_part(key_input, has_part);
            if let Some(history) = body.get("chat_history").and_then(|h| h.as_array()) {
                for msg in history {
                    msg.as_object()?;
                    let role = msg
                        .get("role")
                        .and_then(|r| r.as_str())
                        .unwrap_or("unknown");
                    let content = msg
                        .get("message")
                        .or_else(|| msg.get("content"))
                        .and_then(|c| c.as_str())
                        .unwrap_or("");
                    append_len_prefixed(key_input, role);
                    append_len_prefixed(key_input, &normalize_text(content));
                }
            }
            if let Some(message) = body.get("message").and_then(|m| m.as_str()) {
                append_len_prefixed(key_input, "user");
                append_len_prefixed(key_input, &normalize_text(message));
            }
            Some(())
        }
        CacheRequestFamily::LegacyPrompt => {
            let prompt = body.get("prompt")?;
            start_key_part(key_input, has_part);
            key_input.push_str("prompt:");
            key_input.push_str(&normalize_prompt_value(prompt));
            Some(())
        }
        CacheRequestFamily::Tgi => {
            let inputs = body.get("inputs")?;
            start_key_part(key_input, has_part);
            key_input.push_str("inputs:");
            key_input.push_str(&normalize_prompt_value(inputs));
            Some(())
        }
        CacheRequestFamily::Titan => {
            let input_text = body.get("inputText").and_then(|v| v.as_str())?;
            start_key_part(key_input, has_part);
            key_input.push_str("inputText:");
            key_input.push_str(&normalize_text(input_text));
            Some(())
        }
    }
}

fn append_family_instruction_exact_key(
    family: CacheRequestFamily,
    body: &Value,
    key_input: &mut String,
    has_part: &mut bool,
) {
    match family {
        CacheRequestFamily::Messages => {
            if let Some(system) = body.get("system") {
                start_key_part(key_input, has_part);
                key_input.push_str("sys:");
                key_input.push_str(&normalize_system_value(system));
            }
            if let Some(preamble) = body.get("preamble").and_then(|v| v.as_str()) {
                start_key_part(key_input, has_part);
                key_input.push_str("preamble:");
                key_input.push_str(&normalize_text(preamble));
            }
        }
        CacheRequestFamily::Responses => {
            if let Some(instructions) = body.get("instructions") {
                start_key_part(key_input, has_part);
                key_input.push_str("instructions:");
                key_input.push_str(&normalize_prompt_value(instructions));
            }
            if let Some(previous) = body.get("previous_response_id").and_then(|v| v.as_str()) {
                start_key_part(key_input, has_part);
                key_input.push_str("previous_response_id:");
                key_input.push_str(previous);
            }
        }
        CacheRequestFamily::Gemini => {
            for field in ["systemInstruction", "system_instruction"] {
                if let Some(system) = body.get(field) {
                    start_key_part(key_input, has_part);
                    key_input.push_str(field);
                    key_input.push(':');
                    key_input.push_str(&normalize_gemini_instruction(system));
                }
            }
        }
        CacheRequestFamily::Cohere => {
            if let Some(preamble) = body.get("preamble").and_then(|v| v.as_str()) {
                start_key_part(key_input, has_part);
                key_input.push_str("preamble:");
                key_input.push_str(&normalize_text(preamble));
            }
        }
        CacheRequestFamily::LegacyPrompt | CacheRequestFamily::Tgi | CacheRequestFamily::Titan => {}
    }
}

fn append_family_semantic_role_scope(
    family: CacheRequestFamily,
    body: &Value,
    key_input: &mut String,
    has_part: &mut bool,
) -> Option<()> {
    match family {
        CacheRequestFamily::Messages => {
            let messages = body.get("messages").and_then(|m| m.as_array())?;
            start_key_part(key_input, has_part);
            key_input.push_str("roles:");
            for (index, msg) in messages.iter().enumerate() {
                if index > 0 {
                    key_input.push('|');
                }
                let role = msg
                    .get("role")
                    .and_then(|r| r.as_str())
                    .unwrap_or("unknown");
                push_ascii_lowercase(key_input, role);
            }
            Some(())
        }
        CacheRequestFamily::Gemini => {
            let contents = body.get("contents").and_then(|c| c.as_array())?;
            start_key_part(key_input, has_part);
            key_input.push_str("roles:");
            for (index, content) in contents.iter().enumerate() {
                if index > 0 {
                    key_input.push('|');
                }
                let role = content
                    .get("role")
                    .and_then(|r| r.as_str())
                    .unwrap_or("user");
                push_ascii_lowercase(key_input, role);
            }
            Some(())
        }
        CacheRequestFamily::Cohere => {
            start_key_part(key_input, has_part);
            key_input.push_str("roles:");
            let mut wrote = false;
            if let Some(history) = body.get("chat_history").and_then(|h| h.as_array()) {
                for msg in history {
                    if wrote {
                        key_input.push('|');
                    }
                    let role = msg
                        .get("role")
                        .and_then(|r| r.as_str())
                        .unwrap_or("unknown");
                    push_ascii_lowercase(key_input, role);
                    wrote = true;
                }
            }
            if body.get("message").and_then(|m| m.as_str()).is_some() {
                if wrote {
                    key_input.push('|');
                }
                key_input.push_str("user");
            }
            Some(())
        }
        CacheRequestFamily::Responses => {
            start_key_part(key_input, has_part);
            key_input.push_str("roles:input");
            Some(())
        }
        CacheRequestFamily::LegacyPrompt => {
            start_key_part(key_input, has_part);
            key_input.push_str("roles:prompt");
            Some(())
        }
        CacheRequestFamily::Tgi => {
            start_key_part(key_input, has_part);
            key_input.push_str("roles:inputs");
            Some(())
        }
        CacheRequestFamily::Titan => {
            start_key_part(key_input, has_part);
            key_input.push_str("roles:inputText");
            Some(())
        }
    }
}

fn append_family_instruction_scope(
    family: CacheRequestFamily,
    body: &Value,
    key_input: &mut String,
    has_part: &mut bool,
) {
    match family {
        CacheRequestFamily::Messages => {
            if let Some(messages) = body.get("messages").and_then(|m| m.as_array()) {
                let mut has_instruction_message = false;
                for msg in messages {
                    let role = msg
                        .get("role")
                        .and_then(|r| r.as_str())
                        .unwrap_or("unknown");
                    if !matches!(role.to_ascii_lowercase().as_str(), "system" | "developer") {
                        continue;
                    }
                    let content = extract_message_content(msg);
                    if content.is_empty() {
                        continue;
                    }
                    if !has_instruction_message {
                        start_key_part(key_input, has_part);
                        key_input.push_str("instructions:");
                        has_instruction_message = true;
                    } else {
                        key_input.push('|');
                    }
                    push_ascii_lowercase(key_input, role);
                    key_input.push(':');
                    let hash = Sha256::digest(content.as_bytes());
                    key_input.push_str(&hex::encode(hash));
                }
            }
            if let Some(system) = body.get("system") {
                start_key_part(key_input, has_part);
                key_input.push_str("sys:");
                key_input.push_str(&normalize_system_value(system));
            }
            if let Some(preamble) = body.get("preamble").and_then(|v| v.as_str()) {
                start_key_part(key_input, has_part);
                key_input.push_str("preamble:");
                key_input.push_str(&normalize_text(preamble));
            }
        }
        CacheRequestFamily::Responses => {
            if let Some(instructions) = body.get("instructions") {
                let normalized = normalize_prompt_value(instructions);
                if !normalized.is_empty() {
                    start_key_part(key_input, has_part);
                    key_input.push_str("instructions:");
                    let hash = Sha256::digest(normalized.as_bytes());
                    key_input.push_str(&hex::encode(hash));
                }
            }
            if let Some(previous) = body.get("previous_response_id").and_then(|v| v.as_str()) {
                start_key_part(key_input, has_part);
                key_input.push_str("previous_response_id:");
                key_input.push_str(previous);
            }
        }
        CacheRequestFamily::Gemini => {
            for field in ["systemInstruction", "system_instruction"] {
                if let Some(system) = body.get(field) {
                    let normalized = normalize_gemini_instruction(system);
                    if normalized.is_empty() {
                        continue;
                    }
                    start_key_part(key_input, has_part);
                    key_input.push_str(field);
                    key_input.push(':');
                    let hash = Sha256::digest(normalized.as_bytes());
                    key_input.push_str(&hex::encode(hash));
                }
            }
        }
        CacheRequestFamily::Cohere => {
            if let Some(preamble) = body.get("preamble").and_then(|v| v.as_str()) {
                let normalized = normalize_text(preamble);
                if !normalized.is_empty() {
                    start_key_part(key_input, has_part);
                    key_input.push_str("preamble:");
                    let hash = Sha256::digest(normalized.as_bytes());
                    key_input.push_str(&hex::encode(hash));
                }
            }
        }
        CacheRequestFamily::LegacyPrompt | CacheRequestFamily::Tgi | CacheRequestFamily::Titan => {}
    }
}

fn build_family_semantic_input(family: CacheRequestFamily, body: &Value) -> Option<String> {
    let mut input = String::with_capacity(512);
    match family {
        CacheRequestFamily::Messages => {
            let messages = body.get("messages").and_then(|m| m.as_array())?;
            for msg in messages {
                let role = msg
                    .get("role")
                    .and_then(|r| r.as_str())
                    .unwrap_or("unknown");
                if matches!(role.to_ascii_lowercase().as_str(), "system" | "developer") {
                    continue;
                }
                let content = extract_message_content(msg);
                if content.is_empty() {
                    continue;
                }
                push_ascii_lowercase(&mut input, role);
                input.push_str(": ");
                input.push_str(&content);
                input.push('\n');
            }
        }
        CacheRequestFamily::Responses => {
            if let Some(raw) = body.get("input") {
                let text = extract_responses_input_text(raw);
                if !text.is_empty() {
                    input.push_str("input: ");
                    input.push_str(&text);
                    input.push('\n');
                }
            }
        }
        CacheRequestFamily::Gemini => {
            let contents = body.get("contents").and_then(|c| c.as_array())?;
            for content in contents {
                let role = content
                    .get("role")
                    .and_then(|r| r.as_str())
                    .unwrap_or("user");
                let text = content
                    .get("parts")
                    .and_then(|p| p.as_array())
                    .map(|parts| extract_gemini_parts_text(parts))
                    .unwrap_or_default();
                if text.is_empty() {
                    continue;
                }
                push_ascii_lowercase(&mut input, role);
                input.push_str(": ");
                input.push_str(&text);
                input.push('\n');
            }
        }
        CacheRequestFamily::Cohere => {
            if let Some(history) = body.get("chat_history").and_then(|h| h.as_array()) {
                for msg in history {
                    let role = msg
                        .get("role")
                        .and_then(|r| r.as_str())
                        .unwrap_or("unknown");
                    if role.eq_ignore_ascii_case("system") {
                        continue;
                    }
                    let content = msg
                        .get("message")
                        .or_else(|| msg.get("content"))
                        .and_then(|c| c.as_str())
                        .unwrap_or("");
                    let normalized = normalize_text(content);
                    if normalized.is_empty() {
                        continue;
                    }
                    push_ascii_lowercase(&mut input, role);
                    input.push_str(": ");
                    input.push_str(&normalized);
                    input.push('\n');
                }
            }
            if let Some(message) = body.get("message").and_then(|m| m.as_str()) {
                let normalized = normalize_text(message);
                if !normalized.is_empty() {
                    input.push_str("user: ");
                    input.push_str(&normalized);
                    input.push('\n');
                }
            }
        }
        CacheRequestFamily::LegacyPrompt => {
            let prompt = normalize_prompt_value(body.get("prompt")?);
            if !prompt.is_empty() {
                input.push_str("prompt: ");
                input.push_str(&prompt);
                input.push('\n');
            }
        }
        CacheRequestFamily::Tgi => {
            let inputs = normalize_prompt_value(body.get("inputs")?);
            if !inputs.is_empty() {
                input.push_str("inputs: ");
                input.push_str(&inputs);
                input.push('\n');
            }
        }
        CacheRequestFamily::Titan => {
            let input_text = body.get("inputText").and_then(|v| v.as_str())?;
            let normalized = normalize_text(input_text);
            if !normalized.is_empty() {
                input.push_str("inputText: ");
                input.push_str(&normalized);
                input.push('\n');
            }
        }
    }

    if input.trim().is_empty() {
        None
    } else {
        Some(input)
    }
}

fn normalize_prompt_value(value: &Value) -> String {
    match value {
        Value::String(text) => normalize_text(text),
        Value::Array(items) => {
            let mut normalized = String::new();
            let _ = write!(normalized, "array:{}:", items.len());
            for item in items {
                let text = match item {
                    Value::String(text) => normalize_text(text),
                    other => normalize_text(&other.to_string()),
                };
                append_len_prefixed(&mut normalized, &text);
            }
            normalized
        }
        other => normalize_text(&other.to_string()),
    }
}

fn normalize_gemini_instruction(system: &Value) -> String {
    if let Some(text) = system.as_str() {
        return normalize_text(text);
    }
    if let Some(parts) = system.get("parts").and_then(|p| p.as_array()) {
        return extract_gemini_parts_text(parts);
    }
    if let Some(parts) = system.as_array() {
        return extract_gemini_parts_text(parts);
    }
    normalize_text(&system.to_string())
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

/// Produce a canonical key fragment for a sampling parameter value.
///
/// Numeric values are normalized through their `f64` form so that
/// semantically identical encodings collapse to a single representation:
/// `1`, `1.0`, and `1e0` all render to `"1"`, and `0.70`/`0.7` both render to
/// `"0.7"`. Without this, two requests with the same effective temperature or
/// top_p would produce different cache keys and miss each other.
///
/// `f64::to_string` emits the shortest round-trippable decimal, so distinct
/// values (e.g. `0.7` vs `0.71`) are preserved. Integers that cannot be
/// represented exactly as `f64` (magnitude beyond 2^53) fall back to the raw
/// `Value` serialization to avoid collapsing distinct large integers; sampling
/// parameters are always small floats, so this fallback is only a safety net.
fn canonical_param_value(value: &Value) -> String {
    if let Some(n) = value.as_f64()
        && n.is_finite()
    {
        // Only trust the f64 normalization when it round-trips the original
        // integer exactly; otherwise keep the raw representation.
        if let Some(i) = value.as_i64() {
            if i as f64 as i64 == i {
                return n.to_string();
            }
        } else if let Some(u) = value.as_u64() {
            if u as f64 as u64 == u {
                return n.to_string();
            }
        } else {
            // Floating-point input: f64 already captures it exactly.
            return n.to_string();
        }
    }
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

/// Cheap structural check for whether `body` contains any non-text content
/// part, mirroring the traversal in [`build_multimodal_fingerprint`] but
/// short-circuiting on the first match and performing no hashing or
/// canonicalization. Used by `cache_multimodal: reject` to bypass without
/// paying the fingerprinting cost for a body that will be discarded.
fn body_has_multimodal_parts(body: &Value) -> bool {
    match classify_cache_request_family(body) {
        Some(CacheRequestFamily::Messages) => {
            if let Some(messages) = body.get("messages").and_then(|m| m.as_array())
                && messages
                    .iter()
                    .filter_map(|message| message.get("content"))
                    .any(|content| content_has_multimodal_parts(content, PartDialect::OpenAi))
            {
                return true;
            }
            body.get("system")
                .is_some_and(|system| content_has_multimodal_parts(system, PartDialect::OpenAi))
        }
        Some(CacheRequestFamily::Responses) => body
            .get("input")
            .is_some_and(responses_input_has_multimodal_parts),
        Some(CacheRequestFamily::Gemini) => {
            if let Some(contents) = body.get("contents").and_then(|c| c.as_array()) {
                for content in contents {
                    if let Some(parts) = content.get("parts").and_then(|p| p.as_array())
                        && parts.iter().any(|part| !is_gemini_text_part(part))
                    {
                        return true;
                    }
                }
            }
            for field in ["systemInstruction", "system_instruction"] {
                if let Some(system) = body.get(field)
                    && gemini_instruction_has_multimodal_parts(system)
                {
                    return true;
                }
            }
            false
        }
        // Cohere / legacy / TGI / Titan prompt containers are scalar strings (or
        // string arrays for legacy/TGI) and have no typed multimodal parts in
        // the shapes Ferrum caches. Native tool blocks for Cohere are exact-keyed
        // via shape fields rather than multimodal fingerprints.
        Some(
            CacheRequestFamily::Cohere
            | CacheRequestFamily::LegacyPrompt
            | CacheRequestFamily::Tgi
            | CacheRequestFamily::Titan,
        )
        | None => false,
    }
}

#[derive(Clone, Copy)]
enum PartDialect {
    OpenAi,
    Gemini,
}

/// Returns `true` if a message/system `content` value carries at least one
/// non-text part. A plain string is always text-only; an array contains a
/// multimodal part when any element is not a text block for the dialect; any
/// other scalar/object form is multimodal unless it is itself a text part.
fn content_has_multimodal_parts(content: &Value, dialect: PartDialect) -> bool {
    match content {
        Value::String(_) => false,
        Value::Array(parts) => parts
            .iter()
            .any(|part| !is_text_part_for_dialect(part, dialect)),
        Value::Null => false,
        other => !is_text_part_for_dialect(other, dialect),
    }
}

fn gemini_instruction_has_multimodal_parts(system: &Value) -> bool {
    if system.as_str().is_some() {
        return false;
    }
    if let Some(parts) = system.get("parts").and_then(|p| p.as_array()) {
        return parts.iter().any(|part| !is_gemini_text_part(part));
    }
    if let Some(parts) = system.as_array() {
        return parts.iter().any(|part| !is_gemini_text_part(part));
    }
    !is_gemini_text_part(system)
}

fn responses_input_has_multimodal_parts(input: &Value) -> bool {
    match input {
        Value::String(_) => false,
        Value::Array(items) => items.iter().any(responses_item_has_multimodal_parts),
        other => responses_item_has_multimodal_parts(other),
    }
}

fn responses_item_has_multimodal_parts(item: &Value) -> bool {
    if item.as_str().is_some() {
        return false;
    }
    let Some(object) = item.as_object() else {
        return true;
    };
    if let Some(content) = object.get("content") {
        return content_has_multimodal_parts(content, PartDialect::OpenAi);
    }
    match object.get("type").and_then(|t| t.as_str()) {
        Some("input_text" | "text" | "output_text") => {
            object.get("text").and_then(|t| t.as_str()).is_none()
        }
        Some(_) => true,
        None => object.get("text").and_then(|t| t.as_str()).is_none(),
    }
}

fn build_multimodal_fingerprint(body: &Value) -> Option<String> {
    let mut descriptor = String::new();
    let mut has_part = false;

    match classify_cache_request_family(body) {
        Some(CacheRequestFamily::Messages) => {
            if let Some(messages) = body.get("messages").and_then(|m| m.as_array()) {
                for (message_index, message) in messages.iter().enumerate() {
                    let role = message
                        .get("role")
                        .and_then(|r| r.as_str())
                        .unwrap_or("unknown");
                    if let Some(content) = message.get("content") {
                        append_multimodal_content_fingerprint(
                            &mut descriptor,
                            &mut has_part,
                            "message",
                            Some(message_index),
                            Some(role),
                            content,
                            PartDialect::OpenAi,
                        );
                    }
                }
            }

            if let Some(system) = body.get("system") {
                append_multimodal_content_fingerprint(
                    &mut descriptor,
                    &mut has_part,
                    "system",
                    None,
                    None,
                    system,
                    PartDialect::OpenAi,
                );
            }
        }
        Some(CacheRequestFamily::Responses) => {
            if let Some(input) = body.get("input") {
                append_responses_multimodal_fingerprint(&mut descriptor, &mut has_part, input);
            }
        }
        Some(CacheRequestFamily::Gemini) => {
            if let Some(contents) = body.get("contents").and_then(|c| c.as_array()) {
                for (content_index, content) in contents.iter().enumerate() {
                    let role = content
                        .get("role")
                        .and_then(|r| r.as_str())
                        .unwrap_or("user");
                    if let Some(parts) = content.get("parts") {
                        append_multimodal_content_fingerprint(
                            &mut descriptor,
                            &mut has_part,
                            "contents",
                            Some(content_index),
                            Some(role),
                            parts,
                            PartDialect::Gemini,
                        );
                    }
                }
            }
            for field in ["systemInstruction", "system_instruction"] {
                if let Some(system) = body.get(field) {
                    if let Some(parts) = system.get("parts") {
                        append_multimodal_content_fingerprint(
                            &mut descriptor,
                            &mut has_part,
                            field,
                            None,
                            None,
                            parts,
                            PartDialect::Gemini,
                        );
                    } else if system.as_str().is_none() {
                        append_multimodal_content_fingerprint(
                            &mut descriptor,
                            &mut has_part,
                            field,
                            None,
                            None,
                            system,
                            PartDialect::Gemini,
                        );
                    }
                }
            }
        }
        Some(
            CacheRequestFamily::Cohere
            | CacheRequestFamily::LegacyPrompt
            | CacheRequestFamily::Tgi
            | CacheRequestFamily::Titan,
        )
        | None => {}
    }

    if has_part {
        let hash = Sha256::digest(descriptor.as_bytes());
        Some(hex::encode(hash))
    } else {
        None
    }
}

fn append_responses_multimodal_fingerprint(
    buffer: &mut String,
    has_part: &mut bool,
    input: &Value,
) {
    match input {
        Value::String(_) => {}
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                append_responses_item_multimodal_fingerprint(buffer, has_part, Some(index), item);
            }
        }
        other => {
            append_responses_item_multimodal_fingerprint(buffer, has_part, None, other);
        }
    }
}

fn append_responses_item_multimodal_fingerprint(
    buffer: &mut String,
    has_part: &mut bool,
    index: Option<usize>,
    item: &Value,
) {
    if item.as_str().is_some() {
        return;
    }
    if let Some(content) = item.get("content") {
        append_multimodal_content_fingerprint(
            buffer,
            has_part,
            "input",
            index,
            item.get("role").and_then(|r| r.as_str()),
            content,
            PartDialect::OpenAi,
        );
        return;
    }
    if responses_item_has_multimodal_parts(item) {
        append_multimodal_part_descriptor(
            buffer,
            has_part,
            "input",
            index,
            item.get("role").and_then(|r| r.as_str()),
            None,
            item,
        );
    }
}

fn append_multimodal_content_fingerprint(
    buffer: &mut String,
    has_part: &mut bool,
    owner: &str,
    owner_index: Option<usize>,
    role: Option<&str>,
    content: &Value,
    dialect: PartDialect,
) {
    match content {
        Value::String(_) => {}
        Value::Array(parts) => {
            for (part_index, part) in parts.iter().enumerate() {
                if is_text_part_for_dialect(part, dialect) {
                    continue;
                }
                append_multimodal_part_descriptor(
                    buffer,
                    has_part,
                    owner,
                    owner_index,
                    role,
                    Some(part_index),
                    part,
                );
            }
        }
        Value::Null => {}
        other => {
            if !is_text_part_for_dialect(other, dialect) {
                append_multimodal_part_descriptor(
                    buffer,
                    has_part,
                    owner,
                    owner_index,
                    role,
                    None,
                    other,
                );
            }
        }
    }
}

fn append_multimodal_part_descriptor(
    buffer: &mut String,
    has_part: &mut bool,
    owner: &str,
    owner_index: Option<usize>,
    role: Option<&str>,
    part_index: Option<usize>,
    part: &Value,
) {
    start_key_part(buffer, has_part);
    buffer.push_str(owner);
    if let Some(index) = owner_index {
        let _ = write!(buffer, "[{index}]");
    }
    if let Some(role) = role {
        buffer.push_str(":role:");
        append_ascii_lowercase_len_prefixed(buffer, role);
    }
    if let Some(index) = part_index {
        let _ = write!(buffer, ":part[{index}]");
    }
    buffer.push(':');
    append_canonical_multimodal_value(buffer, part);
}

fn is_text_part_for_dialect(part: &Value, dialect: PartDialect) -> bool {
    match dialect {
        PartDialect::OpenAi => is_openai_text_content_part(part),
        PartDialect::Gemini => is_gemini_text_part(part),
    }
}

fn is_openai_text_content_part(part: &Value) -> bool {
    // A part counts as "text" only when it has a text-bearing `type` AND a
    // string `text` field — exactly the shape prompt extraction folds into the
    // message/input text. OpenAI Chat uses `type: "text"`; Responses also uses
    // `input_text` / `output_text`. Without the string-`text` requirement a
    // malformed part like `{"type": "text"}` would be skipped by both the
    // fingerprint and text extractors, so two requests differing only in such a
    // part would collide. Requiring a string `text` makes the partition
    // exhaustive: malformed parts fall through to fingerprinting instead.
    matches!(
        part.get("type").and_then(|t| t.as_str()),
        Some("text" | "input_text" | "output_text")
    ) && part.get("text").and_then(|t| t.as_str()).is_some()
}

fn is_gemini_text_part(part: &Value) -> bool {
    // Gemini text parts are typically `{"text": "..."}` without an OpenAI-style
    // `type` field. Any media / function-call keys make the part non-text so it
    // is fingerprinted instead of folded into prompt text.
    part.get("text").and_then(|t| t.as_str()).is_some()
        && part.get("inlineData").is_none()
        && part.get("inline_data").is_none()
        && part.get("fileData").is_none()
        && part.get("file_data").is_none()
        && part.get("functionCall").is_none()
        && part.get("function_call").is_none()
        && part.get("functionResponse").is_none()
        && part.get("function_response").is_none()
}

fn append_canonical_multimodal_value(buffer: &mut String, value: &Value) {
    match value {
        Value::Null => buffer.push_str("null"),
        Value::Bool(value) => {
            let _ = write!(buffer, "bool:{value}");
        }
        Value::Number(value) => {
            buffer.push_str("number:");
            buffer.push_str(&value.to_string());
        }
        Value::String(value) => {
            buffer.push_str("string_sha256:");
            buffer.push_str(&hex::encode(Sha256::digest(value.as_bytes())));
        }
        Value::Array(values) => {
            buffer.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    buffer.push(',');
                }
                append_canonical_multimodal_value(buffer, value);
            }
            buffer.push(']');
        }
        Value::Object(map) => {
            buffer.push('{');
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    buffer.push(',');
                }
                buffer.push_str("key:");
                append_len_prefixed(buffer, key);
                buffer.push('=');
                if key == "type"
                    && let Some(part_type) = map.get(key).and_then(|value| value.as_str())
                {
                    // Preserve the original case of the content-part `type`.
                    // Non-text parts are folded into the exact cache key ONLY
                    // through this fingerprint, so lowercasing here would let a
                    // request with `"type": "Image"` collapse onto a cached
                    // response stored for `"type": "image"` (and vice versa).
                    // Upstream model APIs may treat differently-cased enum
                    // values as distinct (or reject one), so they must not share
                    // a cache entry. `is_openai_text_content_part` is likewise
                    // case-sensitive, keeping the two paths consistent.
                    buffer.push_str("type:");
                    append_len_prefixed(buffer, part_type);
                } else if let Some(value) = map.get(key) {
                    append_canonical_multimodal_value(buffer, value);
                }
            }
            buffer.push('}');
        }
    }
}

fn append_len_prefixed(buffer: &mut String, value: &str) {
    let _ = write!(buffer, "{}:", value.len());
    buffer.push_str(value);
}

fn append_ascii_lowercase_len_prefixed(buffer: &mut String, value: &str) {
    let _ = write!(buffer, "{}:", value.len());
    push_ascii_lowercase(buffer, value);
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

    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        ctx.metadata.contains_key(AI_CACHE_KEY_METADATA)
    }

    fn should_buffer_response_body_for_content_type(
        &self,
        ctx: &RequestContext,
        content_type: Option<&str>,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        self.should_buffer_response_body(ctx)
            && !content_type.is_some_and(is_event_stream_content_type)
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

        // Unknown or ambiguous provider shapes deliberately bypass caching
        // rather than guessing a family or mixing structural metadata into
        // prompt text. Clear any prior staged key so a later final-body store
        // cannot retain a body that this instance refused to key.
        if classify_cache_request_family(&json).is_none() {
            debug!("ai_semantic_cache: skipping unknown or ambiguous request shape");
            ctx.metadata.remove(AI_CACHE_KEY_METADATA);
            ctx.ai_semantic_cache_embedding = None;
            ctx.ai_semantic_cache_scope_key = None;
            ctx.metadata
                .insert("ai_cache_status".to_string(), "BYPASS".to_string());
            return PluginResult::Continue;
        }

        // In reject mode, detect multimodal content with a cheap structural
        // scan that short-circuits on the first non-text part. Computing the
        // full SHA-256 fingerprint here would canonicalize and hash every
        // inline base64 image/audio blob only to discard the result, so the
        // hashing work is reserved for modes that actually consume it below.
        if self.cache_multimodal == MultimodalCacheMode::Reject && body_has_multimodal_parts(&json)
        {
            debug!(
                "ai_semantic_cache: skipping multimodal request because cache_multimodal=reject"
            );
            // Clear any cache key/embedding/scope a prior `ai_semantic_cache`
            // instance staged earlier in this request's `before_proxy` chain.
            // Without this, our `on_final_response_body` would still observe a
            // staged key and store this multimodal response, violating
            // `cache_multimodal: reject` whenever another cache instance ran
            // first on the same request.
            ctx.metadata.remove(AI_CACHE_KEY_METADATA);
            ctx.ai_semantic_cache_embedding = None;
            ctx.ai_semantic_cache_scope_key = None;
            ctx.metadata
                .insert("ai_cache_status".to_string(), "BYPASS".to_string());
            return PluginResult::Continue;
        }

        let multimodal_fingerprint = build_multimodal_fingerprint(&json);

        // Build cache key
        let cache_key = match self.build_cache_key(ctx, &json, multimodal_fingerprint.as_deref()) {
            Some(k) => k,
            None => {
                ctx.metadata.remove(AI_CACHE_KEY_METADATA);
                ctx.ai_semantic_cache_embedding = None;
                ctx.ai_semantic_cache_scope_key = None;
                ctx.metadata
                    .insert("ai_cache_status".to_string(), "BYPASS".to_string());
                return PluginResult::Continue;
            }
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

        let semantic_allowed = multimodal_fingerprint.is_none()
            || self.cache_multimodal == MultimodalCacheMode::IncludeFingerprints;

        if self.semantic.is_some()
            && semantic_allowed
            && let (Some(scope_key), Some(input)) = (
                self.build_semantic_scope_key(ctx, &json, multimodal_fingerprint.as_deref()),
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
        ctx.metadata
            .insert(AI_CACHE_KEY_METADATA.to_string(), cache_key);
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

    /// `x-ai-cache-status` is an unconditional gateway `insert`, so a backend
    /// echoing the identical value hides the write from net-diff mutation
    /// tracking and a later gRPC-deadline rebuild would drop the gateway's cache
    /// telemetry. Declared owned only when this request actually produced a
    /// status to write.
    fn owns_deadline_response_header(&self, ctx: &RequestContext, name: &str) -> bool {
        name.eq_ignore_ascii_case("x-ai-cache-status")
            && ctx.metadata.contains_key("ai_cache_status")
    }

    async fn on_final_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Only cache successful JSON responses
        if !(200..300).contains(&response_status) || matches!(response_status, 204 | 205) {
            return PluginResult::Continue;
        }

        // Synthetic short-circuit guard. On a semantic-cache MISS this plugin's
        // `before_proxy` sets `AI_CACHE_KEY_METADATA` so this hook stores the
        // (real) backend response. But this plugin (priority 2980) runs BEFORE
        // the later synthetic-2xx producers — `mesh_route_dispatch` (2995),
        // `serverless_function` (3025), `ai_federation` (4060),
        // `response_mock` (3030), `request_termination`, and a
        // `request_deduplication` replay — so when ANY of those short-circuits
        // with a 2xx body, the generic synthetic body-hook path
        // (`apply_synthetic_response_body_hooks`) re-runs this
        // `on_final_response_body` with `AI_CACHE_KEY_METADATA` still set from
        // the earlier miss. Without this guard that locally-generated synthetic
        // body — which NEVER reached the upstream model — would be written to the
        // in-memory + Redis semantic cache under the miss key and replayed to
        // every future semantically-similar request (cache poisoning). The proxy
        // sets `ferrum:synthetic_short_circuit` only for the duration of the
        // synthetic body-hook phase, so its presence is a precise, unspoofable
        // signal; a genuine backend response (the only legitimate store path)
        // never carries it and falls through to store normally. Mirrors
        // `response_caching`'s and `request_deduplication`'s synthetic guards.
        if ctx
            .metadata
            .contains_key(crate::proxy::SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY)
        {
            debug!(
                "ai_semantic_cache: skipping store of synthetic short-circuit response (no model tokens / upstream body)"
            );
            return PluginResult::Continue;
        }

        let cache_key = match ctx.metadata.get(AI_CACHE_KEY_METADATA) {
            Some(k) => k.clone(),
            None => return PluginResult::Continue,
        };

        // Cache admission is shared by the local and Redis paths below. A
        // successful status alone is not proof of an LLM response: upstreams
        // sometimes return 200 maintenance pages or malformed provider bodies.
        // Those responses still pass through to the original client, but must
        // not be retained and amplified for the cache TTL.
        let content_type = response_headers
            .iter()
            .find_map(|(name, value)| {
                name.eq_ignore_ascii_case("content-type")
                    .then_some(value.as_str())
            })
            .unwrap_or("");
        if is_event_stream_content_type(content_type) {
            debug!("ai_semantic_cache: skipping SSE streaming response");
            return PluginResult::Continue;
        }
        if !is_json_content_type(content_type) {
            debug!("ai_semantic_cache: skipping response without a JSON-compatible content type");
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
        if serde_json::from_slice::<Value>(body).is_err() {
            debug!("ai_semantic_cache: skipping syntactically invalid JSON response");
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

        // Soft total-size enforcement for different-key admits: this load is
        // separate from the fetch_add/insert below, so concurrent inserts of
        // distinct keys can each observe an under-limit total and overshoot
        // the cap transiently. The overshoot is bounded (each entry is
        // <= max_entry_size_bytes, checked above) and reclaimed by
        // `cleanup_expired`, so `max_total_size_bytes` is an approximate
        // ceiling rather than a hard guarantee — see its field doc.
        //
        // Same-key races must not leave permanent phantom bytes: accounting
        // below credits the new size then subtracts whatever `DashMap::insert`
        // actually displaced (including an entry inserted by a racing store).
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

        // Optional test rendezvous: park here after admission so concurrent
        // stores can all observe the same under-limit total before any size
        // credit runs. Production keeps the hook empty (lock-free no-op).
        self.run_store_post_admit_hook();

        let entry = CacheEntry {
            status_code: response_status,
            headers: safe_headers.clone(),
            body: Bytes::from(body.to_vec()),
            inserted_at: Instant::now(),
            approx_size,
            semantic_scope_key: semantic_scope_key.clone(),
            embedding: embedding.clone(),
        };

        // Credit the new entry first, then insert. `DashMap::insert` is atomic
        // per key and returns any displaced value; subtracting that size keeps
        // `total_size` equal to the retained map even when two stores race on
        // an empty key (both would previously remove-miss, both add, and the
        // loser would be overwritten with its size left in the counter).
        self.total_size
            .fetch_add(entry.approx_size, Ordering::Relaxed);
        let mut replaced_semantic_entry = false;
        if let Some(old) = self.cache.insert(cache_key.clone(), entry) {
            replaced_semantic_entry = old.embedding.is_some();
            self.total_size
                .fetch_sub(old.approx_size, Ordering::Relaxed);
        }
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
        let mut hosts = Vec::new();
        if let Some(hostname) = self
            .semantic
            .as_ref()
            .and_then(|semantic| semantic.warmup_hostname.as_ref())
        {
            hosts.push(hostname.clone());
        }
        if let Some(ref redis) = self.redis_client
            && let Some(hostname) = redis
                .warmup_hostname()
                .map(|hostname| hostname.to_ascii_lowercase())
            && !hosts.contains(&hostname)
        {
            hosts.push(hostname);
        }
        hosts
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

fn parse_multimodal_cache_mode(config: &Value) -> Result<MultimodalCacheMode, String> {
    optional_non_empty_string(config, "cache_multimodal")?
        .as_deref()
        .map(MultimodalCacheMode::parse)
        .transpose()
        .map(|mode| mode.unwrap_or(MultimodalCacheMode::ExactOnly))
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

fn parse_semantic_config(
    config: &Value,
    backend_allow_ips: &crate::config::BackendEgressPolicy,
) -> Result<Option<SemanticConfig>, String> {
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
    let warmup_hostname = validate_semantic_embedding_endpoint(&endpoint, backend_allow_ips)?;

    Ok(Some(SemanticConfig {
        provider,
        endpoint,
        warmup_hostname,
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

fn validate_semantic_embedding_endpoint(
    endpoint: &str,
    backend_allow_ips: &crate::config::BackendEgressPolicy,
) -> Result<Option<String>, String> {
    let parsed_endpoint = url::Url::parse(endpoint)
        .map_err(|_| "ai_semantic_cache: 'semantic_embedding_endpoint' must be a valid URL")?;
    if !matches!(parsed_endpoint.scheme(), "http" | "https") {
        return Err(
            "ai_semantic_cache: 'semantic_embedding_endpoint' must use http or https".to_string(),
        );
    }

    let host = parsed_endpoint.host().ok_or_else(|| {
        "ai_semantic_cache: 'semantic_embedding_endpoint' must include a host".to_string()
    })?;

    let (literal_ip, warmup_hostname) = match host {
        Host::Ipv4(ip) => (Some(std::net::IpAddr::V4(ip)), None),
        Host::Ipv6(ip) => (Some(std::net::IpAddr::V6(ip)), None),
        Host::Domain(hostname) => (None, Some(hostname.to_ascii_lowercase())),
    };

    if let Some(ip) = literal_ip
        && !backend_allow_ips.is_allowed(&ip)
    {
        return Err(format!(
            "ai_semantic_cache: 'semantic_embedding_endpoint' IP {ip} denied by backend egress policy ({backend_allow_ips})"
        ));
    }

    Ok(warmup_hostname)
}

fn default_redis_key_prefix(namespace: &str) -> String {
    let mut prefix = String::with_capacity(
        namespace.len() + 1 + AI_SEMANTIC_CACHE_DEFAULT_REDIS_KEY_SUFFIX.len(),
    );
    prefix.push_str(namespace);
    prefix.push(':');
    prefix.push_str(AI_SEMANTIC_CACHE_DEFAULT_REDIS_KEY_SUFFIX);
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

    /// Force cleanup to run regardless of the cooldown gate by resetting the
    /// gate to the "never cleaned" sentinel before the call.
    fn force_cleanup(plugin: &AiSemanticCache) {
        plugin.last_cleanup.store(u64::MAX, Ordering::Relaxed);
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
    fn multimodal_fingerprint_is_unambiguous_for_delimiter_like_keys_and_type() {
        let body_a = json!({
            "messages": [{
                "role": "user:part[0]",
                "content": [
                    {"type": "text", "text": "What is in this image?"},
                    {
                        "type": "image:url",
                        "image_url": {"url": "https://example.com/a.png"},
                        "a,b": "c"
                    }
                ]
            }]
        });
        let body_b = json!({
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "What is in this image?"},
                    {
                        "type": "image",
                        "url": {"image_url": "https://example.com/a.png"},
                        "a": {"b": "c"}
                    }
                ]
            }]
        });

        assert_ne!(
            build_multimodal_fingerprint(&body_a),
            build_multimodal_fingerprint(&body_b),
            "delimiter-bearing roles, keys, and types must not collapse to one fingerprint"
        );
    }

    #[test]
    fn multimodal_fingerprint_preserves_content_part_type_case() {
        // Two requests identical except for the case of a non-text part's
        // `type` must NOT collapse to the same fingerprint. Non-text parts are
        // folded into the exact cache key only through this fingerprint, so a
        // shared fingerprint would let a cached response for `"image"` be
        // replayed for `"Image"` (which upstream APIs may treat differently).
        let lower = json!({
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "describe"},
                    {"type": "image", "image_url": {"url": "https://example.com/a.png"}}
                ]
            }]
        });
        let upper = json!({
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "describe"},
                    {"type": "Image", "image_url": {"url": "https://example.com/a.png"}}
                ]
            }]
        });
        let lower_again = lower.clone();

        assert_ne!(
            build_multimodal_fingerprint(&lower),
            build_multimodal_fingerprint(&upper),
            "differently-cased part types must produce different fingerprints"
        );
        assert_eq!(
            build_multimodal_fingerprint(&lower),
            build_multimodal_fingerprint(&lower_again),
            "identical bodies must produce identical fingerprints"
        );
    }

    #[test]
    fn multimodal_detector_agrees_with_fingerprint_presence() {
        // The cheap reject-mode detector must classify "is multimodal"
        // identically to the full fingerprint helper, otherwise reject mode
        // would diverge from the exact/include modes.
        let text_only = json!({
            "messages": [{"role": "user", "content": "just text"}]
        });
        let text_array = json!({
            "messages": [{
                "role": "user",
                "content": [{"type": "text", "text": "still text"}]
            }]
        });
        let multimodal = json!({
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "look"},
                    {"type": "image", "image_url": {"url": "https://example.com/a.png"}}
                ]
            }]
        });
        let multimodal_system = json!({
            "system": [{"type": "image", "image_url": {"url": "https://example.com/a.png"}}],
            "messages": [{"role": "user", "content": "hi"}]
        });

        for body in [&text_only, &text_array, &multimodal, &multimodal_system] {
            assert_eq!(
                body_has_multimodal_parts(body),
                build_multimodal_fingerprint(body).is_some(),
                "detector must agree with fingerprint presence for {body}"
            );
        }
        assert!(!body_has_multimodal_parts(&text_only));
        assert!(!body_has_multimodal_parts(&text_array));
        assert!(body_has_multimodal_parts(&multimodal));
        assert!(body_has_multimodal_parts(&multimodal_system));
    }

    #[tokio::test]
    async fn reject_mode_bypass_clears_staged_cache_keys() {
        // A prior `ai_semantic_cache` instance in the same `before_proxy` chain
        // may have staged a cache key/embedding/scope. When a later reject-mode
        // instance bypasses a multimodal request, it must clear that staged
        // state so its `on_final_response_body` does not store the multimodal
        // response under the stale key.
        let plugin = AiSemanticCache::new(
            &json!({"ttl_seconds": 600, "cache_multimodal": "reject"}),
            PluginHttpClient::default(),
        )
        .unwrap_or_else(|err| panic!("test config should be valid: {err}"));
        assert_eq!(plugin.cache_multimodal, MultimodalCacheMode::Reject);

        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/v1/chat/completions".to_string(),
        );
        let body = json!({
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "what is this?"},
                    {"type": "image", "image_url": {"url": "https://example.com/a.png"}}
                ]
            }]
        });
        ctx.metadata
            .insert("request_body".to_string(), body.to_string());
        // Simulate staging done by an earlier cache instance.
        ctx.metadata
            .insert(AI_CACHE_KEY_METADATA.to_string(), "stale-key".to_string());
        ctx.ai_semantic_cache_embedding = Some(vec![0.1, 0.2, 0.3]);
        ctx.ai_semantic_cache_scope_key = Some("stale-scope".to_string());

        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());

        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(matches!(result, PluginResult::Continue));

        // Staged state must be cleared so a stale entry cannot be stored.
        assert!(
            !ctx.metadata.contains_key(AI_CACHE_KEY_METADATA),
            "reject bypass must remove the staged cache key"
        );
        assert!(
            ctx.ai_semantic_cache_embedding.is_none(),
            "reject bypass must clear the staged embedding"
        );
        assert!(
            ctx.ai_semantic_cache_scope_key.is_none(),
            "reject bypass must clear the staged scope key"
        );
        assert_eq!(
            ctx.metadata.get("ai_cache_status").map(String::as_str),
            Some("BYPASS")
        );

        // And the consume path must therefore store nothing.
        let response_headers = HashMap::new();
        plugin
            .on_final_response_body(&mut ctx, 200, &response_headers, b"{\"ok\":true}")
            .await;
        assert!(
            plugin.cache.is_empty(),
            "no entry may be stored after a reject-mode bypass"
        );
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
            warmup_hostname: None,
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

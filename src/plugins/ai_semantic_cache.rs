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
//! # v1 — Exact Match
//!
//! Exact cache keys preserve LLM-significant prompt case and whitespace. Safe
//! structural canonicalization still applies before hashing:
//! - Message order is preserved; roles and content string bytes are kept as sent
//! - JSON object key order is deterministic; sampling params use canonical numeric forms
//! - Model name is included in the key (different models = different cache entries)
//! - Temperature, top_p, and other sampling parameters are optionally included
//!
//! Semantic embedding input (optional v2 path) still lowercases and collapses
//! whitespace so approximate matching is not unintentionally tightened.
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
use hmac::{Hmac, KeyInit, Mac};
use instant_distance::{Builder as HnswBuilder, HnswMap, Point as HnswPoint, Search as HnswSearch};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::mem;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, Semaphore, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::debug;
use url::Host;

use super::utils::auth_flow::constant_time_eq;
use super::utils::body_transform::{is_event_stream_content_type, is_json_content_type};
use super::utils::byte_budget::{ByteBudget, ByteLease};
use super::utils::cache_headers::sanitize_cached_headers;
use super::utils::redis_rate_limiter::{
    BoundedRedisValue, REDIS_PLUGIN_CONFIG_KEYS, RedisConfig, RedisRateLimitClient,
};
use super::utils::response_body::read_response_body_bounded;
use super::{Plugin, PluginHttpClient, PluginResult, RequestContext};
use crate::util::unknown_keys::reject_unknown_keys;

type HmacSha256 = Hmac<Sha256>;

/// Request-metadata namespace prefix. Each plugin instance appends its
/// process-unique [`AiSemanticCache::instance_id`] so multiple
/// `ai_semantic_cache` configs on one proxy cannot overwrite one another's
/// staged cache key, status, match, or similarity markers.
const METADATA_NAMESPACE_PREFIX: &str = "ai_semantic_cache.";
const CACHE_KEY_SUFFIX: &str = "cache_key";
const CACHE_STATUS_SUFFIX: &str = "cache_status";
const CACHE_MATCH_SUFFIX: &str = "cache_match";
const CACHE_SIMILARITY_SUFFIX: &str = "cache_similarity";

static NEXT_AI_SEMANTIC_CACHE_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

fn staging_metadata_key(instance_id: u64, suffix: &str) -> String {
    let mut key = String::with_capacity(METADATA_NAMESPACE_PREFIX.len() + 20 + 1 + suffix.len());
    key.push_str(METADATA_NAMESPACE_PREFIX);
    {
        let _ = write!(key, "{instance_id}");
    }
    key.push('.');
    key.push_str(suffix);
    key
}

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
    // Redis envelope authenticity (required in redis sync mode)
    "redis_integrity_key",
];

const VECTOR_REBUILD_INTERVAL_SECONDS: u64 = 30;

/// Embedding-provider responses are small JSON documents in normal operation.
/// Bound the wire body before generic JSON deserialization so a compromised or
/// faulty provider cannot force an unbounded allocation.
const MAX_EMBEDDING_RESPONSE_BYTES: usize = 1024 * 1024;
/// OpenAI-compatible and custom embedding models are normally at most a few
/// thousand dimensions. This deliberately generous ceiling bounds scalar
/// allocation and HNSW indexing work.
const MAX_EMBEDDING_DIMENSIONS: usize = 16_384;
/// Conservative per-point HNSW graph/metadata overhead charged against the
/// shared cache byte budget (ZeroNode neighbors, layer bookkeeping, ids).
const HNSW_GRAPH_OVERHEAD_PER_POINT: usize = 256;
/// Conservative peak-copy multiplier charged per point while `instant-distance`
/// builds an HNSW map. Embedding floats are `Arc<[f32]>`-shared, so the scan
/// clone and any `instant-distance` internal clones do not deep-copy the float
/// slice; this multiplier still reserves headroom for construction working
/// memory (reordered point/value vectors, layer scratch) so the whole live peak
/// stays inside the cap. `ByteLease::shrink_to` releases the surplus once the
/// published snapshot is the only retained copy.
const HNSW_BUILD_EMBEDDING_COPIES: usize = 2;

/// Minimum interval between expired-entry cleanup passes, measured against a
/// monotonic clock so the throttle is immune to wall-clock jumps.
const CLEANUP_INTERVAL_SECONDS: u64 = 30;

/// Deployment-safe hard maximum for a single cached response body. Configured
/// `max_entry_size_bytes` values above this are rejected at admission so Redis
/// byte caps and local retention cannot be configured into `usize::MAX`.
const MAX_ENTRY_SIZE_BYTES_HARD_CAP: usize = 16 * 1024 * 1024; // 16 MiB
/// Deployment-safe hard maximum for retained local cache memory (entries +
/// HNSW generations). Rejects configs that would make Redis/index accounting
/// saturate platform integers.
const MAX_TOTAL_SIZE_BYTES_HARD_CAP: usize = 1024 * 1024 * 1024; // 1 GiB
/// Hard ceiling on a Redis envelope transfer. JSON expansion of the body plus
/// headers/MAC framing stays under this regardless of saturating arithmetic on
/// the configured entry size.
const MAX_REDIS_VALUE_BYTES_HARD_CAP: usize = 96 * 1024 * 1024; // 96 MiB
/// Deployment-safe hard maximum for `semantic_vector_max_candidates`. The value
/// flows into HNSW `ef_search` / `ef_construction`; unbounded configs can turn
/// semantic lookup/rebuild into unbounded graph walks. Rejected at admission.
const MAX_SEMANTIC_VECTOR_CANDIDATES_HARD_CAP: usize = 1_024;
/// Minimum length for `redis_integrity_key` (UTF-8 bytes). Shorter secrets are
/// rejected so Redis envelopes cannot be authenticated with a trivial key.
const MIN_REDIS_INTEGRITY_KEY_BYTES: usize = 32;

/// Schema version stamped into every Redis-stored [`SerializableCacheEntry`].
/// Redis is untrusted storage shared across gateway versions and other writers;
/// a hit whose envelope version does not match is treated as invalid (a
/// cross-version or foreign write) and quarantined rather than replayed. Bump
/// this whenever the stored envelope shape or authenticity contract changes.
/// v2 requires an HMAC authenticity tag; v3 length-frames every authenticated
/// header name/value so embedded NUL bytes cannot repartition header fields;
/// v4 authenticates the seal timestamp so Redis retention cannot extend replay
/// beyond the configured cache TTL. There is no legacy unauthenticated read
/// path during build-out.
const SEMANTIC_CACHE_ENTRY_VERSION: u8 = 4;

/// Deployment-safe ceiling on concurrent outbound embedding requests per plugin
/// instance. A burst of distinct concurrent misses (or an embedding outage that
/// stalls in-flight calls) cannot fan out more than this many simultaneous
/// outbound requests, bounding outbound sockets / provider quota / runtime
/// tasks. Identical concurrent misses additionally coalesce (see the embedding
/// singleflight in [`AiSemanticCache::compute_embedding`]) so they share one
/// outbound request rather than each consuming a permit.
const MAX_CONCURRENT_EMBEDDINGS: usize = 8;
/// Hard ceiling on how long one caller may wait for outbound-embedding
/// admission or for a singleflight leader before bypassing the semantic lookup.
///
/// The *effective* wait is derived from the operator-configured
/// `semantic_embedding_timeout_ms` (see
/// [`AiSemanticCache::embedding_singleflight_wait`]) and only clamped by this
/// ceiling, so a saturated or stalled embedding lane cannot hold a proxied
/// request far past the per-call embedding budget the operator opted into —
/// the documented failure mode is a plain cache miss, not a long stall.
/// A timeout must not evict a still-running leader and duplicate the same
/// outbound embedding call. Cancellation closes the channel and frees the slot
/// immediately, allowing one replacement leader to be elected.
const EMBEDDING_SINGLEFLIGHT_WAIT: Duration = Duration::from_secs(30);
/// Upper bound on singleflight re-election attempts for one caller so a
/// pathological leader-cancellation storm cannot loop forever on the request
/// task.
const EMBEDDING_SINGLEFLIGHT_MAX_RETRIES: usize = 16;
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

/// Provider-native state, tool, and response-shape fields for Cohere v1 chat requests.
const COHERE_SHAPE_FIELDS: &[&str] = &[
    // Cohere v1 can bind requests to backend-side conversation state. Include
    // the identifier in exact keys and semantic scopes so stateful responses
    // never cross persisted conversations with the same current message.
    "conversation_id",
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
    /// Retained-byte lease against [`AiSemanticCache::cache_budget`]. Cloning
    /// shares the `Arc`; the budget releases when the last handle drops
    /// (DashMap eviction, replacement, or plugin drop).
    _budget_lease: Arc<ByteLease>,
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
    /// Normalized embedding values behind an `Arc<[f32]>` so that cloning a
    /// point (rebuild scan clone + `instant-distance` internal construction
    /// clones) shares one float allocation instead of deep-copying every
    /// dimension. A cache entry and every HNSW point derived from it reference
    /// the same underlying slice.
    values: Arc<[f32]>,
}

impl EmbeddingPoint {
    fn from_raw(values: Vec<f32>) -> Result<Self, String> {
        if values.is_empty() {
            return Err("embedding vector must not be empty".to_string());
        }
        if values.len() > MAX_EMBEDDING_DIMENSIONS {
            return Err(format!(
                "embedding vector exceeds the maximum dimension {MAX_EMBEDDING_DIMENSIONS}"
            ));
        }

        // f32::MAX is finite but squaring it in f32 overflows to infinity, which
        // then normalizes every component to zero and admits an invalid vector.
        // Accumulate in f64 and fail closed for any non-finite / zero-length /
        // non-unit normalized result.
        let mut norm_squared = 0.0_f64;
        for value in &values {
            if !value.is_finite() {
                return Err("embedding vector contains a non-finite value".to_string());
            }
            let value = f64::from(*value);
            norm_squared += value * value;
            if !norm_squared.is_finite() {
                return Err("embedding vector norm is non-finite".to_string());
            }
        }
        if norm_squared == 0.0 {
            return Err("embedding vector must not have zero length".to_string());
        }

        let norm = norm_squared.sqrt();
        if !norm.is_finite() || norm == 0.0 {
            return Err("embedding vector norm is invalid".to_string());
        }

        let mut normalized = Vec::with_capacity(values.len());
        for value in values {
            let component = f64::from(value) / norm;
            if !component.is_finite() {
                return Err("normalized embedding contains a non-finite value".to_string());
            }
            let component = component as f32;
            if !component.is_finite() {
                return Err("normalized embedding is outside f32 range".to_string());
            }
            normalized.push(component);
        }

        let unit_norm_squared = normalized.iter().fold(0.0_f64, |acc, value| {
            let value = f64::from(*value);
            acc + value * value
        });
        if !unit_norm_squared.is_finite() || (unit_norm_squared.sqrt() - 1.0).abs() > 1.0e-4 {
            return Err("normalized embedding does not have unit length".to_string());
        }

        Ok(Self {
            values: normalized.into(),
        })
    }

    fn to_vec(&self) -> Vec<f32> {
        self.values.to_vec()
    }

    /// Bytes uniquely retained by this point's own struct plus its float slice.
    /// The float slice is `Arc`-shared, so charging it for both the owning cache
    /// entry and a derived HNSW generation conservatively over-counts shared
    /// memory rather than under-counting — the safe direction for a hard cap.
    fn approx_size(&self) -> usize {
        mem::size_of::<Self>() + self.values.len() * mem::size_of::<f32>()
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
            .zip(other.values.iter())
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
    /// Bytes reserved for this published generation (embeddings + values +
    /// graph overhead). Dropping the snapshot releases the lease promptly.
    accounted_bytes: usize,
    _budget_lease: Arc<ByteLease>,
}

enum VectorRebuildOutcome {
    Empty,
    BudgetExhausted,
    Built {
        index: HnswMap<EmbeddingPoint, VectorEntry>,
        lease: Arc<ByteLease>,
        accounted_bytes: usize,
    },
}

/// Cancellation-safe reset for the in-flight rebuild flags. Clears the
/// running guard and the reserved-bytes mirror on drop, so a rebuild task that
/// is dropped mid-flight (runtime shutdown, aborted join) cannot leave the
/// index permanently marked "rebuild running" or over-report reserved bytes.
/// The candidate `ByteLease` itself releases independently when its owning
/// `VectorRebuildOutcome` drops; this only resets the observable mirrors.
struct RebuildStateGuard {
    running: Arc<AtomicBool>,
    reserved: Arc<AtomicUsize>,
}

impl Drop for RebuildStateGuard {
    fn drop(&mut self) {
        self.reserved.store(0, Ordering::Release);
        self.running.store(false, Ordering::Release);
    }
}

/// Result of one embedding computation, shared across coalesced waiters.
type EmbeddingResult = Result<EmbeddingPoint, String>;

/// One in-flight embedding computation. Followers clone `rx` to await the
/// leader's published result without holding a `DashMap` shard lock across an
/// `.await`.
struct EmbeddingFlightSlot {
    rx: watch::Receiver<Option<Arc<EmbeddingResult>>>,
}

/// Leader/follower role for the embedding singleflight.
enum EmbeddingFlightRole {
    /// First caller for this input hash: owns the sender and the slot identity.
    Leader {
        tx: watch::Sender<Option<Arc<EmbeddingResult>>>,
        slot: Arc<EmbeddingFlightSlot>,
    },
    /// A later caller for the same in-flight input hash: awaits the leader.
    Follower(watch::Receiver<Option<Arc<EmbeddingResult>>>),
}

/// Cancellation-safe removal of a leader's in-flight slot. Drops when the leader
/// finishes OR is cancelled, freeing the map entry so followers re-enter leader
/// election for one replacement computation instead of each falling back to an
/// independent outbound call. `ptr_eq` ensures we only remove our own slot, not
/// a newer leader that replaced it after ours was gone.
struct EmbeddingFlightCleanup {
    map: Arc<DashMap<String, Arc<EmbeddingFlightSlot>>>,
    key: String,
    slot: Arc<EmbeddingFlightSlot>,
}

impl Drop for EmbeddingFlightCleanup {
    fn drop(&mut self) {
        self.map
            .remove_if(&self.key, |_, existing| Arc::ptr_eq(existing, &self.slot));
    }
}

pub struct AiSemanticCache {
    /// Process-unique ownership key for request-private staging. Fresh on every
    /// constructor call so reload generations and sibling instances never share
    /// `RequestContext` embedding/scope maps or namespaced metadata slots.
    instance_id: u64,
    /// Precomputed `ai_semantic_cache.<id>.cache_key` (hot-path insert/get).
    meta_cache_key: String,
    /// Precomputed `ai_semantic_cache.<id>.cache_status`.
    meta_status: String,
    /// Precomputed `ai_semantic_cache.<id>.cache_match`.
    meta_match: String,
    /// Precomputed `ai_semantic_cache.<id>.cache_similarity`.
    meta_similarity: String,
    /// Cache TTL.
    ttl: Duration,
    /// Maximum number of cached entries.
    max_entries: usize,
    /// Maximum size of a single cached response body in bytes.
    max_entry_size_bytes: usize,
    /// Hard ceiling on retained local cache memory: response entries (bodies,
    /// headers, scope keys, embeddings) plus published and in-flight HNSW
    /// generations. Admission uses lock-free `ByteBudget` leases so concurrent
    /// distinct-key stores cannot permanently overshoot; a store that cannot
    /// reserve is skipped. Same-key replacement drops the displaced entry's
    /// lease so overwritten bytes are released promptly.
    max_total_size_bytes: usize,
    /// Shared retained-byte budget backing `max_total_size_bytes`.
    cache_budget: Arc<ByteBudget>,
    /// Bytes currently reserved for an in-flight HNSW rebuild candidate.
    /// Published snapshot leases live on [`VectorSnapshot`]; this atomic makes
    /// peak (old + candidate) accounting observable to tests while the rebuild
    /// task still holds the candidate lease.
    rebuild_reserved_bytes: Arc<AtomicUsize>,
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
    /// Bounds concurrent outbound embedding requests for this instance so a
    /// burst of distinct misses cannot fan out unboundedly. See
    /// [`MAX_CONCURRENT_EMBEDDINGS`].
    embedding_semaphore: Arc<Semaphore>,
    /// Test-only per-instance follower/admission wait override in milliseconds.
    /// Zero uses [`EMBEDDING_SINGLEFLIGHT_WAIT`].
    embedding_singleflight_wait_override_ms: AtomicU64,
    /// Singleflight map keyed by embedding input hash. Identical concurrent
    /// misses coalesce onto one outbound computation; followers await the
    /// leader's shared result. Empty in normal operation (entries live only for
    /// the duration of an in-flight computation).
    embedding_flights: Arc<DashMap<String, Arc<EmbeddingFlightSlot>>>,
    /// Shared outbound HTTP client for embedding calls.
    http_client: PluginHttpClient,
    /// Local in-memory cache.
    cache: Arc<DashMap<String, CacheEntry>>,
    /// Immutable HNSW snapshot for semantic lookup.
    vector_index: Arc<ArcSwapOption<VectorSnapshot>>,
    /// First successfully admitted embedding dimension for this instance.
    /// Later vectors must match so HNSW distance stays well-defined.
    embedding_dimension: Arc<OnceLock<usize>>,
    /// Optional Redis client for centralized caching.
    redis_client: Option<Arc<RedisRateLimitClient>>,
    /// HMAC key authenticating Redis envelopes. Required whenever
    /// `redis_client` is `Some`; also accepted without Redis so hit-side
    /// authenticity helpers remain unit-testable. Never logged.
    redis_integrity_key: Option<Arc<[u8]>>,
    /// Monotonic reference instant captured at construction. Cleanup
    /// scheduling measures elapsed time against this rather than the wall
    /// clock so a backward/forward `SystemTime` jump cannot stall or
    /// spuriously trigger cleanup.
    created_at: Instant,
    /// Seconds elapsed (against `created_at`) at the last cleanup pass, used to
    /// throttle cleanup to once per `CLEANUP_INTERVAL_SECONDS`.
    last_cleanup: AtomicU64,
    /// Guards the lifecycle-owned cleanup worker so the full-map `retain` +
    /// oldest-entry eviction never overlaps itself.
    cleanup_running: Arc<AtomicBool>,
    /// Last time the semantic vector snapshot was rebuilt.
    last_vector_rebuild: Arc<AtomicU64>,
    /// Whether local semantic entries changed since the latest vector rebuild.
    vector_index_dirty: Arc<AtomicBool>,
    /// Guards lifecycle-owned HNSW rebuild work.
    vector_index_rebuild_running: Arc<AtomicBool>,
    /// Cheap hot-path signal that expired-entry cleanup is due. The request
    /// path only notifies; the lifecycle-owned worker performs the O(N) scan.
    cleanup_signal: Arc<Notify>,
    /// Cheap hot-path signal that the semantic vector index is dirty. The
    /// request path only notifies; the lifecycle-owned worker rebuilds.
    rebuild_signal: Arc<Notify>,
    /// Set by [`Plugin::commit_background_tasks`] after PluginCache
    /// publication. Workers staged in `start_background_tasks` stay dormant
    /// until this is true so a rolled-back generation has no maintenance side
    /// effects.
    maintenance_committed: Arc<AtomicBool>,
    /// Lifecycle-owned maintenance handles cancelled on drop/reload. Blocking
    /// work already scheduled may complete before releasing its bounded lease.
    maintenance: Mutex<Option<MaintenanceHandles>>,
    /// Optional test-only callback after byte-budget admission succeeds and
    /// before `DashMap` insert. Production keeps this empty; the
    /// `ArcSwap` load of `None` is lock-free on the store path.
    store_post_admit_hook: Arc<ArcSwapOption<StorePostAdmitHook>>,
}

/// JoinHandles + cancellation for lifecycle-owned cleanup/rebuild workers.
struct MaintenanceHandles {
    cancel: CancellationToken,
    handles: Vec<JoinHandle<()>>,
}

/// Test-only rendezvous wrapper for deterministic concurrent store races.
struct StorePostAdmitHook {
    callback: Arc<dyn Fn() + Send + Sync + 'static>,
}

/// Serializable form of CacheEntry for Redis storage.
///
/// `version` is always written and defaults to `0` on read, so an envelope from
/// a prior gateway version (which never wrote the field) fails the version check
/// on hit and is quarantined instead of replayed. `integrity` carries an
/// HMAC-SHA256 authenticity tag bound to the envelope bytes and the Redis
/// namespace/key context; missing or invalid tags fail closed.
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
struct SerializableCacheEntry {
    #[serde(default)]
    version: u8,
    /// Wall-clock seal time authenticated with the rest of the envelope.
    /// Missing timestamps deserialize as zero and fail the freshness check.
    #[serde(default)]
    sealed_at_epoch_seconds: u64,
    status_code: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    semantic_scope_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    embedding: Option<Vec<f32>>,
    /// Hex-encoded HMAC-SHA256 over the authenticated envelope fields and the
    /// Redis key context. Absent on foreign/legacy writes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    integrity: Option<String>,
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
                .chain(std::iter::once(&"redis_integrity_key"))
                .all(|key| AI_SEMANTIC_CACHE_CONFIG_KEYS.contains(key))
                && AI_SEMANTIC_CACHE_CONFIG_KEYS.len()
                    == AI_SEMANTIC_CACHE_ROOT_POLICY_KEYS.len()
                        + AI_SEMANTIC_CACHE_SEMANTIC_POLICY_KEYS.len()
                        + REDIS_PLUGIN_CONFIG_KEYS.len()
                        + 1 // redis_integrity_key
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
        if max_entry_size_bytes > MAX_ENTRY_SIZE_BYTES_HARD_CAP {
            return Err(format!(
                "ai_semantic_cache: 'max_entry_size_bytes' must be <= {MAX_ENTRY_SIZE_BYTES_HARD_CAP} (deployment hard cap)"
            ));
        }
        if max_total_size_bytes > MAX_TOTAL_SIZE_BYTES_HARD_CAP {
            return Err(format!(
                "ai_semantic_cache: 'max_total_size_bytes' must be <= {MAX_TOTAL_SIZE_BYTES_HARD_CAP} (deployment hard cap)"
            ));
        }
        if max_entry_size_bytes > max_total_size_bytes {
            return Err(
                "ai_semantic_cache: 'max_entry_size_bytes' must be <= 'max_total_size_bytes'"
                    .to_string(),
            );
        }

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

        // Redis envelopes must be authenticated. Fail closed when Redis mode is
        // enabled without a narrowly scoped integrity secret; there is no
        // unauthenticated legacy read path during build-out.
        let redis_integrity_key = match optional_string(config, "redis_integrity_key")? {
            Some(raw) => {
                let key = raw.into_bytes();
                if key.len() < MIN_REDIS_INTEGRITY_KEY_BYTES {
                    return Err(format!(
                        "ai_semantic_cache: 'redis_integrity_key' must be at least {MIN_REDIS_INTEGRITY_KEY_BYTES} bytes"
                    ));
                }
                Some(Arc::<[u8]>::from(key))
            }
            None => None,
        };
        if redis_client.is_some() && redis_integrity_key.is_none() {
            return Err(
                "ai_semantic_cache: 'redis_integrity_key' is required when sync_mode is redis"
                    .to_string(),
            );
        }

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

        let instance_id = NEXT_AI_SEMANTIC_CACHE_INSTANCE_ID.fetch_add(1, Ordering::Relaxed);
        let shard_amount = http_client.pool_shard_amount();
        Ok(Self {
            instance_id,
            meta_cache_key: staging_metadata_key(instance_id, CACHE_KEY_SUFFIX),
            meta_status: staging_metadata_key(instance_id, CACHE_STATUS_SUFFIX),
            meta_match: staging_metadata_key(instance_id, CACHE_MATCH_SUFFIX),
            meta_similarity: staging_metadata_key(instance_id, CACHE_SIMILARITY_SUFFIX),
            ttl,
            max_entries,
            max_entry_size_bytes,
            max_total_size_bytes,
            cache_budget: Arc::new(ByteBudget::new("ai_semantic_cache", max_total_size_bytes)),
            rebuild_reserved_bytes: Arc::new(AtomicUsize::new(0)),
            include_model_in_key,
            include_params_in_key,
            scope_by_consumer,
            cache_multimodal,
            semantic,
            embedding_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_EMBEDDINGS)),
            embedding_singleflight_wait_override_ms: AtomicU64::new(0),
            embedding_flights: Arc::new(DashMap::with_shard_amount(shard_amount)),
            http_client,
            cache: Arc::new(DashMap::with_shard_amount(shard_amount)),
            vector_index: Arc::new(ArcSwapOption::empty()),
            embedding_dimension: Arc::new(OnceLock::new()),
            redis_client,
            redis_integrity_key,
            created_at: Instant::now(),
            // Sentinel: never cleaned, so the first cleanup pass always runs.
            last_cleanup: AtomicU64::new(u64::MAX),
            cleanup_running: Arc::new(AtomicBool::new(false)),
            last_vector_rebuild: Arc::new(AtomicU64::new(0)),
            vector_index_dirty: Arc::new(AtomicBool::new(false)),
            vector_index_rebuild_running: Arc::new(AtomicBool::new(false)),
            cleanup_signal: Arc::new(Notify::new()),
            rebuild_signal: Arc::new(Notify::new()),
            maintenance_committed: Arc::new(AtomicBool::new(false)),
            maintenance: Mutex::new(None),
            store_post_admit_hook: Arc::new(ArcSwapOption::empty()),
        })
    }

    /// Process-local staging id for external multi-instance tests.
    #[allow(dead_code)]
    pub(crate) fn instance_id_for_tests(&self) -> u64 {
        self.instance_id
    }

    /// Precomputed namespaced metadata key for external tests.
    #[allow(dead_code)]
    pub(crate) fn staging_metadata_key_for_tests(&self, suffix: &str) -> String {
        staging_metadata_key(self.instance_id, suffix)
    }

    fn set_cache_status(&self, ctx: &mut RequestContext, status: &str) {
        ctx.metadata
            .insert(self.meta_status.clone(), status.to_string());
    }

    fn cache_status<'a>(&self, ctx: &'a RequestContext) -> Option<&'a str> {
        ctx.metadata.get(&self.meta_status).map(String::as_str)
    }

    /// Drop this instance's lookup/store staging without touching sibling
    /// instances' namespaced keys or embedding/scope map entries.
    fn clear_instance_staging(&self, ctx: &mut RequestContext) {
        ctx.metadata.remove(&self.meta_cache_key);
        ctx.metadata.remove(&self.meta_match);
        ctx.metadata.remove(&self.meta_similarity);
        ctx.ai_semantic_cache_embeddings.remove(&self.instance_id);
        ctx.ai_semantic_cache_scope_keys.remove(&self.instance_id);
    }

    fn stage_semantic_miss(
        &self,
        ctx: &mut RequestContext,
        scope_key: String,
        embedding: Vec<f32>,
    ) {
        ctx.ai_semantic_cache_embeddings
            .insert(self.instance_id, embedding);
        ctx.ai_semantic_cache_scope_keys
            .insert(self.instance_id, scope_key);
    }

    fn take_staged_semantic(
        &self,
        ctx: &mut RequestContext,
    ) -> (Option<String>, Option<EmbeddingPoint>) {
        let scope_key = ctx.ai_semantic_cache_scope_keys.remove(&self.instance_id);
        let embedding = ctx
            .ai_semantic_cache_embeddings
            .remove(&self.instance_id)
            .and_then(|values| EmbeddingPoint::from_raw(values).ok());
        (scope_key, embedding)
    }

    /// Build a normalized cache key from the request body.
    ///
    /// Normalization steps:
    /// 1. Classify the JSON body into an exclusive provider request family
    /// 2. Optionally scope by proxy and authenticated consumer
    /// 3. Optionally include model name and family-correct generation controls
    /// 4. Preserve family-correct prompt text and structural JSON bytes exactly
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

    /// Compute an embedding with bounded outbound concurrency and singleflight
    /// coalescing.
    ///
    /// Identical concurrent misses (same normalized input) share one outbound
    /// embedding request: the first caller is the leader, later callers are
    /// followers that await the leader's published result. Distinct concurrent
    /// inputs are additionally capped by [`Self::embedding_semaphore`] so a burst
    /// cannot fan out more than [`MAX_CONCURRENT_EMBEDDINGS`] simultaneous
    /// outbound requests. Cancellation is election-safe: a leader that is
    /// dropped before publishing frees its slot (via [`EmbeddingFlightCleanup`])
    /// and closes its channel, so waiters re-enter the map and elect exactly one
    /// replacement leader rather than each issuing a duplicate outbound call.
    /// Admission and follower waits share one bound derived from the configured
    /// embedding timeout ([`Self::embedding_singleflight_wait`], clamped by
    /// [`EMBEDDING_SINGLEFLIGHT_WAIT`]). A timeout bypasses
    /// semantic lookup for that follower without evicting the live leader, so it
    /// cannot create duplicate outbound work. One shared success or failure is
    /// published to all waiters on each completed leadership.
    async fn compute_embedding(&self, input: &str) -> Result<EmbeddingPoint, String> {
        if self.semantic.is_none() {
            return Err("semantic similarity is disabled".to_string());
        }

        // Coalesce by input hash: the embedding depends only on the input text,
        // so identical inputs (regardless of scope) share one computation.
        let flight_key = hex::encode(Sha256::digest(input.as_bytes()));

        for _attempt in 0..EMBEDDING_SINGLEFLIGHT_MAX_RETRIES {
            // Resolve leader/follower without holding the DashMap shard guard
            // across any `.await`.
            let role = match self.embedding_flights.entry(flight_key.clone()) {
                dashmap::mapref::entry::Entry::Occupied(occupied) => {
                    EmbeddingFlightRole::Follower(occupied.get().rx.clone())
                }
                dashmap::mapref::entry::Entry::Vacant(vacant) => {
                    let (tx, rx) = watch::channel::<Option<Arc<EmbeddingResult>>>(None);
                    let slot = Arc::new(EmbeddingFlightSlot { rx });
                    vacant.insert(Arc::clone(&slot));
                    EmbeddingFlightRole::Leader { tx, slot }
                }
            };

            match role {
                EmbeddingFlightRole::Leader { tx, slot } => {
                    // Free the slot on completion OR cancellation so waiters can
                    // elect a replacement rather than stampeding.
                    let _cleanup = EmbeddingFlightCleanup {
                        map: Arc::clone(&self.embedding_flights),
                        key: flight_key,
                        slot,
                    };
                    // Publish admission failures as well as provider outcomes so
                    // followers never wait on a leader stuck behind saturation.
                    let shared = match self.acquire_embedding_permit().await {
                        Ok(_permit) => Arc::new(self.compute_embedding_inner(input).await),
                        Err(error) => Arc::new(Err(error)),
                    };
                    // Publish one shared success/failure to every waiter.
                    let _ = tx.send(Some(Arc::clone(&shared)));
                    return (*shared).clone();
                }
                EmbeddingFlightRole::Follower(mut rx) => {
                    let wait_deadline = Instant::now() + self.embedding_singleflight_wait();
                    loop {
                        // Bind the cloned value so the borrow guard drops before
                        // the wait below re-borrows `rx`.
                        let latest = (*rx.borrow_and_update()).clone();
                        if let Some(shared) = latest {
                            return (*shared).clone();
                        }
                        let remaining = wait_deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            return Err(
                                "embedding singleflight leader exceeded follower wait bound"
                                    .to_string(),
                            );
                        }
                        match tokio::time::timeout(remaining, rx.changed()).await {
                            Ok(Ok(())) => continue,
                            Ok(Err(_)) => {
                                // Leader vanished before publishing; re-elect.
                                break;
                            }
                            Err(_) => {
                                // The leader still owns the slot. Bypass this
                                // follower rather than stealing a live flight
                                // and issuing a duplicate outbound request.
                                return Err(
                                    "embedding singleflight leader exceeded follower wait bound"
                                        .to_string(),
                                );
                            }
                        }
                    }
                }
            }
        }

        // Exhausted re-election budget under a leader-cancellation storm: still
        // honor the per-instance semaphore for one final bounded attempt.
        let _permit = self.acquire_embedding_permit().await?;
        self.compute_embedding_inner(input).await
    }

    /// Bound time spent waiting for embedding admission as well as provider I/O.
    async fn acquire_embedding_permit(&self) -> Result<tokio::sync::SemaphorePermit<'_>, String> {
        match tokio::time::timeout(
            self.embedding_singleflight_wait(),
            self.embedding_semaphore.acquire(),
        )
        .await
        {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) => Err("embedding concurrency admission is closed".to_string()),
            Err(_) => Err("embedding concurrency admission wait exceeded bound".to_string()),
        }
    }

    /// Effective bound for embedding admission and singleflight follower waits.
    ///
    /// Derived from the configured `semantic_embedding_timeout_ms` rather than
    /// the fixed [`EMBEDDING_SINGLEFLIGHT_WAIT`] ceiling: a leader's own worst
    /// case is one admission wait plus one provider call. A follower budget of
    /// twice the per-call timeout leaves one provider-timeout's admission
    /// cushion while still coalescing useful work. Using the bare ceiling would
    /// let a saturated embedding lane stall
    /// a proxied request for six times the timeout the operator configured
    /// (30s vs the 5s default) before the request falls through to its normal
    /// backend dispatch. The test override, when set, still wins.
    fn embedding_singleflight_wait(&self) -> Duration {
        let override_ms = self
            .embedding_singleflight_wait_override_ms
            .load(Ordering::Relaxed);
        if override_ms > 0 {
            return Duration::from_millis(override_ms);
        }
        let Some(semantic) = self.semantic.as_ref() else {
            return EMBEDDING_SINGLEFLIGHT_WAIT;
        };
        let leader_budget = semantic.request_timeout.saturating_mul(2);
        leader_budget.min(EMBEDDING_SINGLEFLIGHT_WAIT)
    }

    async fn compute_embedding_inner(&self, input: &str) -> Result<EmbeddingPoint, String> {
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

        if response
            .content_length()
            .is_some_and(|length| length > MAX_EMBEDDING_RESPONSE_BYTES as u64)
        {
            return Err(format!(
                "embedding response invalid: declared body exceeds {MAX_EMBEDDING_RESPONSE_BYTES} bytes"
            ));
        }
        let body = read_response_body_bounded(response, MAX_EMBEDDING_RESPONSE_BYTES)
            .await
            .map_err(|err| format!("embedding response invalid: bounded read failed: {err}"))?;
        let body: Value = serde_json::from_slice(&body)
            .map_err(|err| format!("embedding response parse failed: {err}"))?;
        let values = parse_embedding_response(&body, semantic.output_dimension)
            .map_err(|err| format!("embedding response invalid: {err}"))?;
        // Validate/normalize before learning the instance dimension so an
        // invalid first provider response cannot permanently pin a dimension
        // and reject later valid vectors.
        let point = EmbeddingPoint::from_raw(values)
            .map_err(|err| format!("embedding response invalid: {err}"))?;
        let dimension = point.values.len();
        let learned = self.embedding_dimension.get_or_init(|| dimension);
        if *learned != dimension {
            return Err(format!(
                "embedding response invalid: dimension changed from {} to {dimension}",
                *learned
            ));
        }
        Ok(point)
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
            // Cheap hot-path signal only; the lifecycle-owned worker rebuilds.
            self.rebuild_signal.notify_one();
        }
    }

    /// Byte cap for a Redis-stored envelope before allocation.
    ///
    /// The stored value is a `SerializableCacheEntry` JSON document whose
    /// response body is serialized as a JSON byte array (up to ~4x its raw
    /// length) plus sanitized headers, status, integrity tag, and version
    /// framing. Bound the transfer generously above that expansion, then clamp
    /// to [`MAX_REDIS_VALUE_BYTES_HARD_CAP`] so checked Redis index conversion
    /// never sees a saturating `usize::MAX` cap. The exact per-entry limit is
    /// re-checked against `max_entry_size_bytes` on the decoded body in
    /// [`Self::admit_redis_hit`].
    fn redis_value_byte_cap(&self) -> usize {
        let expanded = self
            .max_entry_size_bytes
            .checked_mul(6)
            .and_then(|v| v.checked_add(64 * 1024))
            .unwrap_or(MAX_REDIS_VALUE_BYTES_HARD_CAP);
        expanded.min(MAX_REDIS_VALUE_BYTES_HARD_CAP)
    }

    /// Re-apply the full store-side admission contract to a Redis hit before
    /// replaying it.
    ///
    /// Redis is untrusted storage shared across gateway versions and other
    /// writers. Successful deserialization is not proof of a value this gateway
    /// wrote: a tampered, stale, foreign, or cross-version entry must not let
    /// the gateway emit an oversized, non-JSON, wrong-status, or unsanitized
    /// (cookie/auth-bearing) response. Authenticity is verified with an HMAC
    /// bound to the full cached status/header/body envelope and the Redis
    /// namespace/key context before any other admission check. Returns the
    /// sanitized response to serve, or `None` when any invariant fails so the
    /// caller quarantines the entry.
    fn admit_redis_hit(
        &self,
        entry: SerializableCacheEntry,
        redis_key: &str,
    ) -> Option<CachedResponse> {
        // Fail closed when Redis mode cannot authenticate.
        let integrity_key = self.redis_integrity_key.as_ref()?;
        // Schema/version gate: reject envelopes not written by this version.
        if entry.version != SEMANTIC_CACHE_ENTRY_VERSION {
            return None;
        }
        let provided_mac_hex = entry.integrity.as_deref()?;
        let Ok(provided_mac) = hex::decode(provided_mac_hex) else {
            return None;
        };
        let expected_mac = compute_redis_envelope_mac(
            integrity_key,
            &RedisEnvelopeMacInput {
                redis_key,
                version: entry.version,
                sealed_at_epoch_seconds: entry.sealed_at_epoch_seconds,
                status_code: entry.status_code,
                headers: &entry.headers,
                body: &entry.body,
                semantic_scope_key: entry.semantic_scope_key.as_deref(),
                embedding: entry.embedding.as_deref(),
            },
        )?;
        if !constant_time_eq(&provided_mac, &expected_mac) {
            return None;
        }
        let age_seconds = current_epoch_seconds().checked_sub(entry.sealed_at_epoch_seconds)?;
        if age_seconds >= self.ttl.as_secs() {
            return None;
        }
        // Status: same 2xx contract as the store path (exclude 204/205, which
        // carry no body).
        if !(200..300).contains(&entry.status_code) || matches!(entry.status_code, 204 | 205) {
            return None;
        }
        // Hard per-entry body-size cap.
        if entry.body.len() > self.max_entry_size_bytes {
            return None;
        }
        // Content-type must be JSON-compatible and not an event stream, mirroring
        // the store path. An absent content-type is rejected: the store path only
        // admits JSON responses, so a hit lacking one is not a value we wrote.
        let content_type = entry.headers.iter().find_map(|(name, value)| {
            name.eq_ignore_ascii_case("content-type")
                .then_some(value.as_str())
        });
        match content_type {
            Some(ct) if is_json_content_type(ct) && !is_event_stream_content_type(ct) => {}
            _ => return None,
        }
        // Body must be syntactically valid JSON.
        if serde_json::from_slice::<Value>(&entry.body).is_err() {
            return None;
        }
        // Re-sanitize headers: a foreign writer could have injected Set-Cookie /
        // authorization headers even though this gateway's store path strips
        // them before writing.
        let headers = sanitize_cached_headers(&entry.headers);
        Some(CachedResponse {
            status_code: entry.status_code,
            headers,
            body: Bytes::from(entry.body),
        })
    }

    async fn build_vector_snapshot(
        cache: Arc<DashMap<String, CacheEntry>>,
        ttl: Duration,
        max_candidates: usize,
        cache_budget: Arc<ByteBudget>,
        rebuild_reserved_bytes: Arc<AtomicUsize>,
    ) -> Result<VectorRebuildOutcome, tokio::task::JoinError> {
        tokio::task::spawn_blocking(move || {
            // HnswMap is immutable, so local semantic inserts/removals are
            // made visible in batches. The dirty flag is cleared before this
            // snapshot; any concurrent insert that races this scan re-dirties
            // the index and schedules a later rebuild.
            //
            // First measure the current live semantic set without allocating
            // candidate vectors, then reserve its full estimated peak before
            // any rebuild-owned key/value clones are created. The map can
            // change between passes, so the collection pass independently
            // measures each current entry and admits it only when the running
            // peak remains within the amount already reserved. A concurrent
            // insert can therefore be skipped, but can never make the rebuild
            // allocate or index more points than were charged.
            let now = Instant::now();
            let mut peak_estimate = 0usize;
            for entry in cache.iter() {
                if now.duration_since(entry.inserted_at) >= ttl {
                    continue;
                }
                let (Some(scope_key), Some(embedding)) =
                    (entry.semantic_scope_key.as_ref(), entry.embedding.as_ref())
                else {
                    continue;
                };
                let cache_key = entry.key();
                peak_estimate = peak_estimate.saturating_add(estimate_hnsw_point_peak_bytes(
                    embedding, cache_key, scope_key,
                ));
            }

            if peak_estimate == 0 {
                return VectorRebuildOutcome::Empty;
            }

            // Reserve the measured live peak BEFORE allocating candidate
            // vectors. Because the old published generation still holds its
            // own lease against this same budget, `try_acquire` only succeeds
            // when entries + old snapshot + this candidate's peak all fit
            // under `max_total_size_bytes`.
            let Some(lease) = cache_budget.try_acquire(peak_estimate) else {
                return VectorRebuildOutcome::BudgetExhausted;
            };
            rebuild_reserved_bytes.store(peak_estimate, Ordering::Release);

            let mut points: Vec<EmbeddingPoint> = Vec::new();
            let mut values: Vec<VectorEntry> = Vec::new();
            let mut collected_peak = 0usize;
            let mut retained_estimate = 0usize;
            for entry in cache.iter() {
                if now.duration_since(entry.inserted_at) >= ttl {
                    continue;
                }
                let (Some(scope_key), Some(embedding)) =
                    (entry.semantic_scope_key.as_ref(), entry.embedding.as_ref())
                else {
                    continue;
                };
                let cache_key = entry.key();
                let point_peak = estimate_hnsw_point_peak_bytes(embedding, cache_key, scope_key);
                let next_peak = collected_peak.saturating_add(point_peak);
                if next_peak > peak_estimate {
                    continue;
                }
                collected_peak = next_peak;
                retained_estimate = retained_estimate.saturating_add(
                    estimate_hnsw_point_retained_bytes(embedding, cache_key, scope_key),
                );
                // `embedding.clone()` only bumps the `Arc<[f32]>` refcount, so
                // the scan does not duplicate the cache's float allocation.
                points.push(embedding.clone());
                values.push(VectorEntry {
                    cache_key: cache_key.clone(),
                    scope_key: scope_key.clone(),
                });
            }

            if points.is_empty() {
                return VectorRebuildOutcome::Empty;
            }

            // Hold the full peak lease ACROSS `build`, which allocates internal
            // construction copies; keeping the reservation live means those
            // copies stay inside the cap instead of escaping it.
            let index = HnswBuilder::default()
                .ef_search(max_candidates)
                .ef_construction(max_candidates.max(100))
                .seed(0)
                .build(points, values);

            // Construction temporaries are freed once `build` returns; shrink
            // the lease down to the published generation footprint.
            let retained = retained_estimate.min(peak_estimate);
            lease.shrink_to(retained);
            rebuild_reserved_bytes.store(retained, Ordering::Release);
            VectorRebuildOutcome::Built {
                index,
                lease,
                accounted_bytes: retained,
            }
        })
        .await
    }

    fn store_vector_snapshot_result(
        build_result: Result<VectorRebuildOutcome, tokio::task::JoinError>,
        vector_index: &ArcSwapOption<VectorSnapshot>,
        dirty: &AtomicBool,
        rebuild_reserved_bytes: &AtomicUsize,
    ) {
        rebuild_reserved_bytes.store(0, Ordering::Release);
        match build_result {
            Ok(VectorRebuildOutcome::Built {
                index,
                lease,
                accounted_bytes,
            }) => {
                vector_index.store(Some(Arc::new(VectorSnapshot {
                    index,
                    accounted_bytes,
                    _budget_lease: lease,
                })));
            }
            Ok(VectorRebuildOutcome::Empty) => {
                vector_index.store(None);
            }
            Ok(VectorRebuildOutcome::BudgetExhausted) => {
                // Keep the previous published generation; retry when space
                // frees (TTL eviction / entry release).
                dirty.store(true, Ordering::Release);
                debug!(
                    "ai_semantic_cache: semantic vector rebuild skipped; cache byte budget exhausted"
                );
            }
            Err(err) => {
                // Join/cancellation drops any candidate lease held inside the
                // aborted blocking task; re-dirty so a later pass retries.
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
    ///
    /// Returns the peak `cache_budget.used()` observed while the previous
    /// published generation and the candidate rebuild lease overlapped (when
    /// both were non-zero).
    #[allow(dead_code)]
    pub(crate) async fn rebuild_vector_index_for_tests(&self) -> usize {
        let Some(semantic) = self.semantic.as_ref() else {
            return self.cache_budget.used();
        };

        while self
            .vector_index_rebuild_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            tokio::task::yield_now().await;
        }

        self.vector_index_dirty.store(false, Ordering::Release);
        // Keep the previous generation alive so peak (old + candidate) is
        // observable while the rebuild lease is outstanding.
        let previous = self.vector_index.load_full();
        let build_result = Self::build_vector_snapshot(
            Arc::clone(&self.cache),
            self.ttl,
            semantic.max_candidates,
            Arc::clone(&self.cache_budget),
            Arc::clone(&self.rebuild_reserved_bytes),
        )
        .await;
        let peak_used = self.cache_budget.used();
        Self::store_vector_snapshot_result(
            build_result,
            self.vector_index.as_ref(),
            self.vector_index_dirty.as_ref(),
            self.rebuild_reserved_bytes.as_ref(),
        );
        drop(previous);
        self.last_vector_rebuild
            .store(current_epoch_seconds(), Ordering::Release);
        self.vector_index_rebuild_running
            .store(false, Ordering::Release);
        peak_used
    }

    /// Tracked budget usage and the sum of retained entry + published vector
    /// generation + in-flight rebuild reservation bytes. External tests assert
    /// these stay equal after concurrent stores and rebuilds.
    #[allow(dead_code)]
    pub(crate) fn size_accounting_snapshot_for_tests(&self) -> (usize, usize) {
        let tracked = self.cache_budget.used();
        let entries = self
            .cache
            .iter()
            .map(|entry| entry.approx_size)
            .fold(0usize, usize::saturating_add);
        let published = self
            .vector_index
            .load_full()
            .map(|snapshot| snapshot.accounted_bytes)
            .unwrap_or(0);
        let rebuild = self.rebuild_reserved_bytes.load(Ordering::Acquire);
        (
            tracked,
            entries.saturating_add(published).saturating_add(rebuild),
        )
    }

    /// Published HNSW generation bytes currently charged to `cache_budget`.
    #[allow(dead_code)]
    pub(crate) fn vector_snapshot_accounted_bytes_for_tests(&self) -> usize {
        self.vector_index
            .load_full()
            .map(|snapshot| snapshot.accounted_bytes)
            .unwrap_or(0)
    }

    /// Aggregate retained-byte budget usage (entries + vector generations).
    #[allow(dead_code)]
    pub(crate) fn cache_budget_used_for_tests(&self) -> usize {
        self.cache_budget.used()
    }

    /// Force a rebuild reservation attempt that cannot fit, then confirm the
    /// candidate lease is not retained. Returns whether the budget rejected
    /// the reservation (and dirty was re-armed).
    #[allow(dead_code)]
    pub(crate) async fn force_vector_rebuild_budget_failure_for_tests(&self) -> bool {
        let Some(semantic) = self.semantic.as_ref() else {
            return false;
        };
        while self
            .vector_index_rebuild_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            tokio::task::yield_now().await;
        }
        self.vector_index_dirty.store(false, Ordering::Release);
        let before = self.cache_budget.used();
        // Saturate remaining budget so the rebuild estimate cannot acquire.
        let filler = self
            .cache_budget
            .try_acquire(self.max_total_size_bytes.saturating_sub(before).max(1));
        let build_result = Self::build_vector_snapshot(
            Arc::clone(&self.cache),
            self.ttl,
            semantic.max_candidates,
            Arc::clone(&self.cache_budget),
            Arc::clone(&self.rebuild_reserved_bytes),
        )
        .await;
        let rejected = matches!(build_result, Ok(VectorRebuildOutcome::BudgetExhausted))
            && self.rebuild_reserved_bytes.load(Ordering::Acquire) == 0;
        Self::store_vector_snapshot_result(
            build_result,
            self.vector_index.as_ref(),
            self.vector_index_dirty.as_ref(),
            self.rebuild_reserved_bytes.as_ref(),
        );
        drop(filler);
        self.vector_index_rebuild_running
            .store(false, Ordering::Release);
        rejected && self.cache_budget.used() == before
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

    /// Install (or clear) a callback that runs after byte-budget admission and
    /// before insert. Used by external tests to park concurrent stores that
    /// have already reserved leases.
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

    /// Hot-path admission signal for a dirty vector index. Does not spawn work
    /// or scan the map; the lifecycle-owned rebuild worker observes the dirty
    /// flag and interval.
    fn signal_vector_index_refresh_if_due(&self) {
        if self.semantic.is_none() {
            return;
        }
        if !self.vector_index_dirty.load(Ordering::Acquire) {
            return;
        }
        let now_epoch = current_epoch_seconds();
        let has_snapshot = self.vector_index.load().is_some();
        let last = self.last_vector_rebuild.load(Ordering::Relaxed);
        if has_snapshot && now_epoch.saturating_sub(last) < VECTOR_REBUILD_INTERVAL_SECONDS {
            return;
        }
        self.rebuild_signal.notify_one();
    }

    /// Claim the current cleanup interval, if one is due.
    ///
    /// Throttled to once per `CLEANUP_INTERVAL_SECONDS` using a monotonic
    /// elapsed-seconds clock (`created_at`) rather than the wall clock, so a
    /// `SystemTime` jump cannot stall or spuriously trigger cleanup. The CAS
    /// guarantees exactly one caller wins per interval; concurrent callers that
    /// lose the race return `false` without scanning. This is the cheap,
    /// hot-path portion; the O(N) scan/eviction runs in [`Self::run_cleanup`].
    fn try_claim_cleanup_interval(&self) -> bool {
        let now = Instant::now();
        let now_secs = now.saturating_duration_since(self.created_at).as_secs();

        // `last_cleanup` starts at `u64::MAX` (never cleaned) so the first
        // call always runs; afterwards it holds the monotonic second at which
        // the most recent pass ran.
        let last = self.last_cleanup.load(Ordering::Relaxed);
        if last != u64::MAX && now_secs.saturating_sub(last) < CLEANUP_INTERVAL_SECONDS {
            return false;
        }
        self.last_cleanup
            .compare_exchange(last, now_secs, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }

    /// Hot-path admission signal for expired-entry cleanup.
    ///
    /// The winning request pays only the cheap interval CAS here and notifies
    /// the lifecycle-owned maintenance worker. The full-map `DashMap::retain`
    /// and oldest-entry selection never run on the request task. Hard
    /// total-byte admission (`max_total_size_bytes`) stays independent on the
    /// store path via byte leases.
    fn signal_cleanup_if_due(&self) {
        if !self.try_claim_cleanup_interval() {
            return;
        }
        self.cleanup_signal.notify_one();
    }

    /// Full-map expired-entry sweep and max-entries eviction. Returns whether a
    /// semantic (embedded) entry was removed so callers can re-dirty the vector
    /// index. Entry byte leases release when the removed `CacheEntry` drops.
    fn run_cleanup(cache: &DashMap<String, CacheEntry>, ttl: Duration, max_entries: usize) -> bool {
        let now = Instant::now();
        let mut removed_semantic_entry = false;
        cache.retain(|_, entry| {
            if now.duration_since(entry.inserted_at) >= ttl {
                removed_semantic_entry |= entry.embedding.is_some();
                false
            } else {
                true
            }
        });

        // Enforce max entries by removing oldest. Use partial-select
        // (`select_nth_unstable_by_key`, average O(n)) instead of a full
        // sort (O(n log n)) — we only need to identify the k oldest, not
        // sort the entire cache.
        if cache.len() > max_entries {
            let mut entries_with_time: Vec<(String, Instant)> = cache
                .iter()
                .map(|entry| (entry.key().clone(), entry.value().inserted_at))
                .collect();

            let to_remove = cache.len().saturating_sub(max_entries);
            if to_remove > 0 && to_remove < entries_with_time.len() {
                // After this call, indices [0..to_remove) hold the
                // `to_remove` oldest entries (in unspecified order among
                // themselves), which is all we need for eviction.
                entries_with_time.select_nth_unstable_by_key(to_remove - 1, |(_, t)| *t);
            }

            for (key, _) in entries_with_time.into_iter().take(to_remove) {
                if let Some((_, removed)) = cache.remove(&key) {
                    removed_semantic_entry |= removed.embedding.is_some();
                    // Lease releases when `removed` drops.
                }
            }
        }
        removed_semantic_entry
    }

    /// Synchronous cleanup used only by the external test crate's
    /// `force_cleanup_for_tests`, which wants the sweep to have completed by the
    /// time it returns (the production hot path uses [`Self::signal_cleanup_if_due`]).
    fn cleanup_expired(&self) {
        if !self.try_claim_cleanup_interval() {
            return;
        }
        if Self::run_cleanup(&self.cache, self.ttl, self.max_entries) {
            self.mark_vector_index_dirty();
        }
    }

    /// Authenticate and seal a Redis envelope. Returns `None` when Redis mode
    /// cannot authenticate (fail closed — never write an unauthenticated value).
    fn seal_redis_entry(
        &self,
        redis_key: &str,
        status_code: u16,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> Option<SerializableCacheEntry> {
        let integrity_key = self.redis_integrity_key.as_ref()?;
        let sealed_at_epoch_seconds = current_epoch_seconds();
        let mac = compute_redis_envelope_mac(
            integrity_key,
            &RedisEnvelopeMacInput {
                redis_key,
                version: SEMANTIC_CACHE_ENTRY_VERSION,
                sealed_at_epoch_seconds,
                status_code,
                headers,
                body,
                semantic_scope_key: None,
                embedding: None,
            },
        )?;
        Some(SerializableCacheEntry {
            version: SEMANTIC_CACHE_ENTRY_VERSION,
            sealed_at_epoch_seconds,
            status_code,
            headers: headers.clone(),
            body: body.to_vec(),
            semantic_scope_key: None,
            embedding: None,
            integrity: Some(hex::encode(mac)),
        })
    }

    /// Whether lifecycle maintenance workers have been staged. External tests
    /// observe activation rollback / reload drop behavior.
    #[allow(dead_code)]
    pub(crate) fn maintenance_staged_for_tests(&self) -> bool {
        self.maintenance
            .lock()
            .map(|guard| guard.is_some())
            .unwrap_or(false)
    }

    /// Whether [`Plugin::commit_background_tasks`] has released maintenance.
    #[allow(dead_code)]
    pub(crate) fn maintenance_committed_for_tests(&self) -> bool {
        self.maintenance_committed.load(Ordering::Acquire)
    }

    /// Count of lifecycle JoinHandles currently retained (0 after drop/abort).
    #[allow(dead_code)]
    pub(crate) fn maintenance_handle_count_for_tests(&self) -> usize {
        self.maintenance
            .lock()
            .map(|guard| guard.as_ref().map(|h| h.handles.len()).unwrap_or(0))
            .unwrap_or(0)
    }

    /// Notify the cleanup worker without claiming the interval (test scheduling).
    #[allow(dead_code)]
    pub(crate) fn notify_cleanup_for_tests(&self) {
        self.cleanup_signal.notify_one();
    }

    /// Notify the rebuild worker (test scheduling).
    #[allow(dead_code)]
    pub(crate) fn notify_rebuild_for_tests(&self) {
        self.rebuild_signal.notify_one();
    }

    /// Override the singleflight follower/admission wait used by external
    /// timeout tests. Pass `None` to restore the production default.
    #[allow(dead_code)]
    pub(crate) fn set_singleflight_wait_override_for_tests(&self, wait: Option<Duration>) {
        let ms = wait
            .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
            .unwrap_or(0);
        self.embedding_singleflight_wait_override_ms
            .store(ms, Ordering::Relaxed);
    }
}

impl Drop for AiSemanticCache {
    fn drop(&mut self) {
        // Cooperatively cancel lifecycle-owned maintenance on generation
        // drop/reload. Aborting the async owner prevents new work; a
        // spawn_blocking sweep/build already scheduled can run to completion,
        // then releases its bounded workspace lease.
        self.maintenance_committed.store(false, Ordering::Release);
        let handles = match self.maintenance.get_mut() {
            Ok(slot) => slot.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(handles) = handles {
            handles.cancel.cancel();
            for handle in handles.handles {
                handle.abort();
            }
        }
    }
}

/// Resets the `cleanup_running` guard on drop so a cancelled or panicking
/// cleanup task cannot permanently block future cleanup scheduling.
struct CleanupRunningGuard {
    running: Arc<AtomicBool>,
}

impl Drop for CleanupRunningGuard {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
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
        key_input.push_str("proxy:");
        append_len_prefixed(key_input, &proxy.id);

        // Canonical route/operation identity within the same proxy. This plugin
        // runs after route-dispatch plugins (`ai_stream_router`, `mcp_gateway`,
        // `a2a_gateway`, `mesh_route_dispatch`) so `route_override_*` already
        // reflects the effective destination that will serve a miss. Exact and
        // semantic scope keys share these dimensions:
        // - `listen_path` (route template / matched proxy route identity; binds
        //   dynamic path segments to the configured route rather than only the
        //   raw request path)
        // - request path (distinguishes sibling operations under one template
        //   and rewritten public paths)
        // - post-routing rewrite path when present
        // - effective destination/provider (upstream id, or direct host/port/
        //   scheme override, else the proxy's configured backend identity)
        start_key_part(key_input, has_part);
        key_input.push_str("route:");
        if let Some(listen_path) = proxy.listen_path.as_deref() {
            key_input.push_str("lp:");
            append_len_prefixed(key_input, listen_path);
            key_input.push('|');
        }
        key_input.push_str("path:");
        append_len_prefixed(key_input, &ctx.path);
        if let Some(rewrite) = ctx.route_override_path.as_deref() {
            key_input.push_str("|rw:");
            append_len_prefixed(key_input, rewrite);
            if ctx.route_override_path_is_absolute {
                key_input.push_str("|rwa:1");
            }
        }
        start_key_part(key_input, has_part);
        key_input.push_str("dst:");
        append_effective_destination_identity(ctx, proxy.as_ref(), key_input);
    }

    if plugin.scope_by_consumer
        && let Some(identity) = ctx.effective_identity()
    {
        start_key_part(key_input, has_part);
        key_input.push_str("consumer:");
        append_len_prefixed(key_input, identity);
    }

    if plugin.include_model_in_key
        && let Some(model) = body.get("model").and_then(|m| m.as_str())
    {
        start_key_part(key_input, has_part);
        key_input.push_str("m:");
        append_len_prefixed(key_input, model);
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
        key_input.push_str(&canonical_json_for_key(value));
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
        key_input.push_str(&canonical_json_for_key(value));
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

fn extract_message_content(msg: &Value, mode: PromptTextCanon) -> String {
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
    canonicalize_prompt_text(&raw, mode)
}

fn extract_gemini_parts_text(parts: &[Value], mode: PromptTextCanon) -> String {
    let mut texts = Vec::new();
    for part in parts {
        if is_gemini_text_part(part)
            && let Some(text) = part.get("text").and_then(|t| t.as_str())
        {
            texts.push(text);
        }
    }
    canonicalize_prompt_text(&texts.join(" "), mode)
}

fn extract_responses_input_text(input: &Value, mode: PromptTextCanon) -> String {
    match input {
        Value::String(text) => canonicalize_prompt_text(text, mode),
        Value::Array(items) => {
            let mut texts = Vec::new();
            for item in items {
                push_responses_item_text(item, &mut texts);
            }
            canonicalize_prompt_text(&texts.join(" "), mode)
        }
        Value::Object(_) => {
            let mut texts = Vec::new();
            push_responses_item_text(input, &mut texts);
            canonicalize_prompt_text(&texts.join(" "), mode)
        }
        _ => String::new(),
    }
}

fn append_responses_prompt_exact_key(input: &Value, key_input: &mut String) -> Option<()> {
    match input {
        Value::String(_) | Value::Array(_) | Value::Object(_) => {}
        _ => return None,
    }
    append_len_prefixed(key_input, &canonical_json_for_key(input));
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
                append_len_prefixed(key_input, role);
                append_len_prefixed(
                    key_input,
                    &canonical_json_for_key(msg.get("content").unwrap_or(&Value::Null)),
                );
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
                append_len_prefixed(key_input, role);
                append_len_prefixed(
                    key_input,
                    &canonical_json_for_key(content.get("parts").unwrap_or(&Value::Null)),
                );
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
                    append_len_prefixed(key_input, role);
                    append_len_prefixed(
                        key_input,
                        &canonical_json_for_key(
                            msg.get("message")
                                .or_else(|| msg.get("content"))
                                .unwrap_or(&Value::Null),
                        ),
                    );
                }
            }
            if let Some(message) = body.get("message").and_then(|m| m.as_str()) {
                append_len_prefixed(key_input, "user");
                append_len_prefixed(key_input, message);
            }
            Some(())
        }
        CacheRequestFamily::LegacyPrompt => {
            let prompt = body.get("prompt")?;
            start_key_part(key_input, has_part);
            key_input.push_str("prompt:");
            append_len_prefixed(
                key_input,
                &prompt_value_for_key(prompt, PromptTextCanon::Exact),
            );
            Some(())
        }
        CacheRequestFamily::Tgi => {
            let inputs = body.get("inputs")?;
            start_key_part(key_input, has_part);
            key_input.push_str("inputs:");
            append_len_prefixed(
                key_input,
                &prompt_value_for_key(inputs, PromptTextCanon::Exact),
            );
            Some(())
        }
        CacheRequestFamily::Titan => {
            let input_text = body.get("inputText").and_then(|v| v.as_str())?;
            start_key_part(key_input, has_part);
            key_input.push_str("inputText:");
            append_len_prefixed(key_input, input_text);
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
                append_len_prefixed(key_input, &canonical_json_for_key(system));
            }
            if let Some(preamble) = body.get("preamble").and_then(|v| v.as_str()) {
                start_key_part(key_input, has_part);
                key_input.push_str("preamble:");
                append_len_prefixed(key_input, preamble);
            }
        }
        CacheRequestFamily::Responses => {
            if let Some(instructions) = body.get("instructions") {
                start_key_part(key_input, has_part);
                key_input.push_str("instructions:");
                append_len_prefixed(
                    key_input,
                    &prompt_value_for_key(instructions, PromptTextCanon::Exact),
                );
            }
            if let Some(previous) = body.get("previous_response_id").and_then(|v| v.as_str()) {
                start_key_part(key_input, has_part);
                key_input.push_str("previous_response_id:");
                append_len_prefixed(key_input, previous);
            }
        }
        CacheRequestFamily::Gemini => {
            for field in ["systemInstruction", "system_instruction"] {
                if let Some(system) = body.get(field) {
                    start_key_part(key_input, has_part);
                    key_input.push_str(field);
                    key_input.push(':');
                    append_len_prefixed(key_input, &canonical_json_for_key(system));
                }
            }
        }
        CacheRequestFamily::Cohere => {
            if let Some(preamble) = body.get("preamble").and_then(|v| v.as_str()) {
                start_key_part(key_input, has_part);
                key_input.push_str("preamble:");
                append_len_prefixed(key_input, preamble);
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
                    let content = extract_message_content(msg, PromptTextCanon::Semantic);
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
                key_input.push_str(&system_value_for_key(system, PromptTextCanon::Semantic));
            }
            if let Some(preamble) = body.get("preamble").and_then(|v| v.as_str()) {
                start_key_part(key_input, has_part);
                key_input.push_str("preamble:");
                key_input.push_str(&normalize_text(preamble));
            }
        }
        CacheRequestFamily::Responses => {
            if let Some(instructions) = body.get("instructions") {
                let normalized = prompt_value_for_key(instructions, PromptTextCanon::Semantic);
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
                append_len_prefixed(key_input, previous);
            }
        }
        CacheRequestFamily::Gemini => {
            for field in ["systemInstruction", "system_instruction"] {
                if let Some(system) = body.get(field) {
                    let normalized = gemini_instruction_for_key(system, PromptTextCanon::Semantic);
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
                let content = extract_message_content(msg, PromptTextCanon::Semantic);
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
                let text = extract_responses_input_text(raw, PromptTextCanon::Semantic);
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
                    .map(|parts| extract_gemini_parts_text(parts, PromptTextCanon::Semantic))
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
            let prompt = prompt_value_for_key(body.get("prompt")?, PromptTextCanon::Semantic);
            if !prompt.is_empty() {
                input.push_str("prompt: ");
                input.push_str(&prompt);
                input.push('\n');
            }
        }
        CacheRequestFamily::Tgi => {
            let inputs = prompt_value_for_key(body.get("inputs")?, PromptTextCanon::Semantic);
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

fn prompt_value_for_key(value: &Value, mode: PromptTextCanon) -> String {
    match value {
        Value::String(text) => canonicalize_prompt_text(text, mode),
        Value::Array(items) => {
            let mut normalized = String::new();
            let _ = write!(normalized, "array:{}:", items.len());
            for item in items {
                let text = match item {
                    Value::String(text) => canonicalize_prompt_text(text, mode),
                    other => canonicalize_prompt_text(&canonical_json_for_key(other), mode),
                };
                append_len_prefixed(&mut normalized, &text);
            }
            normalized
        }
        other => canonicalize_prompt_text(&canonical_json_for_key(other), mode),
    }
}

fn gemini_instruction_for_key(system: &Value, mode: PromptTextCanon) -> String {
    if let Some(text) = system.as_str() {
        return canonicalize_prompt_text(text, mode);
    }
    if let Some(parts) = system.get("parts").and_then(|p| p.as_array()) {
        return extract_gemini_parts_text(parts, mode);
    }
    if let Some(parts) = system.as_array() {
        return extract_gemini_parts_text(parts, mode);
    }
    canonicalize_prompt_text(&canonical_json_for_key(system), mode)
}

fn system_value_for_key(system: &Value, mode: PromptTextCanon) -> String {
    if let Some(s) = system.as_str() {
        canonicalize_prompt_text(s, mode)
    } else if let Some(parts) = system.as_array() {
        let mut texts = Vec::with_capacity(parts.len());
        for part in parts {
            if part.get("type").and_then(|t| t.as_str()) == Some("text")
                && let Some(text) = part.get("text").and_then(|t| t.as_str())
            {
                texts.push(text);
            }
        }
        canonicalize_prompt_text(&texts.join(" "), mode)
    } else {
        canonicalize_prompt_text(&canonical_json_for_key(system), mode)
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
    canonical_json_for_key(value)
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
    // copy. Published HNSW generations and in-flight rebuild workspace are
    // charged separately against the same `max_total_size_bytes` budget.
    mem::size_of::<CacheEntry>()
        .saturating_add(body_len)
        .saturating_add(header_size)
        .saturating_add(scope_size)
        .saturating_add(embedding_size)
}

fn estimate_hnsw_point_retained_bytes(
    embedding: &EmbeddingPoint,
    cache_key: &str,
    scope_key: &str,
) -> usize {
    embedding
        .approx_size()
        .saturating_add(mem::size_of::<VectorEntry>())
        .saturating_add(cache_key.len())
        .saturating_add(scope_key.len())
        .saturating_add(HNSW_GRAPH_OVERHEAD_PER_POINT)
}

fn estimate_hnsw_point_peak_bytes(
    embedding: &EmbeddingPoint,
    cache_key: &str,
    scope_key: &str,
) -> usize {
    // Peak during construction: rebuild scan clone + Hnsw internal clone, plus
    // VectorEntry string clones while sorting values into the published map.
    embedding
        .approx_size()
        .saturating_mul(HNSW_BUILD_EMBEDDING_COPIES)
        .saturating_add(
            mem::size_of::<VectorEntry>()
                .saturating_add(cache_key.len())
                .saturating_add(scope_key.len())
                .saturating_mul(2),
        )
        .saturating_add(HNSW_GRAPH_OVERHEAD_PER_POINT)
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
                    if let Some(parts) = content.get("parts")
                        && content_has_multimodal_parts(parts, PartDialect::Gemini)
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

/// Recursion bound for key-only canonical JSON serialization.
///
/// Ordinary request parsing already has serde_json's recursion guard. This
/// second bound keeps cache-key work independently bounded; unusually deep
/// values fall back to their structurally safe insertion-order serialization,
/// which can only cause a conservative cache miss.
const MAX_CACHE_KEY_JSON_DEPTH: usize = 64;

/// Serialize JSON with recursively sorted object keys while preserving array
/// order and scalar bytes. `serde_json`'s `preserve_order` feature is enabled
/// transitively in this build, so `Value::to_string()` alone is not canonical.
fn canonical_json_for_key(value: &Value) -> String {
    let mut canonical = String::new();
    if append_canonical_json_for_key(&mut canonical, value, MAX_CACHE_KEY_JSON_DEPTH) {
        canonical
    } else {
        value.to_string()
    }
}

fn append_canonical_json_for_key(
    buffer: &mut String,
    value: &Value,
    depth_remaining: usize,
) -> bool {
    match value {
        Value::Array(values) => {
            if depth_remaining == 0 {
                return false;
            }
            buffer.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    buffer.push(',');
                }
                if !append_canonical_json_for_key(buffer, value, depth_remaining - 1) {
                    return false;
                }
            }
            buffer.push(']');
            true
        }
        Value::Object(map) => {
            if depth_remaining == 0 {
                return false;
            }
            buffer.push('{');
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    buffer.push(',');
                }
                let Ok(encoded_key) = serde_json::to_string(key) else {
                    return false;
                };
                buffer.push_str(&encoded_key);
                buffer.push(':');
                let Some(child) = map.get(key) else {
                    return false;
                };
                if !append_canonical_json_for_key(buffer, child, depth_remaining - 1) {
                    return false;
                }
            }
            buffer.push('}');
            true
        }
        _ => {
            let _ = write!(buffer, "{value}");
            true
        }
    }
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

fn parse_embedding_response(
    body: &Value,
    expected_dimension: Option<usize>,
) -> Result<Vec<f32>, String> {
    let (embedding, label) = first_embedding_array(body).ok_or_else(|| {
        "missing embedding array at data[0].embedding, embedding, embedding.values, \
         embeddings[0], embeddings.float[0], predictions[0].embeddings.values, \
         embeddingsByType.float, or results[0].embedding"
            .to_string()
    })?;

    let values = embedding
        .as_array()
        .ok_or_else(|| format!("embedding field at {label} must be an array"))?;
    if values.is_empty() {
        return Err(format!("embedding array at {label} must not be empty"));
    }
    if values.len() > MAX_EMBEDDING_DIMENSIONS {
        return Err(format!(
            "embedding array at {label} exceeds the maximum dimension {MAX_EMBEDDING_DIMENSIONS}"
        ));
    }
    if let Some(expected) = expected_dimension
        && values.len() != expected
    {
        return Err(format!(
            "embedding array at {label} has dimension {}, expected {expected}",
            values.len()
        ));
    }
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

/// How prompt / instruction string bytes are folded into cache material.
///
/// Exact keys preserve LLM-significant case and whitespace. Semantic embedding
/// input and semantic scope text keep the historical lowercase + whitespace
/// collapse so approximate matching is not unintentionally changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PromptTextCanon {
    Exact,
    Semantic,
}

fn canonicalize_prompt_text(text: &str, mode: PromptTextCanon) -> String {
    match mode {
        PromptTextCanon::Exact => text.to_string(),
        PromptTextCanon::Semantic => normalize_text(text),
    }
}

/// Normalize text for semantic embedding/scope material: lowercase, collapse
/// whitespace to single spaces, trim.
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

    fn start_background_tasks(&self) -> Result<(), String> {
        let mut slot = self.maintenance.lock().map_err(|_| {
            "ai_semantic_cache: maintenance lock poisoned; refusing to start workers".to_string()
        })?;
        if slot.is_some() {
            return Ok(());
        }
        let _runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            "ai_semantic_cache: start_background_tasks requires a Tokio runtime".to_string()
        })?;

        let cancel = CancellationToken::new();
        let mut handles = Vec::with_capacity(2);

        // Cleanup worker: waits for commit, then reacts to cheap dirty signals
        // and a bounded interval tick. Never spawned from the request path.
        {
            let cancel = cancel.clone();
            let committed = Arc::clone(&self.maintenance_committed);
            let signal = Arc::clone(&self.cleanup_signal);
            let plugin_cache = Arc::clone(&self.cache);
            let cleanup_running = Arc::clone(&self.cleanup_running);
            let dirty = Arc::clone(&self.vector_index_dirty);
            let rebuild_signal = Arc::clone(&self.rebuild_signal);
            let ttl = self.ttl;
            let max_entries = self.max_entries;
            let semantic_enabled = self.semantic.is_some();
            handles.push(tokio::spawn(async move {
                // Stay dormant until PluginCache commit so activation rollback
                // aborts without maintenance side effects.
                while !committed.load(Ordering::Acquire) {
                    tokio::select! {
                        _ = cancel.cancelled() => return,
                        _ = signal.notified() => {},
                        _ = tokio::time::sleep(Duration::from_millis(25)) => {}
                    }
                }
                let mut interval =
                    tokio::time::interval(Duration::from_secs(CLEANUP_INTERVAL_SECONDS));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => return,
                        _ = signal.notified() => {},
                        _ = interval.tick() => {},
                    }
                    if cancel.is_cancelled() {
                        return;
                    }
                    if cleanup_running
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                        .is_err()
                    {
                        continue;
                    }
                    let _running_guard = CleanupRunningGuard {
                        running: Arc::clone(&cleanup_running),
                    };
                    let cleanup_cache = Arc::clone(&plugin_cache);
                    let removed_semantic = match tokio::task::spawn_blocking(move || {
                        AiSemanticCache::run_cleanup(&cleanup_cache, ttl, max_entries)
                    })
                    .await
                    {
                        Ok(removed) => removed,
                        Err(error) => {
                            debug!(
                                error = %error,
                                "ai_semantic_cache: cleanup worker join failed"
                            );
                            false
                        }
                    };
                    if removed_semantic && semantic_enabled {
                        dirty.store(true, Ordering::Release);
                        rebuild_signal.notify_one();
                    }
                }
            }));
        }

        // Rebuild worker: only meaningful when semantic mode is enabled.
        if self.semantic.is_some() {
            let cancel = cancel.clone();
            let committed = Arc::clone(&self.maintenance_committed);
            let signal = Arc::clone(&self.rebuild_signal);
            // Reconstruct a thin rebuild closure via cloned Arcs + config.
            let cache = Arc::clone(&self.cache);
            let vector_index = Arc::clone(&self.vector_index);
            let dirty = Arc::clone(&self.vector_index_dirty);
            let rebuild_running = Arc::clone(&self.vector_index_rebuild_running);
            let cache_budget = Arc::clone(&self.cache_budget);
            let rebuild_reserved_bytes = Arc::clone(&self.rebuild_reserved_bytes);
            let last_vector_rebuild = Arc::clone(&self.last_vector_rebuild);
            let ttl = self.ttl;
            let max_candidates = self
                .semantic
                .as_ref()
                .map(|s| s.max_candidates)
                .unwrap_or(16);
            handles.push(tokio::spawn(async move {
                while !committed.load(Ordering::Acquire) {
                    tokio::select! {
                        _ = cancel.cancelled() => return,
                        _ = signal.notified() => {},
                        _ = tokio::time::sleep(Duration::from_millis(25)) => {}
                    }
                }
                let mut interval =
                    tokio::time::interval(Duration::from_secs(VECTOR_REBUILD_INTERVAL_SECONDS));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => return,
                        _ = signal.notified() => {},
                        _ = interval.tick() => {},
                    }
                    if cancel.is_cancelled() {
                        return;
                    }
                    if !dirty.load(Ordering::Acquire) {
                        continue;
                    }
                    let now_epoch = current_epoch_seconds();
                    let has_snapshot = vector_index.load().is_some();
                    let last = last_vector_rebuild.load(Ordering::Relaxed);
                    if has_snapshot
                        && now_epoch.saturating_sub(last) < VECTOR_REBUILD_INTERVAL_SECONDS
                    {
                        continue;
                    }
                    if rebuild_running
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                        .is_err()
                    {
                        continue;
                    }
                    if !dirty.swap(false, Ordering::AcqRel) {
                        rebuild_running.store(false, Ordering::Release);
                        continue;
                    }
                    last_vector_rebuild.store(now_epoch, Ordering::Release);
                    let _state_guard = RebuildStateGuard {
                        running: Arc::clone(&rebuild_running),
                        reserved: Arc::clone(&rebuild_reserved_bytes),
                    };
                    let build_result = AiSemanticCache::build_vector_snapshot(
                        Arc::clone(&cache),
                        ttl,
                        max_candidates,
                        Arc::clone(&cache_budget),
                        Arc::clone(&rebuild_reserved_bytes),
                    )
                    .await;
                    AiSemanticCache::store_vector_snapshot_result(
                        build_result,
                        vector_index.as_ref(),
                        dirty.as_ref(),
                        rebuild_reserved_bytes.as_ref(),
                    );
                }
            }));
        }

        *slot = Some(MaintenanceHandles { cancel, handles });
        Ok(())
    }

    fn commit_background_tasks(&self) {
        self.maintenance_committed.store(true, Ordering::Release);
        // Wake staged workers that may be polling for commit.
        self.cleanup_signal.notify_waiters();
        self.rebuild_signal.notify_waiters();
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
        ctx.metadata.contains_key(&self.meta_cache_key)
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
        // prompt text. Clear only this instance's staged key so a later
        // final-body store cannot retain a body that this instance refused to
        // key, without touching sibling instances' staging.
        if classify_cache_request_family(&json).is_none() {
            debug!("ai_semantic_cache: skipping unknown or ambiguous request shape");
            self.clear_instance_staging(ctx);
            self.set_cache_status(ctx, "BYPASS");
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
            // Clear only this instance's staging. Sibling instances keep their
            // own namespaced keys/embeddings; this instance's
            // `on_final_response_body` only observes `meta_cache_key`, so it
            // cannot store under another instance's miss key.
            self.clear_instance_staging(ctx);
            self.set_cache_status(ctx, "BYPASS");
            return PluginResult::Continue;
        }

        let multimodal_fingerprint = build_multimodal_fingerprint(&json);

        // Build cache key
        let cache_key = match self.build_cache_key(ctx, &json, multimodal_fingerprint.as_deref()) {
            Some(k) => k,
            None => {
                self.clear_instance_staging(ctx);
                self.set_cache_status(ctx, "BYPASS");
                return PluginResult::Continue;
            }
        };

        // Periodic cleanup — scheduled off the request hot path so no single
        // request pays the full-map scan / oldest-entry eviction.
        self.signal_cleanup_if_due();

        // Check Redis first (centralized cache across instances). Redis is an
        // untrusted trust boundary: every hit is byte-bounded before allocation
        // and re-validated against the same status/content-type/size/JSON/header
        // admission contract as a local store, and any entry that fails is
        // quarantined so it cannot inject an oversized, non-JSON, wrong-status,
        // or unsanitized response.
        if let Some(ref redis) = self.redis_client
            && redis.is_available()
        {
            let redis_key = redis.make_key(&[&cache_key]);
            match redis
                .get_bytes_bounded(&redis_key, self.redis_value_byte_cap())
                .await
            {
                Ok(BoundedRedisValue::Found(data)) => {
                    match serde_json::from_slice::<SerializableCacheEntry>(&data)
                        .ok()
                        .and_then(|entry| self.admit_redis_hit(entry, &redis_key))
                    {
                        Some(cached) => {
                            debug!(
                                cache_key = %cache_key,
                                "ai_semantic_cache: Redis cache HIT, returning cached response"
                            );
                            let mut response_headers = cached.headers;
                            response_headers
                                .insert("x-ai-cache-status".to_string(), "HIT".to_string());
                            self.clear_instance_staging(ctx);
                            self.set_cache_status(ctx, "HIT");
                            return PluginResult::RejectBinary {
                                status_code: cached.status_code,
                                body: cached.body,
                                headers: response_headers,
                            };
                        }
                        None => {
                            debug!(
                                cache_key = %cache_key,
                                "ai_semantic_cache: quarantining Redis entry that failed hit-side admission"
                            );
                            let _ = redis.delete(&redis_key).await;
                        }
                    }
                }
                Ok(BoundedRedisValue::Oversized { length }) => {
                    debug!(
                        cache_key = %cache_key,
                        length,
                        cap = self.redis_value_byte_cap(),
                        "ai_semantic_cache: quarantining oversized Redis entry"
                    );
                    let _ = redis.delete(&redis_key).await;
                }
                Ok(BoundedRedisValue::Empty) => {
                    debug!(
                        cache_key = %cache_key,
                        "ai_semantic_cache: quarantining empty Redis entry"
                    );
                    let _ = redis.delete(&redis_key).await;
                }
                Ok(BoundedRedisValue::Missing) | Err(()) => {}
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
                self.clear_instance_staging(ctx);
                self.set_cache_status(ctx, "HIT");
                return PluginResult::RejectBinary {
                    status_code: entry.status_code,
                    body: entry.body.clone(),
                    headers: response_headers,
                };
            }
            // Expired — remove. Lease releases when `removed` drops (including
            // when the embedding guard fails after remove succeeds).
            drop(entry);
            if let Some((_, removed)) = self.cache.remove(&cache_key)
                && removed.embedding.is_some()
            {
                self.mark_vector_index_dirty();
                self.signal_vector_index_refresh_if_due();
            }
        }

        self.signal_vector_index_refresh_if_due();

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
                        self.clear_instance_staging(ctx);
                        self.set_cache_status(ctx, "HIT");
                        ctx.metadata
                            .insert(self.meta_match.clone(), "semantic".to_string());
                        ctx.metadata
                            .insert(self.meta_similarity.clone(), format!("{similarity:.6}"));
                        return PluginResult::RejectBinary {
                            status_code: entry.status_code,
                            body: entry.body.clone(),
                            headers: response_headers,
                        };
                    }

                    self.stage_semantic_miss(ctx, scope_key, embedding.to_vec());
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
        ctx.metadata.insert(self.meta_cache_key.clone(), cache_key);
        self.set_cache_status(ctx, "MISS");

        PluginResult::Continue
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Inject cache status header from this instance's namespaced status.
        if let Some(status) = self.cache_status(ctx) {
            response_headers.insert("x-ai-cache-status".to_string(), status.to_string());
        }
        PluginResult::Continue
    }

    /// `x-ai-cache-status` is an unconditional gateway `insert`, so a backend
    /// echoing the identical value hides the write from net-diff mutation
    /// tracking and a later gRPC-deadline rebuild would drop the gateway's cache
    /// telemetry. Declared owned only when this request actually produced a
    /// status to write.
    fn owns_deadline_response_header(&self, ctx: &RequestContext, name: &str) -> bool {
        name.eq_ignore_ascii_case("x-ai-cache-status") && self.cache_status(ctx).is_some()
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
        // `before_proxy` sets `meta_cache_key` so this hook stores the
        // (real) backend response. But this plugin (priority 2996) runs before
        // later synthetic-2xx producers such as `serverless_function` (3025),
        // `response_mock` (3030), and `ai_federation` (4060), so when one of
        // those short-circuits
        // with a 2xx body, the generic synthetic body-hook path
        // (`apply_synthetic_response_body_hooks`) re-runs this
        // `on_final_response_body` with `meta_cache_key` still set from
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

        // Read only this instance's staged key so sibling instances keep their
        // own miss markers for later final hooks in plugin order.
        let cache_key = match ctx.metadata.get(&self.meta_cache_key) {
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
        // Consume this instance's staging only after admission succeeds so
        // early skips leave siblings untouched and leave this instance's
        // markers intact if a later retry path re-enters the hook.
        ctx.metadata.remove(&self.meta_cache_key);
        let (semantic_scope_key, embedding) = self.take_staged_semantic(ctx);
        let approx_size = cache_entry_approx_size(
            body.len(),
            &safe_headers,
            semantic_scope_key.as_ref(),
            embedding.as_ref(),
        );

        // Hard total-size enforcement via lock-free byte leases. Concurrent
        // distinct-key admits race on `ByteBudget::try_acquire`; losers skip
        // retention so published + in-flight HNSW generations and entries
        // cannot permanently exceed `max_total_size_bytes`.
        let Some(budget_lease) = self.cache_budget.try_acquire(approx_size) else {
            debug!(
                cache_key = %cache_key,
                entry_size = approx_size,
                max_total = self.max_total_size_bytes,
                "ai_semantic_cache: total cache size would exceed limit, skipping"
            );
            return PluginResult::Continue;
        };

        // Optional test rendezvous: park here after admission so concurrent
        // stores can observe lease ownership before insert. Production keeps
        // the hook empty (lock-free no-op).
        self.run_store_post_admit_hook();

        let entry = CacheEntry {
            status_code: response_status,
            headers: safe_headers.clone(),
            body: Bytes::from(body.to_vec()),
            inserted_at: Instant::now(),
            approx_size,
            semantic_scope_key: semantic_scope_key.clone(),
            embedding: embedding.clone(),
            _budget_lease: budget_lease,
        };

        // Insert. `DashMap::insert` is atomic per key and returns any
        // displaced value; dropping that value releases its byte lease so
        // same-key races never leave phantom retained bytes.
        let mut replaced_semantic_entry = false;
        if let Some(old) = self.cache.insert(cache_key.clone(), entry) {
            replaced_semantic_entry = old.embedding.is_some();
        }
        if replaced_semantic_entry || embedding.is_some() {
            self.mark_vector_index_dirty();
            self.signal_vector_index_refresh_if_due();
        }

        // Also store in Redis if configured
        if let Some(ref redis) = self.redis_client
            && redis.is_available()
        {
            let redis_key = redis.make_key(&[&cache_key]);
            if let Some(serializable) =
                self.seal_redis_entry(&redis_key, response_status, &safe_headers, body)
                && let Ok(data) = serde_json::to_vec(&serializable)
            {
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

fn append_effective_destination_identity(
    ctx: &RequestContext,
    proxy: &crate::config::types::Proxy,
    key_input: &mut String,
) {
    if let Some(upstream) = ctx.effective_upstream_id(proxy) {
        key_input.push_str("up:");
        append_len_prefixed(key_input, upstream);
    } else {
        // Direct-backend override or the proxy's configured backend. Always bind
        // host/port so a route rewrite to a different provider cannot share a
        // cache entry with the proxy default destination.
        key_input.push_str("host:");
        append_len_prefixed(key_input, ctx.effective_backend_host(proxy));
        let _ = write!(key_input, "|port:{}", ctx.effective_backend_port(proxy));
        if let Some(scheme) = ctx.route_override_backend_scheme {
            let _ = write!(key_input, "|scheme:{scheme}");
        } else if let Some(scheme) = proxy.backend_scheme {
            let _ = write!(key_input, "|pscheme:{scheme}");
        }
    }
    if let Some(authority) = ctx.route_override_authority.as_deref() {
        key_input.push_str("|auth:");
        append_len_prefixed(key_input, authority);
    }
}

/// Length-framed Redis envelope fields covered by the authenticity MAC.
///
/// Kept as one cohesive input so the MAC surface stays auditable without an
/// 8-argument helper (key material remains a separate first parameter).
struct RedisEnvelopeMacInput<'a> {
    redis_key: &'a str,
    version: u8,
    sealed_at_epoch_seconds: u64,
    status_code: u16,
    headers: &'a HashMap<String, String>,
    body: &'a [u8],
    semantic_scope_key: Option<&'a str>,
    embedding: Option<&'a [f32]>,
}

/// HMAC-SHA256 authenticity tag over the Redis envelope and key context.
///
/// Binds status/headers/body (and optional semantic fields) to the Redis
/// namespace/key so a valid-looking foreign JSON document under another key
/// cannot be replayed. Returns `None` only when the HMAC implementation fails
/// to initialize (fail closed).
fn compute_redis_envelope_mac(key: &[u8], envelope: &RedisEnvelopeMacInput<'_>) -> Option<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key).ok()?;
    mac.update(b"ai_semantic_cache.v4\0");
    mac.update(&(envelope.redis_key.len() as u64).to_le_bytes());
    mac.update(envelope.redis_key.as_bytes());
    mac.update(&[envelope.version]);
    mac.update(&envelope.sealed_at_epoch_seconds.to_le_bytes());
    mac.update(&envelope.status_code.to_le_bytes());
    let mut header_pairs: Vec<(&str, &str)> = envelope
        .headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    header_pairs.sort_by(|a, b| a.0.cmp(b.0).then(a.1.cmp(b.1)));
    mac.update(&(header_pairs.len() as u64).to_le_bytes());
    for (name, value) in header_pairs {
        mac.update(&(name.len() as u64).to_le_bytes());
        mac.update(name.as_bytes());
        mac.update(&(value.len() as u64).to_le_bytes());
        mac.update(value.as_bytes());
    }
    mac.update(&(envelope.body.len() as u64).to_le_bytes());
    mac.update(envelope.body);
    if let Some(scope) = envelope.semantic_scope_key {
        mac.update(&[1]);
        mac.update(&(scope.len() as u64).to_le_bytes());
        mac.update(scope.as_bytes());
    } else {
        mac.update(&[0]);
    }
    if let Some(values) = envelope.embedding {
        mac.update(&[1]);
        mac.update(&(values.len() as u64).to_le_bytes());
        for value in values {
            mac.update(&value.to_le_bytes());
        }
    } else {
        mac.update(&[0]);
    }
    Some(mac.finalize().into_bytes().to_vec())
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
    if let Some(dimension) = output_dimension
        && dimension > MAX_EMBEDDING_DIMENSIONS
    {
        return Err(format!(
            "ai_semantic_cache: 'semantic_embedding_output_dimension' must be <= {MAX_EMBEDDING_DIMENSIONS}"
        ));
    }
    let similarity_threshold =
        optional_threshold(config, "semantic_similarity_threshold")?.unwrap_or(0.95);
    let max_candidates =
        optional_positive_usize(config, "semantic_vector_max_candidates")?.unwrap_or(16);
    if max_candidates > MAX_SEMANTIC_VECTOR_CANDIDATES_HARD_CAP {
        return Err(format!(
            "ai_semantic_cache: 'semantic_vector_max_candidates' must be <= {MAX_SEMANTIC_VECTOR_CANDIDATES_HARD_CAP} (deployment hard cap)"
        ));
    }
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
        let approx_size = 8usize;
        let lease = plugin
            .cache_budget
            .try_acquire(approx_size)
            .expect("synthetic entry must fit test budget");
        let entry = CacheEntry {
            status_code: 200,
            body: Bytes::from_static(b"\x00\x00\x00\x00\x00\x00\x00\x00"),
            headers: HashMap::new(),
            inserted_at,
            approx_size,
            semantic_scope_key: None,
            embedding: None,
            _budget_lease: lease,
        };
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
        let gemini_malformed_non_text_parts = json!({
            "contents": [{
                "role": "user",
                "parts": {"inlineData": {"mimeType": "image/png", "data": "aGVsbG8="}}
            }]
        });

        for body in [
            &text_only,
            &text_array,
            &multimodal,
            &multimodal_system,
            &gemini_malformed_non_text_parts,
        ] {
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
        assert!(body_has_multimodal_parts(&gemini_malformed_non_text_parts));
    }

    #[tokio::test]
    async fn reject_mode_bypass_clears_only_this_instance_staging() {
        // A prior `ai_semantic_cache` instance in the same `before_proxy` chain
        // may have staged a cache key/embedding/scope under its own instance id.
        // When a later reject-mode instance bypasses a multimodal request, it
        // must clear only its own staging so its `on_final_response_body` does
        // not store, without consuming the sibling's miss markers.
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
        // Simulate staging owned by a sibling instance (different id).
        let sibling_id = plugin.instance_id.wrapping_add(1);
        ctx.metadata.insert(
            staging_metadata_key(sibling_id, CACHE_KEY_SUFFIX),
            "sibling-key".to_string(),
        );
        ctx.ai_semantic_cache_embeddings
            .insert(sibling_id, vec![0.1, 0.2, 0.3]);
        ctx.ai_semantic_cache_scope_keys
            .insert(sibling_id, "sibling-scope".to_string());
        // And a stale entry under this instance that bypass must clear.
        ctx.metadata
            .insert(plugin.meta_cache_key.clone(), "stale-key".to_string());
        ctx.ai_semantic_cache_embeddings
            .insert(plugin.instance_id, vec![9.0, 9.0, 9.0]);
        ctx.ai_semantic_cache_scope_keys
            .insert(plugin.instance_id, "stale-scope".to_string());

        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());

        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(matches!(result, PluginResult::Continue));

        assert!(
            !ctx.metadata.contains_key(&plugin.meta_cache_key),
            "reject bypass must remove this instance's staged cache key"
        );
        assert!(
            !ctx.ai_semantic_cache_embeddings
                .contains_key(&plugin.instance_id),
            "reject bypass must clear this instance's staged embedding"
        );
        assert!(
            !ctx.ai_semantic_cache_scope_keys
                .contains_key(&plugin.instance_id),
            "reject bypass must clear this instance's staged scope key"
        );
        assert_eq!(plugin.cache_status(&ctx), Some("BYPASS"));

        // Sibling staging must survive so the earlier instance can still store.
        assert_eq!(
            ctx.metadata
                .get(&staging_metadata_key(sibling_id, CACHE_KEY_SUFFIX))
                .map(String::as_str),
            Some("sibling-key")
        );
        assert_eq!(
            ctx.ai_semantic_cache_embeddings.get(&sibling_id),
            Some(&vec![0.1, 0.2, 0.3])
        );
        assert_eq!(
            ctx.ai_semantic_cache_scope_keys
                .get(&sibling_id)
                .map(String::as_str),
            Some("sibling-scope")
        );

        // And this instance's consume path must therefore store nothing.
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
                parse_embedding_response(&body, None).unwrap(),
                vec![1.0, 2.0, 3.0]
            );
        }
    }

    #[test]
    fn embedding_response_parser_rejects_oversize_dimension() {
        let values: Vec<f64> = (0..=MAX_EMBEDDING_DIMENSIONS)
            .map(|i| if i == 0 { 1.0 } else { 0.0 })
            .collect();
        let body = json!({ "embedding": values });
        let err = parse_embedding_response(&body, None).expect_err("oversize");
        assert!(err.contains("maximum dimension"), "unexpected error: {err}");
    }

    #[test]
    fn embedding_response_parser_enforces_expected_dimension() {
        let body = json!({ "embedding": [1.0, 0.0, 0.0] });
        let err = parse_embedding_response(&body, Some(2)).expect_err("mismatch");
        assert!(err.contains("expected 2"), "unexpected error: {err}");
        assert_eq!(
            parse_embedding_response(&body, Some(3)).unwrap(),
            vec![1.0, 0.0, 0.0]
        );
    }

    #[test]
    fn exact_prompt_canon_preserves_case_and_whitespace() {
        assert_eq!(
            canonicalize_prompt_text("  Hello   World  ", PromptTextCanon::Exact),
            "  Hello   World  "
        );
        assert_eq!(
            canonicalize_prompt_text("print(\"A\")", PromptTextCanon::Exact),
            "print(\"A\")"
        );
        assert_eq!(
            canonicalize_prompt_text("  Hello   World  ", PromptTextCanon::Semantic),
            "hello world"
        );
    }

    #[test]
    fn redis_serialized_cache_entry_omits_semantic_vector_fields_when_empty() {
        let entry = SerializableCacheEntry {
            version: SEMANTIC_CACHE_ENTRY_VERSION,
            sealed_at_epoch_seconds: current_epoch_seconds(),
            status_code: 200,
            headers: HashMap::new(),
            body: b"cached".to_vec(),
            semantic_scope_key: None,
            embedding: None,
            integrity: None,
        };

        let value = serde_json::to_value(&entry).unwrap();
        assert_eq!(
            value.get("version").and_then(Value::as_u64),
            Some(u64::from(SEMANTIC_CACHE_ENTRY_VERSION))
        );
        assert!(value.get("semantic_scope_key").is_none());
        assert!(value.get("embedding").is_none());
        assert!(value.get("integrity").is_none());
    }

    const TEST_INTEGRITY_KEY: &str = "0123456789abcdef0123456789abcdef";
    const TEST_REDIS_KEY: &str = "ferrum:ai_cache:test-key";

    fn redis_entry(
        version: u8,
        status_code: u16,
        content_type: Option<&str>,
        body: &[u8],
        seal: bool,
    ) -> SerializableCacheEntry {
        let mut headers = HashMap::new();
        let sealed_at_epoch_seconds = current_epoch_seconds();
        if let Some(ct) = content_type {
            headers.insert("content-type".to_string(), ct.to_string());
        }
        let integrity = if seal {
            let mac = compute_redis_envelope_mac(
                TEST_INTEGRITY_KEY.as_bytes(),
                &RedisEnvelopeMacInput {
                    redis_key: TEST_REDIS_KEY,
                    version,
                    sealed_at_epoch_seconds,
                    status_code,
                    headers: &headers,
                    body,
                    semantic_scope_key: None,
                    embedding: None,
                },
            )
            .expect("test HMAC");
            Some(hex::encode(mac))
        } else {
            None
        };
        SerializableCacheEntry {
            version,
            sealed_at_epoch_seconds,
            status_code,
            headers,
            body: body.to_vec(),
            semantic_scope_key: None,
            embedding: None,
            integrity,
        }
    }

    #[test]
    fn admit_redis_hit_reapplies_store_admission_and_sanitizes() {
        let split_headers = HashMap::from([
            ("a".to_string(), "1".to_string()),
            ("b".to_string(), "2".to_string()),
        ]);
        // Intentional embedded NULs: `1` NUL `b` NUL `2` (not an octal `\02`).
        let fused_headers = HashMap::from([("a".to_string(), "1\0b\0\x32".to_string())]);
        let framing_test_sealed_at = current_epoch_seconds();
        let split_mac = compute_redis_envelope_mac(
            TEST_INTEGRITY_KEY.as_bytes(),
            &RedisEnvelopeMacInput {
                redis_key: TEST_REDIS_KEY,
                version: SEMANTIC_CACHE_ENTRY_VERSION,
                sealed_at_epoch_seconds: framing_test_sealed_at,
                status_code: 200,
                headers: &split_headers,
                body: b"body",
                semantic_scope_key: None,
                embedding: None,
            },
        )
        .expect("test HMAC");
        let fused_mac = compute_redis_envelope_mac(
            TEST_INTEGRITY_KEY.as_bytes(),
            &RedisEnvelopeMacInput {
                redis_key: TEST_REDIS_KEY,
                version: SEMANTIC_CACHE_ENTRY_VERSION,
                sealed_at_epoch_seconds: framing_test_sealed_at,
                status_code: 200,
                headers: &fused_headers,
                body: b"body",
                semantic_scope_key: None,
                embedding: None,
            },
        )
        .expect("test HMAC");
        assert_ne!(
            split_mac, fused_mac,
            "length-framed header MAC input must resist NUL boundary repartitioning"
        );

        let plugin = AiSemanticCache::new(
            &json!({
                "ttl_seconds": 600,
                "max_entry_size_bytes": 64,
                "redis_integrity_key": TEST_INTEGRITY_KEY,
            }),
            PluginHttpClient::default(),
        )
        .expect("valid config");

        // Valid, in-version, authenticated JSON entry with an injected sensitive header.
        let mut valid = redis_entry(
            SEMANTIC_CACHE_ENTRY_VERSION,
            200,
            Some("application/json"),
            br#"{"ok":true}"#,
            true,
        );
        // Re-seal after header injection so authenticity covers the stored headers;
        // admission still strips Set-Cookie before replay.
        valid
            .headers
            .insert("set-cookie".to_string(), "sid=secret".to_string());
        let mac = compute_redis_envelope_mac(
            TEST_INTEGRITY_KEY.as_bytes(),
            &RedisEnvelopeMacInput {
                redis_key: TEST_REDIS_KEY,
                version: valid.version,
                sealed_at_epoch_seconds: valid.sealed_at_epoch_seconds,
                status_code: valid.status_code,
                headers: &valid.headers,
                body: &valid.body,
                semantic_scope_key: None,
                embedding: None,
            },
        )
        .expect("test HMAC");
        valid.integrity = Some(hex::encode(mac));
        let admitted = plugin
            .admit_redis_hit(valid, TEST_REDIS_KEY)
            .expect("a valid authenticated JSON 2xx entry must be admitted");
        assert_eq!(admitted.status_code, 200);
        assert_eq!(admitted.body, Bytes::from_static(br#"{"ok":true}"#));
        assert!(
            !admitted
                .headers
                .keys()
                .any(|name| name.eq_ignore_ascii_case("set-cookie")),
            "foreign-injected Set-Cookie must be stripped on the hit path"
        );

        // A valid MAC cannot extend an entry beyond the configured TTL.
        let mut stale = redis_entry(
            SEMANTIC_CACHE_ENTRY_VERSION,
            200,
            Some("application/json"),
            br#"{"ok":true}"#,
            false,
        );
        stale.sealed_at_epoch_seconds = current_epoch_seconds().saturating_sub(600);
        let stale_mac = compute_redis_envelope_mac(
            TEST_INTEGRITY_KEY.as_bytes(),
            &RedisEnvelopeMacInput {
                redis_key: TEST_REDIS_KEY,
                version: stale.version,
                sealed_at_epoch_seconds: stale.sealed_at_epoch_seconds,
                status_code: stale.status_code,
                headers: &stale.headers,
                body: &stale.body,
                semantic_scope_key: None,
                embedding: None,
            },
        )
        .expect("test HMAC");
        stale.integrity = Some(hex::encode(stale_mac));
        assert!(
            plugin.admit_redis_hit(stale, TEST_REDIS_KEY).is_none(),
            "an authenticated entry at the TTL boundary must be quarantined"
        );

        // Missing MAC / cross-key MAC / cross-version envelopes are quarantined.
        assert!(
            plugin
                .admit_redis_hit(
                    redis_entry(
                        SEMANTIC_CACHE_ENTRY_VERSION,
                        200,
                        Some("application/json"),
                        br#"{"ok":true}"#,
                        false,
                    ),
                    TEST_REDIS_KEY,
                )
                .is_none(),
            "missing integrity tag must be quarantined"
        );
        assert!(
            plugin
                .admit_redis_hit(
                    redis_entry(
                        SEMANTIC_CACHE_ENTRY_VERSION,
                        200,
                        Some("application/json"),
                        br#"{"ok":true}"#,
                        true,
                    ),
                    "ferrum:ai_cache:other-key",
                )
                .is_none(),
            "cross-key MAC must be quarantined"
        );
        assert!(
            plugin
                .admit_redis_hit(
                    redis_entry(0, 200, Some("application/json"), br#"{"ok":true}"#, true),
                    TEST_REDIS_KEY,
                )
                .is_none(),
            "cross-version envelope must be quarantined"
        );

        // Non-2xx and no-body 2xx statuses are rejected.
        for status in [500u16, 302, 204, 205] {
            assert!(
                plugin
                    .admit_redis_hit(
                        redis_entry(
                            SEMANTIC_CACHE_ENTRY_VERSION,
                            status,
                            Some("application/json"),
                            br#"{"ok":true}"#,
                            true,
                        ),
                        TEST_REDIS_KEY,
                    )
                    .is_none(),
                "status {status} must not be served from Redis"
            );
        }

        // Oversized body (> max_entry_size_bytes) is rejected even if JSON.
        let big = format!("\"{}\"", "x".repeat(200));
        assert!(
            plugin
                .admit_redis_hit(
                    redis_entry(
                        SEMANTIC_CACHE_ENTRY_VERSION,
                        200,
                        Some("application/json"),
                        big.as_bytes(),
                        true,
                    ),
                    TEST_REDIS_KEY,
                )
                .is_none(),
            "an over-cap body must not be served"
        );

        // Non-JSON content type, missing content type, and invalid JSON body are rejected.
        assert!(
            plugin
                .admit_redis_hit(
                    redis_entry(
                        SEMANTIC_CACHE_ENTRY_VERSION,
                        200,
                        Some("text/html"),
                        b"<html></html>",
                        true,
                    ),
                    TEST_REDIS_KEY,
                )
                .is_none(),
            "non-JSON content type must not be served"
        );
        assert!(
            plugin
                .admit_redis_hit(
                    redis_entry(
                        SEMANTIC_CACHE_ENTRY_VERSION,
                        200,
                        None,
                        br#"{"ok":true}"#,
                        true,
                    ),
                    TEST_REDIS_KEY,
                )
                .is_none(),
            "an entry without a content type must not be served"
        );
        assert!(
            plugin
                .admit_redis_hit(
                    redis_entry(
                        SEMANTIC_CACHE_ENTRY_VERSION,
                        200,
                        Some("application/json"),
                        b"not json",
                        true,
                    ),
                    TEST_REDIS_KEY,
                )
                .is_none(),
            "a syntactically invalid JSON body must not be served"
        );
    }

    #[test]
    fn redis_value_byte_cap_is_hard_capped_and_checked() {
        let plugin = AiSemanticCache::new(
            &json!({
                "ttl_seconds": 600,
                "max_entry_size_bytes": MAX_ENTRY_SIZE_BYTES_HARD_CAP,
                "max_total_size_bytes": MAX_TOTAL_SIZE_BYTES_HARD_CAP,
            }),
            PluginHttpClient::default(),
        )
        .expect("hard-cap config must admit");
        let cap = plugin.redis_value_byte_cap();
        assert!(cap <= MAX_REDIS_VALUE_BYTES_HARD_CAP);
        assert!(
            crate::plugins::utils::redis_rate_limiter::redis_getrange_end_index(cap).is_ok(),
            "deployment caps must convert to a non-negative GETRANGE end index"
        );
        assert!(
            AiSemanticCache::new(
                &json!({"max_entry_size_bytes": MAX_ENTRY_SIZE_BYTES_HARD_CAP + 1}),
                PluginHttpClient::default(),
            )
            .is_err(),
            "over hard-cap max_entry_size_bytes must be rejected"
        );
    }
}

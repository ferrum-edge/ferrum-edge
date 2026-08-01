//! AI Federation Plugin
//!
//! Universal AI gateway that translates OpenAI Chat Completions format to any
//! of the supported AI providers and normalizes responses back to OpenAI format.
//!
//! Uses the "terminate and respond" pattern: runs from the final HTTP request
//! body hook after request transforms, makes its own HTTP call to the matched
//! AI provider through the shared plugin client, and returns
//! `PluginResult::RejectBinary` with the normalized response. The normal proxy
//! dispatch is skipped entirely. Native gRPC is deliberately outside this
//! OpenAI Chat Completions JSON contract.
//! Streaming Chat Completions are intentionally unsupported by this buffered
//! execution path: matched requests with `"stream": true` are rejected with a
//! clear 501 error instead of being forwarded to an unimplemented SSE path.
//!
//! ## Supported Providers
//!
//! **OpenAI-compatible** (send OpenAI format directly, auth differs):
//! - OpenAI, Mistral, xAI (Grok), DeepSeek, Meta Llama, Hugging Face, Azure OpenAI
//!
//! **Requires request translation**:
//! - Anthropic (Messages API), Google Gemini, Google Vertex AI, AWS Bedrock (Converse API), Cohere v2
//!
//! ## Cross-Plugin Synergy
//!
//! Works with the full AI plugin chain on the same proxy:
//! ```text
//! ai_prompt_shield (2925) → ai_request_guard (2975) → ai_prompt_compressor (4055) → ai_federation (4060)
//!                                                        ↓ writes token metadata
//! ai_rate_limiter after_proxy (applies_after_proxy_on_reject=true)
//!                                                        ↓
//! logging plugins see all metadata
//! ```
//!
//! Successful synthetic responses pass through response-side guardrail hooks
//! before the client receives them. This plugin also writes token metadata
//! directly into `ctx.metadata` using the same keys as `ai_token_metrics`, so
//! federation token accounting works even though normal backend dispatch is
//! skipped.

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};
use tracing::{debug, info, warn};
use url::{Host, Url};

use super::utils::aws_sigv4;
use super::utils::body_transform::is_json_content_type;
use super::utils::response_body::{BoundedReadError, read_response_body_bounded};
use super::{
    AiUsageExport, EXTERNAL_OPERATION_COMPLETED_METADATA_KEY, Plugin, PluginHttpClient,
    PluginResult, RELEASE_INFLIGHT_ON_COMMIT_METADATA_KEY, RequestContext,
};

const DEFAULT_MAX_PROVIDER_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_PROVIDER_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const MAX_TRANSLATED_REQUEST_BYTES: usize = 64 * 1024 * 1024;
const MAX_OAUTH_RESPONSE_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 64;
const MAX_CONCURRENT_REQUESTS: usize = 4096;
const MAX_STOP_SEQUENCES: usize = 4;
const MAX_STOP_SEQUENCE_CHARS: usize = 1024;
const MAX_MODEL_IDENTIFIER_BYTES: usize = 256;
const MAX_PROVIDERS: usize = 128;
const MAX_MODEL_PATTERNS_PER_PROVIDER: usize = 128;
const MAX_MODEL_MAPPINGS_PER_PROVIDER: usize = 1024;
const MAX_FORWARDED_PROVIDER_HEADERS: usize = 32;
const MAX_FORWARDED_PROVIDER_HEADER_VALUE_BYTES: usize = 1024;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Supported AI provider types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProviderType {
    OpenAi,
    Anthropic,
    GoogleGemini,
    GoogleVertex,
    AzureOpenAi,
    AwsBedrock,
    Mistral,
    Cohere,
    Xai,
    DeepSeek,
    MetaLlama,
    HuggingFace,
}

impl ProviderType {
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "openai" => Ok(Self::OpenAi),
            "anthropic" => Ok(Self::Anthropic),
            "google_gemini" => Ok(Self::GoogleGemini),
            "google_vertex" => Ok(Self::GoogleVertex),
            "azure_openai" => Ok(Self::AzureOpenAi),
            "aws_bedrock" => Ok(Self::AwsBedrock),
            "mistral" => Ok(Self::Mistral),
            "cohere" => Ok(Self::Cohere),
            "xai" => Ok(Self::Xai),
            "deepseek" => Ok(Self::DeepSeek),
            "meta_llama" => Ok(Self::MetaLlama),
            "hugging_face" => Ok(Self::HuggingFace),
            _ => Err("ai_federation: unknown provider_type".to_string()),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
            Self::Anthropic => "anthropic",
            Self::GoogleGemini => "google_gemini",
            Self::GoogleVertex => "google_vertex",
            Self::AzureOpenAi => "azure_openai",
            Self::AwsBedrock => "aws_bedrock",
            Self::Mistral => "mistral",
            Self::Cohere => "cohere",
            Self::Xai => "xai",
            Self::DeepSeek => "deepseek",
            Self::MetaLlama => "meta_llama",
            Self::HuggingFace => "hugging_face",
        }
    }

    /// Default base URL for each provider.
    fn default_base_url(self) -> &'static str {
        match self {
            Self::OpenAi => "https://api.openai.com/v1/chat/completions",
            Self::Anthropic => "https://api.anthropic.com/v1/messages",
            Self::Mistral => "https://api.mistral.ai/v1/chat/completions",
            Self::Xai => "https://api.x.ai/v1/chat/completions",
            Self::DeepSeek => "https://api.deepseek.com/v1/chat/completions",
            Self::MetaLlama => "https://api.llama.com/v1/chat/completions",
            Self::HuggingFace => "https://router.huggingface.co/v1/chat/completions",
            Self::Cohere => "https://api.cohere.com/v2/chat",
            // These providers have dynamic URLs built from config fields
            Self::GoogleGemini => "https://generativelanguage.googleapis.com",
            Self::GoogleVertex => "https://aiplatform.googleapis.com",
            Self::AzureOpenAi => "https://openai.azure.com",
            Self::AwsBedrock => "https://bedrock-runtime.amazonaws.com",
        }
    }

    /// Whether this provider uses the OpenAI request/response format natively.
    fn is_openai_compatible(self) -> bool {
        matches!(
            self,
            Self::OpenAi
                | Self::Mistral
                | Self::Xai
                | Self::DeepSeek
                | Self::MetaLlama
                | Self::HuggingFace
                | Self::AzureOpenAi
        )
    }
}

/// Authentication method for a provider.
#[derive(Clone)]
enum AuthMethod {
    /// `Authorization: Bearer {api_key}`
    BearerToken { api_key: String },
    /// Custom header (e.g., `x-api-key` for Anthropic, `api-key` for Azure)
    CustomHeader {
        header_name: String,
        api_key: String,
    },
    /// AWS SigV4 request signing
    AwsSigV4 { config: aws_sigv4::AwsSigV4Config },
    /// Google OAuth2 via service account JWT
    GoogleOAuth2 { cache: Arc<OAuth2Cache> },
}

/// How ai_federation handles OpenAI content parts that are not plain text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MultimodalMode {
    /// Reject matched requests with non-text content parts before dispatch.
    Reject,
    /// Translate non-text parts into provider-native request shapes when this
    /// plugin has an explicit preservation mapping.
    Translate,
    /// Drop non-text parts intentionally, send only text, and record metadata
    /// so downstream logs make the omission visible.
    TextOnlyWithWarning,
}

impl MultimodalMode {
    fn from_str(s: &str, provider_name: &str) -> Result<Self, String> {
        match s {
            "reject" => Ok(Self::Reject),
            "translate" => Ok(Self::Translate),
            "text_only_with_warning" => Ok(Self::TextOnlyWithWarning),
            other => Err(format!(
                "ai_federation: provider '{provider_name}' unknown multimodal_mode '{other}' (expected reject, translate, or text_only_with_warning)"
            )),
        }
    }

    fn default_for_provider(provider_type: ProviderType) -> Self {
        if provider_type.is_openai_compatible() || provider_type == ProviderType::Cohere {
            Self::Translate
        } else {
            Self::Reject
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::Translate => "translate",
            Self::TextOnlyWithWarning => "text_only_with_warning",
        }
    }
}

/// Cached OAuth2 access token with expiry.
#[derive(Debug, Clone)]
struct CachedToken {
    token: String,
    expires_at: std::time::Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthFailureImpact {
    /// Local configuration, key parsing, or signing failed before any
    /// provider-owned dependency was contacted.
    CircuitNeutral,
    /// The provider's OAuth dependency could not supply a usable token.
    ProviderUnavailable,
}

struct AuthFailure {
    impact: AuthFailureImpact,
    message: String,
}

impl AuthFailure {
    fn local(message: String) -> Self {
        Self {
            impact: AuthFailureImpact::CircuitNeutral,
            message,
        }
    }

    fn provider_unavailable(message: String) -> Self {
        Self {
            impact: AuthFailureImpact::ProviderUnavailable,
            message,
        }
    }
}

/// Thread-safe OAuth2 token cache for Google Vertex AI.
struct OAuth2Cache {
    cache: ArcSwapOption<CachedToken>,
    refresh_lock: Mutex<()>,
    client_email: String,
    private_key_pem: String,
    token_uri: String,
}

impl OAuth2Cache {
    fn new(service_account_json: String) -> Result<Self, String> {
        let service_account: Value = serde_json::from_str(&service_account_json)
            .map_err(|e| format!("ai_federation: invalid service account JSON: {e}"))?;
        let client_email = service_account["client_email"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or("ai_federation: service account JSON missing client_email")?
            .to_string();
        let private_key_pem = service_account["private_key"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or("ai_federation: service account JSON missing private_key")?
            .to_string();
        let token_uri = service_account["token_uri"]
            .as_str()
            .unwrap_or("https://oauth2.googleapis.com/token")
            .to_string();
        validate_google_token_uri(&token_uri)?;
        jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
            .map_err(|e| format!("ai_federation: invalid service account RSA private key: {e}"))?;

        Ok(Self {
            cache: ArcSwapOption::empty(),
            refresh_lock: Mutex::new(()),
            client_email,
            private_key_pem,
            token_uri,
        })
    }

    async fn get_token(
        &self,
        http_client: &PluginHttpClient,
        latency_accumulator: &AtomicU64,
    ) -> Result<String, AuthFailure> {
        // Hot path: lock-free cache read. Refresh coordination only happens
        // when the cached token is absent or close to expiry.
        if let Some(token) = self.cache.load_full()
            && token.expires_at > std::time::Instant::now() + Duration::from_secs(60)
        {
            return Ok(token.token.clone());
        }

        let _refresh = self.refresh_lock.lock().await;

        // Double-check after acquiring the refresh lock.
        if let Some(token) = self.cache.load_full()
            && token.expires_at > std::time::Instant::now() + Duration::from_secs(60)
        {
            return Ok(token.token.clone());
        }

        let token = self.refresh_token(http_client, latency_accumulator).await?;
        let result = token.token.clone();
        self.cache.store(Some(Arc::new(token)));
        Ok(result)
    }

    async fn refresh_token(
        &self,
        http_client: &PluginHttpClient,
        latency_accumulator: &AtomicU64,
    ) -> Result<CachedToken, AuthFailure> {
        let now = Utc::now().timestamp();
        let claims = json!({
            "iss": self.client_email,
            "scope": "https://www.googleapis.com/auth/cloud-platform",
            "aud": self.token_uri,
            "iat": now,
            "exp": now + 3600,
        });

        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(self.private_key_pem.as_bytes())
            .map_err(|e| {
                AuthFailure::local(format!("ai_federation: invalid RSA private key: {e}"))
            })?;
        let jwt = jsonwebtoken::encode(&header, &claims, &key)
            .map_err(|e| AuthFailure::local(format!("ai_federation: JWT signing failed: {e}")))?;

        let body = format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={}",
            jwt
        );

        let req = http_client
            .get()
            .post(&self.token_uri)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body);
        let resp = http_client
            .execute_redacted_tracked(
                req,
                "ai_federation_oauth2",
                "https://oauth2.googleapis.com/<redacted>",
                latency_accumulator,
            )
            .await
            .map_err(|e| {
                AuthFailure::provider_unavailable(format!(
                    "ai_federation: OAuth2 token request failed: {e}"
                ))
            })?;

        let status = resp.status().as_u16();
        let body_read_started = std::time::Instant::now();
        let body_result = read_response_body_bounded(resp, MAX_OAUTH_RESPONSE_BYTES).await;
        add_external_io_elapsed(latency_accumulator, body_read_started);
        let resp_body = body_result.map_err(|error| {
            AuthFailure::provider_unavailable(match error {
                BoundedReadError::LimitExceeded { .. } => format!(
                    "ai_federation: OAuth2 response exceeded {MAX_OAUTH_RESPONSE_BYTES} byte limit"
                ),
                BoundedReadError::Stream(error) => format!(
                    "ai_federation: OAuth2 response read failed: {}",
                    crate::retry::classify_reqwest_error(&error)
                ),
            })
        })?;

        if status != 200 {
            return Err(AuthFailure::provider_unavailable(format!(
                "ai_federation: OAuth2 token endpoint returned status {status}"
            )));
        }

        let token_resp: Value = serde_json::from_slice(&resp_body).map_err(|e| {
            AuthFailure::provider_unavailable(format!(
                "ai_federation: OAuth2 response parse failed: {e}"
            ))
        })?;

        let access_token = token_resp["access_token"]
            .as_str()
            .filter(|value| !value.is_empty() && value.len() <= MAX_OAUTH_RESPONSE_BYTES)
            .ok_or_else(|| {
                AuthFailure::provider_unavailable(
                    "ai_federation: OAuth2 response missing access_token".to_string(),
                )
            })?
            .to_string();
        let expires_in = match token_resp.get("expires_in") {
            None => 3600,
            Some(value) => value
                .as_u64()
                .filter(|seconds| (1..=86_400).contains(seconds))
                .ok_or_else(|| {
                    AuthFailure::provider_unavailable(
                        "ai_federation: OAuth2 expires_in must be an integer between 1 and 86400"
                            .to_string(),
                    )
                })?,
        };

        Ok(CachedToken {
            token: access_token,
            expires_at: std::time::Instant::now() + Duration::from_secs(expires_in),
        })
    }
}

/// Token usage counts extracted from a provider response.
#[derive(Debug, Default)]
struct TokenCounts {
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
    total_tokens: Option<u64>,
    model: Option<String>,
}

struct ProviderResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProviderCallFailureKind {
    /// The request was proven not to have reached the provider and is safe to
    /// replay on a fallback provider.
    PreWire,
    /// The provider may have processed the POST. Replaying is disabled unless
    /// an operator explicitly accepts duplicate model invocations.
    Ambiguous,
    /// A response exceeded its configured bound. Never replay: the same or a
    /// larger response from another provider would amplify attacker work.
    ResponseTooLarge,
}

struct ProviderCallFailure {
    kind: ProviderCallFailureKind,
    error_class: crate::retry::ErrorClass,
    headers: HashMap<String, String>,
    circuit_failure: bool,
}

enum BoundedJsonSerializationError {
    LimitExceeded,
    Serialization,
}

struct BoundedJsonWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl BoundedJsonWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit.min(8192)),
            limit,
            exceeded: false,
        }
    }
}

impl std::io::Write for BoundedJsonWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if buffer.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(std::io::Error::other(
                "normalized provider response exceeded configured limit",
            ));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn serialize_json_bounded(
    value: &Value,
    limit: usize,
) -> Result<Vec<u8>, BoundedJsonSerializationError> {
    let mut writer = BoundedJsonWriter::new(limit);
    if serde_json::to_writer(&mut writer, value).is_err() {
        return if writer.exceeded {
            Err(BoundedJsonSerializationError::LimitExceeded)
        } else {
            Err(BoundedJsonSerializationError::Serialization)
        };
    }
    Ok(writer.bytes)
}

fn serialize_translated_request(value: &Value, provider: &str) -> Result<Vec<u8>, String> {
    match serialize_json_bounded(value, MAX_TRANSLATED_REQUEST_BYTES) {
        Ok(body) => Ok(body),
        Err(BoundedJsonSerializationError::LimitExceeded) => Err(format!(
            "ai_federation: translated {provider} request exceeded {MAX_TRANSLATED_REQUEST_BYTES} bytes"
        )),
        Err(BoundedJsonSerializationError::Serialization) => Err(format!(
            "ai_federation: failed to serialize translated {provider} request"
        )),
    }
}

/// A pre-resolved provider ready for request dispatch.
struct ResolvedProvider {
    name: String,
    provider_type: ProviderType,
    auth: AuthMethod,
    priority: u32,
    model_patterns: Vec<String>,
    model_mapping: HashMap<String, String>,
    default_model: Option<String>,
    multimodal_mode: MultimodalMode,
    /// Per-provider connect deadline applied via Ferrum's patched reqwest
    /// per-request override.
    connect_timeout: Duration,
    /// Overall per-request deadline applied via reqwest's `.timeout()`.
    read_timeout: Duration,
    max_response_body_bytes: usize,
    circuit: Option<ProviderCircuit>,
    /// Operator-supplied URL override. Used directly by Anthropic and Cohere
    /// dispatch paths that build their own URLs without going through
    /// `url_template`.
    base_url: Option<String>,
    /// Pre-computed URL template — built once at config-load time so
    /// per-request URL construction is one `String` concatenation, not a
    /// multi-arg `format!()` call. Provider-specific config (azure_*,
    /// google_*, aws_region, base_url) is consumed when this is built and
    /// then discarded — we don't need the raw fields at request time.
    url_template: UrlTemplate,
}

#[derive(Debug, Clone, Copy)]
struct ProviderCircuitConfig {
    failure_threshold: u32,
    cooldown: Duration,
    success_threshold: u32,
}

struct ProviderCircuit {
    config: ProviderCircuitConfig,
    consecutive_failures: AtomicU32,
    open_until_monotonic_ms: AtomicU64,
    metrics_open: AtomicBool,
    half_open_in_flight: AtomicBool,
    half_open_successes: AtomicU32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitAdmission {
    Closed,
    HalfOpenProbe,
    Open,
}

/// Cancellation-safe lease for a half-open probe. Provider dispatch awaits
/// DNS, connect, response headers, and body reads; dropping that future must
/// not leave the circuit's single probe slot permanently occupied.
struct HalfOpenProbeGuard<'a> {
    circuit: &'a ProviderCircuit,
    release_on_drop: bool,
}

impl<'a> HalfOpenProbeGuard<'a> {
    fn new(circuit: &'a ProviderCircuit) -> Self {
        Self {
            circuit,
            release_on_drop: true,
        }
    }

    /// An outcome was recorded by the circuit state machine, so dropping this
    /// cancellation lease must not release a slot that a later probe acquired.
    fn resolve(&mut self) {
        self.release_on_drop = false;
    }

    /// Release an admitted probe that stopped before provider I/O produced a
    /// circuit outcome, then disarm the cancellation fallback.
    fn release(&mut self) {
        if self.release_on_drop {
            self.circuit.release_probe(CircuitAdmission::HalfOpenProbe);
            self.release_on_drop = false;
        }
    }
}

impl Drop for HalfOpenProbeGuard<'_> {
    fn drop(&mut self) {
        if self.release_on_drop {
            self.circuit.release_probe(CircuitAdmission::HalfOpenProbe);
        }
    }
}

impl ProviderCircuit {
    fn new(config: ProviderCircuitConfig) -> Self {
        Self {
            config,
            consecutive_failures: AtomicU32::new(0),
            open_until_monotonic_ms: AtomicU64::new(0),
            metrics_open: AtomicBool::new(false),
            half_open_in_flight: AtomicBool::new(false),
            half_open_successes: AtomicU32::new(0),
        }
    }

    fn admit(&self) -> CircuitAdmission {
        let open_until = self.open_until_monotonic_ms.load(Ordering::Acquire);
        if open_until == 0 {
            return CircuitAdmission::Closed;
        }
        if circuit_monotonic_millis() < open_until {
            return CircuitAdmission::Open;
        }
        if self
            .half_open_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            super::prometheus_metrics::global_registry().record_ai_federation_half_open_probe();
            CircuitAdmission::HalfOpenProbe
        } else {
            CircuitAdmission::Open
        }
    }

    fn may_admit(&self) -> bool {
        let open_until = self.open_until_monotonic_ms.load(Ordering::Acquire);
        open_until == 0
            || (circuit_monotonic_millis() >= open_until
                && !self.half_open_in_flight.load(Ordering::Acquire))
    }

    fn record_success(&self, provider_name: &str, admission: CircuitAdmission) {
        self.consecutive_failures.store(0, Ordering::Release);
        if admission != CircuitAdmission::HalfOpenProbe {
            return;
        }

        let successes = self
            .half_open_successes
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        if successes >= self.config.success_threshold {
            self.open_until_monotonic_ms.store(0, Ordering::Release);
            self.half_open_successes.store(0, Ordering::Release);
            if self.metrics_open.swap(false, Ordering::AcqRel) {
                super::prometheus_metrics::global_registry().record_ai_federation_circuit_closed();
            }
            info!(
                provider = provider_name,
                "ai_federation: provider circuit closed after successful half-open probe"
            );
        } else {
            self.open_until_monotonic_ms
                .store(circuit_monotonic_millis(), Ordering::Release);
        }
        self.half_open_in_flight.store(false, Ordering::Release);
    }

    fn record_failure(&self, provider_name: &str, admission: CircuitAdmission) {
        if admission == CircuitAdmission::HalfOpenProbe {
            self.open(provider_name, "half_open_probe_failed");
            return;
        }

        let failures = self
            .consecutive_failures
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        if failures >= self.config.failure_threshold {
            self.open(provider_name, "failure_threshold_reached");
        }
    }

    fn release_probe(&self, admission: CircuitAdmission) {
        if admission == CircuitAdmission::HalfOpenProbe {
            self.half_open_in_flight.store(false, Ordering::Release);
        }
    }

    fn open(&self, provider_name: &str, reason: &'static str) {
        let cooldown_ms = self.config.cooldown.as_millis().min(u128::from(u64::MAX)) as u64;
        self.open_until_monotonic_ms.store(
            circuit_monotonic_millis().saturating_add(cooldown_ms),
            Ordering::Release,
        );
        self.consecutive_failures.store(0, Ordering::Release);
        self.half_open_successes.store(0, Ordering::Release);
        self.half_open_in_flight.store(false, Ordering::Release);
        if !self.metrics_open.swap(true, Ordering::AcqRel) {
            super::prometheus_metrics::global_registry().record_ai_federation_circuit_opened();
        }
        warn!(
            provider = provider_name,
            reason,
            cooldown_seconds = self.config.cooldown.as_secs(),
            "ai_federation: provider circuit opened"
        );
    }
}

impl Drop for ProviderCircuit {
    fn drop(&mut self) {
        if self.metrics_open.load(Ordering::Acquire) {
            super::prometheus_metrics::global_registry().release_ai_federation_open_circuit();
        }
    }
}

fn circuit_monotonic_millis() -> u64 {
    // Reserve zero as the circuit's closed-state sentinel. The shared clock is
    // backed by `Instant`, so cooldown admission cannot be extended or
    // shortened by NTP corrections or an operator changing the wall clock.
    crate::socket_opts::monotonic_now_ms().saturating_add(1)
}

fn add_external_io_elapsed(accumulator: &AtomicU64, started: std::time::Instant) {
    let nanos = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
    accumulator.fetch_add(nanos, Ordering::Relaxed);
}

/// How a provider's request URL is assembled.
///
/// Built once at config-load time so the per-request hot path avoids the
/// `format!()` machinery and only does one `String` allocation.
#[derive(Debug, Clone)]
enum UrlTemplate {
    /// Fully static URL — used when the URL does not depend on the request
    /// model (Azure with deployment, OpenAI default, generic base_url).
    Static(Arc<str>),
    /// Static prefix + per-request `model` + static suffix.
    /// Used by Gemini, Vertex AI, and Bedrock where the model name is
    /// embedded in the path.
    PrefixModelSuffix { prefix: Arc<str>, suffix: Arc<str> },
}

impl UrlTemplate {
    /// Render the URL for a specific resolved model.
    fn render(&self, model: &str) -> String {
        match self {
            UrlTemplate::Static(url) => url.to_string(),
            UrlTemplate::PrefixModelSuffix { prefix, suffix } => {
                let mut s = String::with_capacity(prefix.len() + model.len() + suffix.len());
                s.push_str(prefix);
                s.push_str(model);
                s.push_str(suffix);
                s
            }
        }
    }
}

/// Validate an operator-supplied `base_url` against scheme + IP allowlist policy.
///
/// SSRF defense: an admin-API attacker who compromises plugin config can
/// otherwise point `base_url` at an internal endpoint (`http://127.0.0.1`,
/// AWS IMDS `http://169.254.169.254/latest/meta-data/`, an RFC 1918 host
/// inside the gateway's VPC). This guard runs at plugin construction so
/// the misconfigured provider never ships requests.
///
/// Rules:
/// - Must parse as a URL.
/// - Scheme is `https` by default. `http` is only allowed when the
///   per-provider `allow_plaintext: true` opt-in is set.
/// - If the host is a literal IP, it is checked against the gateway-wide
///   `FERRUM_BACKEND_ALLOW_IPS` policy via [`check_backend_ip_allowed`].
/// - If the host is a hostname, no compile-time IP check is possible —
///   runtime DNS resolution flows through `DnsCacheResolver`, which
///   re-applies the same policy before each request lands.
fn validate_base_url(
    provider_name: &str,
    base_url: &str,
    allow_plaintext: bool,
    backend_allow_ips: &crate::config::BackendEgressPolicy,
) -> Result<(), String> {
    let parsed = Url::parse(base_url).map_err(|e| {
        format!("ai_federation: provider '{provider_name}' has an invalid base_url: {e}")
    })?;
    if !base_url.starts_with("https://") && !base_url.starts_with("http://") {
        return Err(format!(
            "ai_federation: provider '{provider_name}' base_url must use a lowercase explicit https:// or http:// scheme"
        ));
    }

    match parsed.scheme() {
        "https" => {}
        "http" => {
            if !allow_plaintext {
                return Err(format!(
                    "ai_federation: provider '{provider_name}' base_url uses 'http://' which is rejected by default; set 'allow_plaintext: true' on the provider to override"
                ));
            }
        }
        other => {
            return Err(format!(
                "ai_federation: provider '{provider_name}' base_url has unsupported scheme '{other}' (expected 'https' or 'http' with allow_plaintext)"
            ));
        }
    }

    if !has_non_empty_authority(base_url) {
        return Err(format!(
            "ai_federation: provider '{provider_name}' base_url has no host"
        ));
    }

    let host = normalized_url_hostname(&parsed)
        .ok_or_else(|| format!("ai_federation: provider '{provider_name}' base_url has no host"))?;

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(format!(
            "ai_federation: provider '{provider_name}' base_url must not contain URL userinfo; use the provider's dedicated credential fields"
        ));
    }
    if parsed.query().is_some() {
        return Err(format!(
            "ai_federation: provider '{provider_name}' base_url must not contain a query string; use dedicated provider fields instead"
        ));
    }
    if parsed.fragment().is_some() {
        return Err(format!(
            "ai_federation: provider '{provider_name}' base_url must not contain a fragment"
        ));
    }

    // If the host is a literal IP, enforce the gateway IP policy at config
    // time. Hostnames are checked at runtime by `DnsCacheResolver`.
    if let Ok(ip) = host.parse::<std::net::IpAddr>()
        && !backend_allow_ips.is_allowed(&ip)
    {
        return Err(format!(
            "ai_federation: provider '{provider_name}' base_url IP {ip} denied by backend egress policy ({backend_allow_ips})"
        ));
    }

    Ok(())
}

fn validate_google_token_uri(token_uri: &str) -> Result<(), String> {
    let parsed = Url::parse(token_uri)
        .map_err(|e| format!("ai_federation: service account token_uri is invalid: {e}"))?;
    if parsed.scheme() != "https"
        || parsed.host_str() != Some("oauth2.googleapis.com")
        || parsed.port().is_some()
        || parsed.path() != "/token"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(
            "ai_federation: service account token_uri must be exactly https://oauth2.googleapis.com/token"
                .to_string(),
        );
    }
    Ok(())
}

fn redacted_endpoint_for_log(url: &str) -> &'static str {
    if url.starts_with("http://") {
        "http://<redacted>"
    } else {
        "https://<redacted>"
    }
}

fn has_non_empty_authority(raw_url: &str) -> bool {
    raw_url
        .split_once("://")
        .and_then(|(_, rest)| rest.split(['/', '?', '#']).next())
        .is_some_and(|authority| !authority.is_empty())
}

fn normalized_url_hostname(url: &Url) -> Option<String> {
    match url.host()? {
        Host::Domain(host) if !host.is_empty() => Some(host.to_string()),
        Host::Ipv4(host) => Some(host.to_string()),
        Host::Ipv6(host) => Some(host.to_string()),
        _ => None,
    }
}

/// Build the URL template for a provider at config-load time.
///
/// The eight-argument shape is intentional: each field comes from a
/// different optional config key and bundling them into a struct would
/// just move the same data through an extra layer of plumbing.
#[allow(clippy::too_many_arguments)]
fn build_url_template(
    provider_type: ProviderType,
    base_url: Option<&str>,
    azure_resource: Option<&str>,
    azure_deployment: Option<&str>,
    azure_api_version: &str,
    google_region: Option<&str>,
    google_project_id: Option<&str>,
    aws_region: Option<&str>,
) -> Result<UrlTemplate, String> {
    if let Some(value) = azure_resource {
        validate_dns_label("azure_resource", value, 2, 64)?;
    }
    if let Some(value) = azure_deployment {
        validate_url_path_component("azure_deployment", value, 64)?;
    }
    validate_url_path_component("azure_api_version", azure_api_version, 64)?;
    if let Some(value) = google_region {
        validate_dns_label("google_region", value, 1, 63)?;
    }
    if let Some(value) = google_project_id {
        validate_url_path_component("google_project_id", value, 128)?;
    }
    if let Some(value) = aws_region {
        validate_dns_label("aws_region", value, 1, 63)?;
    }
    if let Some(base) = base_url {
        return Ok(UrlTemplate::Static(Arc::from(base)));
    }

    let template = match provider_type {
        ProviderType::AzureOpenAi => {
            let resource = azure_resource.unwrap_or("default");
            let deployment = azure_deployment.unwrap_or("default");
            let url = format!(
                "https://{}.openai.azure.com/openai/deployments/{}/chat/completions?api-version={}",
                resource, deployment, azure_api_version
            );
            UrlTemplate::Static(Arc::from(url))
        }

        ProviderType::GoogleGemini => UrlTemplate::PrefixModelSuffix {
            prefix: Arc::from("https://generativelanguage.googleapis.com/v1beta/models/"),
            suffix: Arc::from(":generateContent"),
        },

        ProviderType::GoogleVertex => {
            let region = google_region.unwrap_or("us-central1");
            let project = google_project_id.unwrap_or("default");
            let prefix = format!(
                "https://{}-aiplatform.googleapis.com/v1/projects/{}/locations/{}/publishers/google/models/",
                region, project, region
            );
            UrlTemplate::PrefixModelSuffix {
                prefix: Arc::from(prefix),
                suffix: Arc::from(":generateContent"),
            }
        }

        ProviderType::AwsBedrock => {
            let region = aws_region.unwrap_or("us-east-1");
            let prefix = format!("https://bedrock-runtime.{}.amazonaws.com/model/", region);
            UrlTemplate::PrefixModelSuffix {
                prefix: Arc::from(prefix),
                suffix: Arc::from("/converse"),
            }
        }

        pt => UrlTemplate::Static(Arc::from(pt.default_base_url())),
    };
    Ok(template)
}

fn validate_dns_label(field: &str, value: &str, min: usize, max: usize) -> Result<(), String> {
    let valid_length = value.len() >= min && value.len() <= max;
    let valid_edges = value
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric());
    if !valid_length
        || !valid_edges
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(format!(
            "ai_federation: '{field}' must be an ASCII DNS label between {min} and {max} characters"
        ));
    }
    Ok(())
}

fn validate_url_path_component(field: &str, value: &str, max: usize) -> Result<(), String> {
    if value.is_empty()
        || value.len() > max
        || value.contains("..")
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || byte == b'.'
                || byte == b'_'
                || byte == b'-'
                || byte == b':'
        })
    {
        return Err(format!(
            "ai_federation: '{field}' contains characters that are unsafe in a provider endpoint component"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Main plugin struct
// ---------------------------------------------------------------------------

pub struct AiFederation {
    providers: Vec<ResolvedProvider>,
    fallback_enabled: bool,
    fallback_status_codes: HashSet<u16>,
    fallback_on_network_errors: bool,
    fallback_on_protocol_errors: bool,
    fallback_on_ambiguous_errors: bool,
    fail_on_missing_model: bool,
    fail_on_no_matching_provider: bool,
    request_slots: Semaphore,
    http_client: PluginHttpClient,
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

impl AiFederation {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let config_object = config
            .as_object()
            .ok_or_else(|| "ai_federation: config must be an object".to_string())?;
        reject_unsupported_streaming_config(config, "config")?;
        reject_unknown_config_keys(config_object, "config", AI_FEDERATION_CONFIG_KEYS)?;

        let providers_val = config
            .get("providers")
            .and_then(|v| v.as_array())
            .ok_or("ai_federation: 'providers' must be a non-empty array")?;

        if providers_val.is_empty() {
            return Err("ai_federation: 'providers' array must not be empty".to_string());
        }
        if providers_val.len() > MAX_PROVIDERS {
            return Err(format!(
                "ai_federation: 'providers' supports at most {MAX_PROVIDERS} entries"
            ));
        }

        let mut providers = Vec::with_capacity(providers_val.len());
        let mut provider_names = HashSet::with_capacity(providers_val.len());

        // Use the already-resolved gateway IP allowlist policy so provider
        // validation honors CLI/env/conf/default precedence.
        let backend_allow_ips = http_client.backend_allow_ips().clone();

        for (i, pv) in providers_val.iter().enumerate() {
            let provider_object = pv
                .as_object()
                .ok_or_else(|| format!("ai_federation: provider[{i}] must be an object"))?;
            reject_unsupported_streaming_config(pv, &format!("provider[{i}]"))?;
            reject_unknown_config_keys(
                provider_object,
                &format!("provider[{i}]"),
                AI_FEDERATION_PROVIDER_KEYS,
            )?;

            let name = optional_str(pv, "name")?
                .ok_or(format!("ai_federation: provider[{i}] missing 'name'"))?
                .to_string();

            if name.is_empty()
                || name.len() > 128
                || !name.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'_' || byte == b'-'
                })
            {
                return Err(format!(
                    "ai_federation: provider[{i}] 'name' must contain 1 to 128 ASCII alphanumeric, dot, underscore, or hyphen characters"
                ));
            }
            if !provider_names.insert(name.clone()) {
                return Err(format!(
                    "ai_federation: provider name '{name}' is duplicated"
                ));
            }

            validate_provider_field_types(pv)?;

            let provider_type_str = optional_str(pv, "provider_type")?.ok_or(format!(
                "ai_federation: provider '{name}' missing 'provider_type'"
            ))?;
            let provider_type = ProviderType::from_str(provider_type_str)?;

            let priority_u64 = optional_u64(pv, "priority")?.unwrap_or((i as u64) + 1);
            let priority = u32::try_from(priority_u64)
                .map_err(|_| format!("ai_federation: provider '{name}' priority is too large"))?;

            let model_patterns = optional_string_vec(pv, "model_patterns")?.unwrap_or_default();
            if model_patterns.len() > MAX_MODEL_PATTERNS_PER_PROVIDER
                || model_patterns
                    .iter()
                    .any(|pattern| !is_valid_model_pattern(pattern))
            {
                return Err(format!(
                    "ai_federation: provider '{name}' model_patterns must contain at most {MAX_MODEL_PATTERNS_PER_PROVIDER} bounded model globs"
                ));
            }

            let model_mapping = optional_string_map(pv, "model_mapping")?.unwrap_or_default();
            if model_mapping.len() > MAX_MODEL_MAPPINGS_PER_PROVIDER
                || model_mapping
                    .keys()
                    .any(|model| !is_valid_model_identifier(model))
            {
                return Err(format!(
                    "ai_federation: provider '{name}' model_mapping must contain at most {MAX_MODEL_MAPPINGS_PER_PROVIDER} valid client model identifiers"
                ));
            }

            let default_model = optional_str(pv, "default_model")?.map(String::from);
            if default_model
                .as_deref()
                .is_some_and(|model| !is_valid_model_identifier(model))
                || model_mapping
                    .values()
                    .any(|model| !is_valid_model_identifier(model))
            {
                return Err(format!(
                    "ai_federation: provider '{name}' has an invalid provider-native model identifier"
                ));
            }
            if provider_embeds_model_in_url(provider_type)
                && (default_model
                    .as_deref()
                    .is_some_and(|model| !is_valid_url_model_component(model))
                    || model_mapping
                        .values()
                        .any(|model| !is_valid_url_model_component(model)))
            {
                return Err(format!(
                    "ai_federation: provider '{name}' has a model identifier that is unsafe in its endpoint path"
                ));
            }
            let multimodal_mode = match optional_str(pv, "multimodal_mode")? {
                Some(mode) => MultimodalMode::from_str(mode, &name)?,
                None => MultimodalMode::default_for_provider(provider_type),
            };

            let connect_timeout_seconds = optional_u64(pv, "connect_timeout_seconds")?.unwrap_or(5);
            let read_timeout_seconds = optional_u64(pv, "read_timeout_seconds")?.unwrap_or(60);
            if connect_timeout_seconds == 0 || read_timeout_seconds == 0 {
                return Err(format!(
                    "ai_federation: provider '{name}' timeout values must be greater than zero"
                ));
            }
            let connect_timeout = Duration::from_secs(connect_timeout_seconds);
            let read_timeout = Duration::from_secs(read_timeout_seconds);
            let max_response_body_bytes = parse_provider_response_limit(pv, &name)?;
            let circuit = parse_provider_circuit(pv, &name)?.map(ProviderCircuit::new);

            let base_url = optional_str(pv, "base_url")?.map(String::from);
            let allow_plaintext = optional_bool(pv, "allow_plaintext")?.unwrap_or(false);

            // SSRF guard: validate operator-supplied base_url before storing
            // it. Provider `default_base_url` literals are static `https://`
            // strings and are inherently safe (covered by inspection — see
            // `ProviderType::default_base_url`); only the operator override
            // needs runtime validation.
            if let Some(ref url) = base_url {
                validate_base_url(&name, url, allow_plaintext, &backend_allow_ips)?;
            }

            let azure_resource = optional_str(pv, "azure_resource")?.map(String::from);
            let azure_deployment = optional_str(pv, "azure_deployment")?.map(String::from);
            let azure_api_version = optional_str(pv, "azure_api_version")?
                .unwrap_or("2024-06-01")
                .to_string();

            let google_project_id = optional_str(pv, "google_project_id")?.map(String::from);
            let google_region = optional_str(pv, "google_region")?.map(String::from);
            let aws_region = config_or_env_str(
                pv,
                "aws_region",
                Some(&["AWS_DEFAULT_REGION", "AWS_REGION"]),
            );

            // Validate provider-specific required fields
            validate_provider_config(provider_type, &name, pv)?;

            // Pre-compute the URL template once so per-request URL building
            // is a single allocation (concat of pre-built Arc<str> parts)
            // rather than a multi-arg `format!()` call per request.
            let url_template = build_url_template(
                provider_type,
                base_url.as_deref(),
                azure_resource.as_deref(),
                azure_deployment.as_deref(),
                &azure_api_version,
                google_region.as_deref(),
                google_project_id.as_deref(),
                aws_region.as_deref(),
            )?;
            // Validate endpoint material before parsing or retaining
            // credentials. Unsafe authorities therefore fail deterministically
            // even when the same provider also has malformed auth material.
            let auth = build_auth(provider_type, pv, &name)?;

            providers.push(ResolvedProvider {
                name,
                provider_type,
                auth,
                priority,
                model_patterns,
                model_mapping,
                default_model,
                multimodal_mode,
                connect_timeout,
                read_timeout,
                max_response_body_bytes,
                circuit,
                base_url,
                url_template,
            });
        }

        // Sort by priority (ascending — lower = tried first)
        providers.sort_by_key(|p| p.priority);

        let fallback_enabled = optional_bool(config, "fallback_enabled")?.unwrap_or(true);

        let fallback_status_codes = optional_status_code_set(config, "fallback_on_status_codes")?
            .unwrap_or_else(|| [429, 500, 502, 503].into_iter().collect());

        let fallback_on_network_errors =
            optional_bool(config, "fallback_on_network_errors")?.unwrap_or(true);
        let fallback_on_protocol_errors =
            optional_bool(config, "fallback_on_protocol_errors")?.unwrap_or(true);
        let fallback_on_ambiguous_errors =
            optional_bool(config, "fallback_on_ambiguous_errors")?.unwrap_or(false);

        let fail_on_missing_model = optional_bool(config, "fail_on_missing_model")?.unwrap_or(true);
        let fail_on_no_matching_provider =
            optional_bool(config, "fail_on_no_matching_provider")?.unwrap_or(true);
        let max_concurrent_requests = usize::try_from(
            optional_u64(config, "max_concurrent_requests")?
                .unwrap_or(DEFAULT_MAX_CONCURRENT_REQUESTS as u64),
        )
        .map_err(|_| "ai_federation: 'max_concurrent_requests' is too large".to_string())?;
        if max_concurrent_requests == 0 || max_concurrent_requests > MAX_CONCURRENT_REQUESTS {
            return Err(format!(
                "ai_federation: 'max_concurrent_requests' must be between 1 and {MAX_CONCURRENT_REQUESTS}"
            ));
        }

        Ok(Self {
            providers,
            fallback_enabled,
            fallback_status_codes,
            fallback_on_network_errors,
            fallback_on_protocol_errors,
            fallback_on_ambiguous_errors,
            fail_on_missing_model,
            fail_on_no_matching_provider,
            request_slots: Semaphore::new(max_concurrent_requests),
            http_client,
        })
    }
}

const AI_FEDERATION_CONFIG_KEYS: &[&str] = &[
    "providers",
    "fallback_enabled",
    "fallback_on_status_codes",
    "fallback_on_network_errors",
    "fallback_on_protocol_errors",
    "fallback_on_ambiguous_errors",
    "fail_on_missing_model",
    "fail_on_no_matching_provider",
    "max_concurrent_requests",
];

const AI_FEDERATION_PROVIDER_KEYS: &[&str] = &[
    "name",
    "provider_type",
    "api_key",
    "priority",
    "model_patterns",
    "model_mapping",
    "default_model",
    "multimodal_mode",
    "connect_timeout_seconds",
    "read_timeout_seconds",
    "max_response_body_bytes",
    "base_url",
    "allow_plaintext",
    "azure_resource",
    "azure_deployment",
    "azure_api_version",
    "google_project_id",
    "google_region",
    "google_service_account_json",
    "aws_region",
    "aws_access_key_id",
    "aws_secret_access_key",
    "aws_session_token",
    "circuit_breaker",
];

const PROVIDER_CIRCUIT_KEYS: &[&str] =
    &["failure_threshold", "cooldown_seconds", "success_threshold"];

fn reject_unknown_config_keys(
    object: &serde_json::Map<String, Value>,
    scope: &str,
    allowed: &[&str],
) -> Result<(), String> {
    let mut unknown = object
        .keys()
        .filter(|key| !allowed.contains(&key.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if unknown.is_empty() {
        return Ok(());
    }
    unknown.sort();
    Err(format!(
        "ai_federation: {scope} contains unknown field(s): {}; allowed fields: {}",
        unknown.join(", "),
        allowed.join(", ")
    ))
}

fn validate_provider_field_types(provider: &Value) -> Result<(), String> {
    for field in [
        "api_key",
        "base_url",
        "azure_resource",
        "azure_deployment",
        "azure_api_version",
        "google_project_id",
        "google_region",
        "google_service_account_json",
        "aws_region",
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_session_token",
    ] {
        optional_str(provider, field)?;
    }
    optional_bool(provider, "allow_plaintext")?;
    Ok(())
}

fn parse_provider_response_limit(provider: &Value, name: &str) -> Result<usize, String> {
    let limit = usize::try_from(
        optional_u64(provider, "max_response_body_bytes")?
            .unwrap_or(DEFAULT_MAX_PROVIDER_RESPONSE_BYTES as u64),
    )
    .map_err(|_| {
        format!("ai_federation: provider '{name}' max_response_body_bytes is too large")
    })?;
    if limit == 0 || limit > MAX_PROVIDER_RESPONSE_BYTES {
        return Err(format!(
            "ai_federation: provider '{name}' max_response_body_bytes must be between 1 and {MAX_PROVIDER_RESPONSE_BYTES}"
        ));
    }
    Ok(limit)
}

fn parse_provider_circuit(
    provider: &Value,
    name: &str,
) -> Result<Option<ProviderCircuitConfig>, String> {
    let Some(value) = provider.get("circuit_breaker") else {
        return Ok(None);
    };
    let object = value.as_object().ok_or_else(|| {
        format!("ai_federation: provider '{name}' circuit_breaker must be an object")
    })?;
    reject_unknown_config_keys(
        object,
        &format!("provider '{name}' circuit_breaker"),
        PROVIDER_CIRCUIT_KEYS,
    )?;

    let failure_threshold = u32::try_from(optional_u64(value, "failure_threshold")?.unwrap_or(3))
        .map_err(|_| {
        format!("ai_federation: provider '{name}' circuit failure_threshold is too large")
    })?;
    let cooldown_seconds = optional_u64(value, "cooldown_seconds")?.unwrap_or(30);
    let success_threshold = u32::try_from(optional_u64(value, "success_threshold")?.unwrap_or(1))
        .map_err(|_| {
        format!("ai_federation: provider '{name}' circuit success_threshold is too large")
    })?;

    if failure_threshold == 0 || failure_threshold > 100 {
        return Err(format!(
            "ai_federation: provider '{name}' circuit failure_threshold must be between 1 and 100"
        ));
    }
    if cooldown_seconds == 0 || cooldown_seconds > 86_400 {
        return Err(format!(
            "ai_federation: provider '{name}' circuit cooldown_seconds must be between 1 and 86400"
        ));
    }
    if success_threshold == 0 || success_threshold > 100 {
        return Err(format!(
            "ai_federation: provider '{name}' circuit success_threshold must be between 1 and 100"
        ));
    }

    Ok(Some(ProviderCircuitConfig {
        failure_threshold,
        cooldown: Duration::from_secs(cooldown_seconds),
        success_threshold,
    }))
}

fn reject_unsupported_streaming_config(config: &Value, scope: &str) -> Result<(), String> {
    const UNSUPPORTED_STREAMING_FIELDS: &[&str] = &[
        "stream",
        "streaming",
        "streaming_enabled",
        "enable_streaming",
    ];

    for field in UNSUPPORTED_STREAMING_FIELDS {
        if config.get(*field).is_some() {
            return Err(format!(
                "ai_federation: {scope} field '{field}' is unsupported; ai_federation does not implement provider response streaming and rejects matched OpenAI Chat Completions requests with \"stream\": true"
            ));
        }
    }

    Ok(())
}

fn optional_u64(config: &Value, field: &'static str) -> Result<Option<u64>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_u64()
        .map(Some)
        .ok_or_else(|| format!("ai_federation: '{field}' must be an unsigned integer"))
}

fn optional_bool(config: &Value, field: &'static str) -> Result<Option<bool>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| format!("ai_federation: '{field}' must be a boolean"))
}

fn optional_str<'a>(config: &'a Value, field: &'static str) -> Result<Option<&'a str>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_str()
        .map(Some)
        .ok_or_else(|| format!("ai_federation: '{field}' must be a string"))
}

fn optional_string_vec(config: &Value, field: &'static str) -> Result<Option<Vec<String>>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(values) = value.as_array() else {
        return Err(format!("ai_federation: '{field}' must be an array"));
    };
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let Some(value) = value.as_str() else {
            return Err(format!(
                "ai_federation: '{field}' must contain only strings"
            ));
        };
        out.push(value.to_string());
    }
    Ok(Some(out))
}

fn optional_string_map(
    config: &Value,
    field: &'static str,
) -> Result<Option<HashMap<String, String>>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(values) = value.as_object() else {
        return Err(format!("ai_federation: '{field}' must be an object"));
    };
    let mut out = HashMap::with_capacity(values.len());
    for (key, value) in values {
        let Some(value) = value.as_str() else {
            return Err(format!("ai_federation: '{field}' values must be strings"));
        };
        out.insert(key.clone(), value.to_string());
    }
    Ok(Some(out))
}

fn optional_status_code_set(
    config: &Value,
    field: &'static str,
) -> Result<Option<HashSet<u16>>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(values) = value.as_array() else {
        return Err(format!("ai_federation: '{field}' must be an array"));
    };
    let mut out = HashSet::with_capacity(values.len());
    for value in values {
        let Some(value) = value.as_u64() else {
            return Err(format!(
                "ai_federation: '{field}' must contain integer status codes"
            ));
        };
        let status = u16::try_from(value)
            .map_err(|_| format!("ai_federation: '{field}' status code {value} is too large"))?;
        if !(100..=599).contains(&status) {
            return Err(format!(
                "ai_federation: '{field}' contains invalid HTTP status code {status}"
            ));
        }
        out.insert(status);
    }
    Ok(Some(out))
}

/// Build the authentication method for a provider.
fn build_auth(
    provider_type: ProviderType,
    config: &Value,
    name: &str,
) -> Result<AuthMethod, String> {
    match provider_type {
        // Bearer token providers
        ProviderType::OpenAi
        | ProviderType::Mistral
        | ProviderType::Xai
        | ProviderType::DeepSeek
        | ProviderType::MetaLlama
        | ProviderType::HuggingFace
        | ProviderType::Cohere => {
            let api_key = config_or_env_str(config, "api_key", None).ok_or(format!(
                "ai_federation: provider '{name}' missing 'api_key'"
            ))?;
            Ok(AuthMethod::BearerToken { api_key })
        }

        ProviderType::Anthropic => {
            let api_key = config_or_env_str(config, "api_key", None).ok_or(format!(
                "ai_federation: provider '{name}' missing 'api_key'"
            ))?;
            Ok(AuthMethod::CustomHeader {
                header_name: "x-api-key".to_string(),
                api_key,
            })
        }

        ProviderType::AzureOpenAi => {
            let api_key = config_or_env_str(config, "api_key", None).ok_or(format!(
                "ai_federation: provider '{name}' missing 'api_key'"
            ))?;
            Ok(AuthMethod::CustomHeader {
                header_name: "api-key".to_string(),
                api_key,
            })
        }

        ProviderType::GoogleGemini => {
            let api_key = config_or_env_str(config, "api_key", None).ok_or(format!(
                "ai_federation: provider '{name}' missing 'api_key'"
            ))?;
            Ok(AuthMethod::CustomHeader {
                header_name: "x-goog-api-key".to_string(),
                api_key,
            })
        }

        ProviderType::GoogleVertex => {
            let sa_json = config_or_env_str(config, "google_service_account_json", None).ok_or(
                format!("ai_federation: provider '{name}' missing 'google_service_account_json'"),
            )?;
            Ok(AuthMethod::GoogleOAuth2 {
                cache: Arc::new(OAuth2Cache::new(sa_json).map_err(|error| {
                    format!("ai_federation: provider '{name}' OAuth configuration failed: {error}")
                })?),
            })
        }

        ProviderType::AwsBedrock => {
            let region = config_or_env_str(
                config,
                "aws_region",
                Some(&["AWS_DEFAULT_REGION", "AWS_REGION"]),
            )
            .ok_or(format!(
                "ai_federation: provider '{name}' missing 'aws_region'"
            ))?;
            let access_key_id =
                config_or_env_str(config, "aws_access_key_id", Some(&["AWS_ACCESS_KEY_ID"]))
                    .ok_or(format!(
                        "ai_federation: provider '{name}' missing 'aws_access_key_id'"
                    ))?;
            let secret_access_key = config_or_env_str(
                config,
                "aws_secret_access_key",
                Some(&["AWS_SECRET_ACCESS_KEY"]),
            )
            .ok_or(format!(
                "ai_federation: provider '{name}' missing 'aws_secret_access_key'"
            ))?;
            let session_token =
                config_or_env_str(config, "aws_session_token", Some(&["AWS_SESSION_TOKEN"]));

            Ok(AuthMethod::AwsSigV4 {
                config: aws_sigv4::AwsSigV4Config {
                    region,
                    access_key_id,
                    secret_access_key,
                    session_token,
                },
            })
        }
    }
}

/// Read a string value from config, falling back to environment variables.
fn config_or_env_str(config: &Value, field: &str, env_vars: Option<&[&str]>) -> Option<String> {
    if let Some(s) = config.get(field).and_then(|v| v.as_str())
        && !s.is_empty()
    {
        return Some(s.to_string());
    }
    if let Some(vars) = env_vars {
        for var in vars {
            if let Ok(val) = std::env::var(var)
                && !val.is_empty()
            {
                return Some(val);
            }
        }
    }
    None
}

/// Validate provider-specific required config fields.
fn validate_provider_config(
    provider_type: ProviderType,
    name: &str,
    config: &Value,
) -> Result<(), String> {
    match provider_type {
        ProviderType::AzureOpenAi => {
            if config["azure_resource"].as_str().is_none() {
                return Err(format!(
                    "ai_federation: provider '{name}' (azure_openai) missing 'azure_resource'"
                ));
            }
            if config["azure_deployment"].as_str().is_none() {
                return Err(format!(
                    "ai_federation: provider '{name}' (azure_openai) missing 'azure_deployment'"
                ));
            }
        }
        ProviderType::GoogleVertex => {
            if config["google_project_id"].as_str().is_none() {
                return Err(format!(
                    "ai_federation: provider '{name}' (google_vertex) missing 'google_project_id'"
                ));
            }
            if config["google_region"].as_str().is_none() {
                return Err(format!(
                    "ai_federation: provider '{name}' (google_vertex) missing 'google_region'"
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Model routing
// ---------------------------------------------------------------------------

/// Characters a `*` wildcard in a `model_patterns` glob is NOT allowed to
/// consume.
///
/// This is the security tightening for `simple_glob_match`. Without this,
/// an operator pattern like `gemini-*` would match a malicious user input
/// such as `gemini-../foo:streamGenerateContent?key=stolen` and let
/// `find_providers_for_model` route the request to a Gemini provider that
/// then concatenates the user-controlled string into the URL path. The
/// charset below covers every URL-structural separator (path traversal,
/// query/fragment introducers, alternate path separators) plus
/// whitespace and control-style characters that have no business in a
/// model identifier. Compare with fnmatch(3) where `*` does not cross `/`.
const GLOB_WILDCARD_FORBIDDEN_CHARS: &[char] = &['/', '?', '#', '&', '\\', ' ', '\t', '\n', '\r'];

/// Simple glob match supporting only `*` as a wildcard.
///
/// `*` matches any sequence of characters EXCEPT those listed in
/// [`GLOB_WILDCARD_FORBIDDEN_CHARS`]. The pattern is implicitly anchored to
/// the start and end of the input — there is no "starts-with" mode. The
/// literal segments between `*` markers must appear in order without
/// overlapping the forbidden character set inside any `*` window.
fn simple_glob_match(pattern: &str, input: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        // No wildcard — exact match
        return pattern == input;
    }

    let mut pos = 0;

    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if let Some(found) = input[pos..].find(part) {
            // First segment must be at the start if pattern doesn't start with *
            if i == 0 && found != 0 {
                return false;
            }
            // The substring `*` consumed (between the previous match end
            // and the next literal) must not contain any URL-structural
            // separator. Without this, `gemini-*` would match
            // `gemini-../foo:streamGenerateContent` and let the dispatcher
            // route a path-traversing model to a real Gemini provider.
            let gap = &input[pos..pos + found];
            if gap.contains(GLOB_WILDCARD_FORBIDDEN_CHARS) {
                return false;
            }
            pos += found + part.len();
        } else {
            return false;
        }
    }

    // If the pattern doesn't end with *, input must be consumed
    if !pattern.ends_with('*') && pos != input.len() {
        return false;
    }

    // Trailing `*` window — the remainder must also not contain URL separators.
    if pattern.ends_with('*') && input[pos..].contains(GLOB_WILDCARD_FORBIDDEN_CHARS) {
        return false;
    }

    true
}

/// Validate that a resolved model name is safe to substitute into a URL
/// path component.
///
/// Three providers (Google Gemini, Google Vertex AI, AWS Bedrock) embed
/// the resolved model directly in the URL path (`prefix + model +
/// suffix`). Without validation, a user-supplied `model` field can steer
/// the request to a different provider API path on the operator's API
/// key — e.g. `gemini-../streamGenerateContent?key=stolen` collapses to
/// a different endpoint after URL normalization.
///
/// Allowed charset: `[A-Za-z0-9._:-]`. The colon is required for AWS
/// Bedrock model identifiers like
/// `anthropic.claude-3-5-sonnet-20240620-v1:0`. The dot is required for
/// every provider's versioning scheme. The hyphen and underscore cover
/// the rest of the legitimate model-name space across all three.
///
/// Additionally, `..` is rejected outright — even though both `.`
/// characters are in the allowed set individually, the sequence is the
/// canonical path-traversal token after URL normalization.
fn is_valid_url_model_component(model: &str) -> bool {
    if model.is_empty() {
        return false;
    }
    if model.contains("..") {
        return false;
    }
    model
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-' || b == b':')
}

fn is_valid_model_identifier(model: &str) -> bool {
    !model.is_empty()
        && model.len() <= MAX_MODEL_IDENTIFIER_BYTES
        && !model.contains("..")
        && model.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/' | b'+')
        })
}

fn is_valid_model_pattern(pattern: &str) -> bool {
    !pattern.is_empty()
        && pattern.len() <= MAX_MODEL_IDENTIFIER_BYTES
        && !pattern.contains("..")
        && pattern.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/' | b'+' | b'*')
        })
}

/// Whether a provider embeds the resolved model directly in the URL path.
///
/// Only these providers are vulnerable to URL injection via the `model`
/// field — for OpenAI-compatible / Anthropic / Cohere providers the
/// model goes into the request body, not the URL.
fn provider_embeds_model_in_url(provider_type: ProviderType) -> bool {
    matches!(
        provider_type,
        ProviderType::GoogleGemini | ProviderType::GoogleVertex | ProviderType::AwsBedrock
    )
}

impl AiFederation {
    /// Find all providers matching a model name, in priority order.
    fn find_providers_for_model(&self, model: &str) -> Vec<&ResolvedProvider> {
        self.providers
            .iter()
            .filter(|p| {
                if p.model_patterns.is_empty() {
                    // Empty patterns = catch-all
                    true
                } else {
                    p.model_patterns
                        .iter()
                        .any(|pat| simple_glob_match(pat, model))
                }
            })
            .collect()
    }

    /// Resolve the actual model name to send to the provider.
    fn resolve_model(provider: &ResolvedProvider, model: &str) -> String {
        if let Some(mapped) = provider.model_mapping.get(model) {
            return mapped.clone();
        }
        if let Some(ref default) = provider.default_model {
            return default.clone();
        }
        model.to_string()
    }
}

// ---------------------------------------------------------------------------
// Request translation
// ---------------------------------------------------------------------------

/// Translation result: (url, extra_headers, body_bytes)
type TranslatedRequest = (String, Vec<(String, String)>, Vec<u8>);

/// Detect whether an OpenAI-format request asks for a streamed response.
///
/// This plugin uses the "terminate and respond" pattern: it makes a single
/// non-streaming HTTP call to the provider and buffers the whole body before
/// normalizing it with `serde_json::from_slice`. A streaming request cannot be
/// served by that pattern:
///   - OpenAI-compatible providers receive the `stream` flag verbatim
///     (`translate_openai_compatible` clones the body) and reply with an SSE
///     `text/event-stream`, which is not a single JSON document — normalization
///     fails and the client gets an opaque 502.
///   - Provider-specific paths either build non-streaming provider calls
///     (Anthropic/Gemini/Bedrock) or can still request provider streaming
///     without a relay/normalization path (Cohere).
///
/// Rather than break either way, the final-body hook rejects streaming requests it
/// would otherwise intercept with a clear, OpenAI-shaped error. We only treat
/// `stream: true` (a real boolean) as streaming. A missing field requests the
/// buffered path; any present non-boolean value is rejected by request-shape
/// validation before provider I/O.
fn request_wants_streaming(openai_body: &Value) -> bool {
    openai_body["stream"].as_bool() == Some(true)
}

fn validate_openai_request(
    openai_body: &Value,
    allow_dropped_non_text_parts: bool,
) -> Result<(), String> {
    let object = openai_body
        .as_object()
        .ok_or("ai_federation: request body must be a JSON object")?;
    if object
        .get("stream")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err("ai_federation: 'stream' must be a boolean when present".to_string());
    }
    let messages = object
        .get("messages")
        .and_then(Value::as_array)
        .ok_or("ai_federation: request missing 'messages' array")?;
    if messages.is_empty() {
        return Err("ai_federation: 'messages' array must not be empty".to_string());
    }

    let mut tool_call_ids = HashSet::new();
    for (index, message) in messages.iter().enumerate() {
        let message_object = message
            .as_object()
            .ok_or_else(|| format!("ai_federation: messages[{index}] must be an object"))?;
        let role = message_object
            .get("role")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("ai_federation: messages[{index}] missing string role"))?;
        if !matches!(role, "system" | "developer" | "user" | "assistant" | "tool") {
            let role = bounded_error_value(role);
            return Err(format!(
                "ai_federation: messages[{index}] has unsupported role '{role}'"
            ));
        }

        let has_tool_calls = message_object.get("tool_calls").is_some();
        match message_object.get("content") {
            Some(Value::String(_)) => {}
            Some(content @ Value::Array(_)) => {
                validate_openai_content_parts(content, index, allow_dropped_non_text_parts)?;
            }
            Some(Value::Null) | None if role == "assistant" && has_tool_calls => {}
            _ => {
                return Err(format!(
                    "ai_federation: messages[{index}] content must be a string or content-parts array"
                ));
            }
        }

        if role == "assistant" {
            for call in parse_openai_tool_calls(message, index)? {
                if !tool_call_ids.insert(call.id) {
                    return Err(format!(
                        "ai_federation: messages[{index}] repeats a tool-call id"
                    ));
                }
            }
        } else if has_tool_calls {
            return Err(format!(
                "ai_federation: messages[{index}] tool_calls are only valid on assistant messages"
            ));
        }

        if role == "tool" {
            let tool_call_id = message_object
                .get("tool_call_id")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    format!("ai_federation: messages[{index}] tool message missing tool_call_id")
                })?;
            if !tool_call_ids.contains(tool_call_id) {
                return Err(format!(
                    "ai_federation: messages[{index}] tool_call_id has no preceding assistant tool call"
                ));
            }
            tool_result_text(message_object.get("content").unwrap_or(&Value::Null))?;
        }
    }

    parse_openai_tools(openai_body)?;
    validate_openai_tool_choice(openai_body)?;
    normalized_stop_sequences(openai_body)?;
    Ok(())
}

fn validate_openai_content_parts(
    content: &Value,
    message_index: usize,
    allow_dropped_non_text_parts: bool,
) -> Result<(), String> {
    let parts = content.as_array().ok_or_else(|| {
        format!("ai_federation: messages[{message_index}] content must be an array")
    })?;
    if parts.is_empty() {
        return Err(format!(
            "ai_federation: messages[{message_index}] content-parts array must not be empty"
        ));
    }
    for (part_index, part) in parts.iter().enumerate() {
        let part = part.as_object().ok_or_else(|| {
            format!(
                "ai_federation: messages[{message_index}].content[{part_index}] must be an object"
            )
        })?;
        let part_type = part
            .get("type")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                format!(
                    "ai_federation: messages[{message_index}].content[{part_index}] missing non-empty type"
                )
            })?;
        if allow_dropped_non_text_parts && part_type != "text" {
            continue;
        }
        match part_type {
            "text" => {
                if part.get("text").and_then(Value::as_str).is_none() {
                    return Err(format!(
                        "ai_federation: messages[{message_index}].content[{part_index}] text part missing string text"
                    ));
                }
            }
            "image_url" => {
                if part
                    .get("image_url")
                    .and_then(Value::as_object)
                    .and_then(|image| image.get("url"))
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .is_none()
                {
                    return Err(format!(
                        "ai_federation: messages[{message_index}].content[{part_index}] image_url part missing non-empty image_url.url"
                    ));
                }
            }
            "input_audio" => {
                let audio = part.get("input_audio").and_then(Value::as_object);
                let has_data = audio
                    .and_then(|audio| audio.get("data"))
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.is_empty());
                let has_format = audio
                    .and_then(|audio| audio.get("format"))
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.is_empty());
                if !has_data || !has_format {
                    return Err(format!(
                        "ai_federation: messages[{message_index}].content[{part_index}] input_audio part requires non-empty input_audio.data and input_audio.format"
                    ));
                }
            }
            _ => {
                return Err(format!(
                    "ai_federation: messages[{message_index}].content[{part_index}] has an unsupported content-part type"
                ));
            }
        }
    }
    Ok(())
}

#[derive(Clone)]
struct ParsedToolCall {
    id: String,
    name: String,
    arguments: Value,
}

struct ProviderToolCall<'a> {
    id: &'a str,
    name: &'a str,
    arguments: &'a str,
}

fn parse_openai_tool_calls(
    message: &Value,
    message_index: usize,
) -> Result<Vec<ParsedToolCall>, String> {
    let Some(tool_calls_value) = message.get("tool_calls") else {
        return Ok(Vec::new());
    };
    let tool_calls = tool_calls_value.as_array().ok_or_else(|| {
        format!("ai_federation: messages[{message_index}].tool_calls must be an array")
    })?;
    if tool_calls.is_empty() {
        return Err(format!(
            "ai_federation: messages[{message_index}].tool_calls must not be empty"
        ));
    }

    let mut parsed = Vec::with_capacity(tool_calls.len());
    for (tool_index, call) in tool_calls.iter().enumerate() {
        let call_object = call.as_object().ok_or_else(|| {
            format!(
                "ai_federation: messages[{message_index}].tool_calls[{tool_index}] must be an object"
            )
        })?;
        if call_object.get("type").and_then(Value::as_str) != Some("function") {
            return Err(format!(
                "ai_federation: messages[{message_index}].tool_calls[{tool_index}] must have type 'function'"
            ));
        }
        let id = call_object
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                format!(
                    "ai_federation: messages[{message_index}].tool_calls[{tool_index}] missing id"
                )
            })?;
        let function = call_object
            .get("function")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                format!(
                    "ai_federation: messages[{message_index}].tool_calls[{tool_index}] missing function"
                )
            })?;
        let name = function
            .get("name")
            .and_then(Value::as_str)
            .filter(|value| valid_tool_name(value))
            .ok_or_else(|| {
                format!(
                    "ai_federation: messages[{message_index}].tool_calls[{tool_index}] has invalid function name"
                )
            })?;
        let arguments = function
            .get("arguments")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!(
                    "ai_federation: messages[{message_index}].tool_calls[{tool_index}] arguments must be a JSON string"
                )
            })?;
        let arguments: Value = serde_json::from_str(arguments).map_err(|error| {
            format!(
                "ai_federation: messages[{message_index}].tool_calls[{tool_index}] arguments are not valid JSON: {error}"
            )
        })?;
        if !arguments.is_object() {
            return Err(format!(
                "ai_federation: messages[{message_index}].tool_calls[{tool_index}] arguments must encode a JSON object"
            ));
        }
        parsed.push(ParsedToolCall {
            id: id.to_string(),
            name: name.to_string(),
            arguments,
        });
    }
    Ok(parsed)
}

fn parse_provider_tool_calls<'a>(
    message: &'a serde_json::Map<String, Value>,
    choice_index: usize,
    provider: &str,
) -> Result<Vec<ProviderToolCall<'a>>, String> {
    let Some(tool_calls_value) = message.get("tool_calls") else {
        return Ok(Vec::new());
    };
    let tool_calls = tool_calls_value.as_array().ok_or_else(|| {
        format!(
            "ai_federation: {provider} choices[{choice_index}].message.tool_calls must be an array"
        )
    })?;
    if tool_calls.is_empty() {
        return Err(format!(
            "ai_federation: {provider} choices[{choice_index}].message.tool_calls must not be empty"
        ));
    }

    let mut parsed = Vec::with_capacity(tool_calls.len());
    for (tool_index, call) in tool_calls.iter().enumerate() {
        let scope = format!("{provider} choices[{choice_index}].message.tool_calls[{tool_index}]");
        let call = call
            .as_object()
            .ok_or_else(|| format!("ai_federation: {scope} must be an object"))?;
        if call.get("type").and_then(Value::as_str) != Some("function") {
            return Err(format!("ai_federation: {scope} must have type 'function'"));
        }
        let id = call
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 128)
            .ok_or_else(|| format!("ai_federation: {scope} has an invalid id"))?;
        let function = call
            .get("function")
            .and_then(Value::as_object)
            .ok_or_else(|| format!("ai_federation: {scope} missing function object"))?;
        let name = function
            .get("name")
            .and_then(Value::as_str)
            .filter(|value| valid_tool_name(value))
            .ok_or_else(|| format!("ai_federation: {scope} has an invalid function name"))?;
        let arguments = function
            .get("arguments")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("ai_federation: {scope} arguments must be a string"))?;
        parsed.push(ProviderToolCall {
            id,
            name,
            // Provider output is generated text, not trusted request input.
            // Preserve even partial or invalid JSON for the caller to validate.
            arguments,
        });
    }
    Ok(parsed)
}

fn valid_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn parse_openai_tools(openai_body: &Value) -> Result<Option<Vec<Value>>, String> {
    let Some(value) = openai_body.get("tools") else {
        return Ok(None);
    };
    let tools = value
        .as_array()
        .ok_or("ai_federation: 'tools' must be an array")?;
    if tools.is_empty() {
        return Err("ai_federation: 'tools' must not be empty when present".to_string());
    }

    let mut parsed = Vec::with_capacity(tools.len());
    let mut names = HashSet::with_capacity(tools.len());
    for (index, tool) in tools.iter().enumerate() {
        let object = tool
            .as_object()
            .ok_or_else(|| format!("ai_federation: tools[{index}] must be an object"))?;
        if object.get("type").and_then(Value::as_str) != Some("function") {
            return Err(format!(
                "ai_federation: tools[{index}] must have type 'function'"
            ));
        }
        let function = object
            .get("function")
            .and_then(Value::as_object)
            .ok_or_else(|| format!("ai_federation: tools[{index}] missing function object"))?;
        let name = function
            .get("name")
            .and_then(Value::as_str)
            .filter(|value| valid_tool_name(value))
            .ok_or_else(|| format!("ai_federation: tools[{index}] has invalid function name"))?;
        if !names.insert(name) {
            return Err(format!(
                "ai_federation: tools[{index}] repeats function name '{name}'"
            ));
        }
        let description = match function.get("description") {
            None => None,
            Some(Value::String(value)) => Some(value.clone()),
            Some(_) => {
                return Err(format!(
                    "ai_federation: tools[{index}].function.description must be a string"
                ));
            }
        };
        let parameters = function
            .get("parameters")
            .cloned()
            .unwrap_or_else(|| json!({ "type": "object", "properties": {} }));
        if !parameters.is_object() {
            return Err(format!(
                "ai_federation: tools[{index}].function.parameters must be an object"
            ));
        }
        parsed.push(json!({
            "name": name,
            "description": description,
            "parameters": parameters,
        }));
    }
    Ok(Some(parsed))
}

fn validate_openai_tool_choice(openai_body: &Value) -> Result<(), String> {
    let Some(choice) = openai_body.get("tool_choice") else {
        return Ok(());
    };
    let named_choice = match choice {
        Value::String(value) if matches!(value.as_str(), "none" | "auto" | "required") => Ok(None),
        Value::Object(object) if object.get("type").and_then(Value::as_str) == Some("function") => {
            let name = object
                .get("function")
                .and_then(Value::as_object)
                .and_then(|function| function.get("name"))
                .and_then(Value::as_str)
                .filter(|name| valid_tool_name(name))
                .ok_or("ai_federation: named tool_choice has an invalid function name")?;
            Ok(Some(name))
        }
        _ => Err(
            "ai_federation: 'tool_choice' must be none, auto, required, or a named function"
                .to_string(),
        ),
    }?;

    let tools = parse_openai_tools(openai_body)?;
    if choice.as_str() != Some("none") && tools.is_none() {
        return Err("ai_federation: tool_choice requires a non-empty tools array".to_string());
    }
    if let Some(name) = named_choice
        && !tools
            .as_ref()
            .is_some_and(|tools| tools.iter().any(|tool| tool["name"].as_str() == Some(name)))
    {
        return Err(format!(
            "ai_federation: named tool_choice '{name}' does not match any declared tool"
        ));
    }
    Ok(())
}

fn tool_result_text(content: &Value) -> Result<String, String> {
    if let Some(text) = content.as_str() {
        return Ok(text.to_string());
    }
    let parts = content
        .as_array()
        .ok_or("ai_federation: tool message content must be a string or text-parts array")?;
    let mut text = String::new();
    for (index, part) in parts.iter().enumerate() {
        if part.get("type").and_then(Value::as_str) != Some("text") {
            return Err(format!(
                "ai_federation: tool message content[{index}] must be a text part"
            ));
        }
        text.push_str(
            part.get("text").and_then(Value::as_str).ok_or_else(|| {
                format!("ai_federation: tool message content[{index}] missing text")
            })?,
        );
    }
    Ok(text)
}

fn normalized_stop_sequences(openai_body: &Value) -> Result<Option<Value>, String> {
    let Some(stop) = openai_body.get("stop") else {
        return Ok(None);
    };
    if stop.is_null() {
        return Ok(None);
    }
    let values = match stop {
        Value::String(value) => vec![value.clone()],
        Value::Array(values) => {
            let mut strings = Vec::with_capacity(values.len());
            for value in values {
                strings.push(
                    value
                        .as_str()
                        .ok_or("ai_federation: 'stop' array must contain only strings")?
                        .to_string(),
                );
            }
            strings
        }
        _ => {
            return Err(
                "ai_federation: 'stop' must be a string, an array of strings, or null".to_string(),
            );
        }
    };
    if values.len() > MAX_STOP_SEQUENCES {
        return Err(format!(
            "ai_federation: 'stop' supports at most {MAX_STOP_SEQUENCES} sequences"
        ));
    }
    for value in &values {
        if value.is_empty() || value.chars().count() > MAX_STOP_SEQUENCE_CHARS {
            return Err(format!(
                "ai_federation: every stop sequence must contain 1 to {MAX_STOP_SEQUENCE_CHARS} characters"
            ));
        }
    }
    if values.is_empty() {
        Ok(None)
    } else {
        Ok(Some(Value::Array(
            values.into_iter().map(Value::String).collect(),
        )))
    }
}

fn tool_names_by_id(messages: &[Value]) -> Result<HashMap<String, String>, String> {
    let mut names = HashMap::new();
    for (message_index, message) in messages.iter().enumerate() {
        if message.get("role").and_then(Value::as_str) != Some("assistant") {
            continue;
        }
        for call in parse_openai_tool_calls(message, message_index)? {
            if names.insert(call.id, call.name).is_some() {
                return Err(format!(
                    "ai_federation: messages[{message_index}] repeats a tool-call id"
                ));
            }
        }
    }
    Ok(names)
}

/// Translate an OpenAI Chat Completions request to the provider's native format.
fn translate_request(
    provider: &ResolvedProvider,
    openai_body: &Value,
    resolved_model: &str,
) -> Result<TranslatedRequest, String> {
    match provider.provider_type {
        ProviderType::OpenAi
        | ProviderType::AzureOpenAi
        | ProviderType::Mistral
        | ProviderType::Xai
        | ProviderType::DeepSeek
        | ProviderType::MetaLlama
        | ProviderType::HuggingFace => {
            translate_openai_compatible(provider, openai_body, resolved_model)
        }
        ProviderType::Anthropic => translate_to_anthropic(provider, openai_body, resolved_model),
        ProviderType::GoogleGemini | ProviderType::GoogleVertex => {
            translate_to_gemini(provider, openai_body, resolved_model)
        }
        ProviderType::AwsBedrock => translate_to_bedrock(provider, openai_body, resolved_model),
        ProviderType::Cohere => translate_to_cohere(provider, openai_body, resolved_model),
    }
}

fn translate_openai_compatible(
    provider: &ResolvedProvider,
    openai_body: &Value,
    resolved_model: &str,
) -> Result<TranslatedRequest, String> {
    let mut body = if provider.multimodal_mode == MultimodalMode::TextOnlyWithWarning {
        text_only_openai_body(openai_body)
    } else {
        openai_body.clone()
    };
    canonicalize_openai_tool_arguments(&mut body)?;
    body["model"] = Value::String(resolved_model.to_string());

    // For Azure, strip the model field — the deployment is in the URL
    if provider.provider_type == ProviderType::AzureOpenAi
        && let Some(obj) = body.as_object_mut()
    {
        obj.remove("model");
    }

    let url = build_provider_url(provider, resolved_model);
    let headers = vec![("content-type".to_string(), "application/json".to_string())];
    let body_bytes = serialize_translated_request(&body, "OpenAI-compatible")?;

    Ok((url, headers, body_bytes))
}

/// Replace assistant tool-call argument strings with the JSON object Ferrum
/// actually validated. This prevents duplicate object keys (or other alternate
/// JSON spellings) from being interpreted one way by gateway policy and another
/// way by an OpenAI-compatible provider.
fn canonicalize_openai_tool_arguments(body: &mut Value) -> Result<(), String> {
    let messages = body
        .get_mut("messages")
        .and_then(Value::as_array_mut)
        .ok_or("ai_federation: request missing 'messages' array")?;

    for (message_index, message) in messages.iter_mut().enumerate() {
        if message.get("role").and_then(Value::as_str) != Some("assistant")
            || message.get("tool_calls").is_none()
        {
            continue;
        }

        let parsed_calls = parse_openai_tool_calls(message, message_index)?;
        let tool_calls = message
            .get_mut("tool_calls")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| {
                format!("ai_federation: messages[{message_index}].tool_calls must be an array")
            })?;
        for (tool_index, (tool_call, parsed)) in tool_calls.iter_mut().zip(parsed_calls).enumerate()
        {
            let function = tool_call
                .get_mut("function")
                .and_then(Value::as_object_mut)
                .ok_or_else(|| {
                    format!(
                        "ai_federation: messages[{message_index}].tool_calls[{tool_index}] missing function"
                    )
                })?;
            let arguments = serde_json::to_string(&parsed.arguments).map_err(|error| {
                format!(
                    "ai_federation: messages[{message_index}].tool_calls[{tool_index}] arguments could not be canonicalized: {error}"
                )
            })?;
            function.insert("arguments".to_string(), Value::String(arguments));
        }
    }

    Ok(())
}

/// OpenAI chat-completions messages accept `content` as either a plain
/// string OR an array of content parts (`[{"type":"text","text":"..."},
/// {"type":"image_url","image_url":{...}}, ...]`). This helper extracts
/// text parts only. Callers must run the explicit multimodal policy first:
/// it is used for instruction text and the opt-in `text_only_with_warning`
/// path, not as an implicit fallback.
fn flatten_openai_message_text(content: &Value) -> String {
    if let Some(s) = content.as_str() {
        return s.to_string();
    }
    if let Some(parts) = content.as_array() {
        let mut out = String::new();
        for part in parts {
            // OpenAI's spec: `{"type": "text", "text": "..."}`.
            if part.get("type").and_then(Value::as_str) == Some("text")
                && let Some(text) = part.get("text").and_then(Value::as_str)
                && !text.is_empty()
            {
                if !out.is_empty() {
                    out.push('\n');
                }
                out.push_str(text);
            }
        }
        return out;
    }
    String::new()
}

fn text_only_openai_body(openai_body: &Value) -> Value {
    let mut body = openai_body.clone();
    if let Some(messages) = body.get_mut("messages").and_then(Value::as_array_mut) {
        for message in messages {
            if let Some(obj) = message.as_object_mut()
                && obj.get("content").is_some()
            {
                let text = flatten_openai_message_text(&obj["content"]);
                obj.insert("content".to_string(), Value::String(text));
            }
        }
    }
    body
}

const MAX_MULTIMODAL_ERROR_VALUE_CHARS: usize = 64;
const MAX_MULTIMODAL_ERROR_VALUES: usize = 8;

#[derive(Debug, Clone)]
struct MultimodalUsage {
    non_text_parts: usize,
    types: BTreeSet<String>,
    roles: BTreeSet<String>,
}

impl MultimodalUsage {
    fn is_empty(&self) -> bool {
        self.non_text_parts == 0
    }

    fn types_csv(&self) -> String {
        bounded_values_csv(&self.types)
    }

    fn roles_csv(&self) -> String {
        bounded_values_csv(&self.roles)
    }
}

fn bounded_error_value(value: &str) -> String {
    let mut end = value.len();
    let mut chars = 0;
    for (idx, _) in value.char_indices() {
        if chars == MAX_MULTIMODAL_ERROR_VALUE_CHARS {
            end = idx;
            break;
        }
        chars += 1;
    }

    if chars <= MAX_MULTIMODAL_ERROR_VALUE_CHARS && end == value.len() {
        value.to_string()
    } else {
        format!(
            "{}…<truncated:{} chars>",
            &value[..end],
            value.chars().count()
        )
    }
}

fn bounded_values_csv(values: &BTreeSet<String>) -> String {
    let mut rendered = values
        .iter()
        .take(MAX_MULTIMODAL_ERROR_VALUES)
        .cloned()
        .collect::<Vec<_>>();
    let remaining = values.len().saturating_sub(MAX_MULTIMODAL_ERROR_VALUES);
    if remaining > 0 {
        rendered.push(format!("…<{} more>", remaining));
    }
    rendered.join(",")
}

fn analyze_multimodal_usage(openai_body: &Value) -> MultimodalUsage {
    let mut usage = MultimodalUsage {
        non_text_parts: 0,
        types: BTreeSet::new(),
        roles: BTreeSet::new(),
    };

    let Some(messages) = openai_body.get("messages").and_then(Value::as_array) else {
        return usage;
    };

    for message in messages {
        let role = message
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let Some(parts) = message.get("content").and_then(Value::as_array) else {
            continue;
        };

        for part in parts {
            if part.get("type").and_then(Value::as_str) == Some("text")
                && part.get("text").and_then(Value::as_str).is_some()
            {
                continue;
            }

            usage.non_text_parts += 1;
            usage.roles.insert(bounded_error_value(role));
            usage.types.insert(bounded_error_value(
                part.get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown"),
            ));
        }
    }

    usage
}

fn is_instruction_role(role: &str) -> bool {
    role == "system" || role == "developer"
}

fn multimodal_unsupported_message(
    provider: &ResolvedProvider,
    usage: &MultimodalUsage,
    reason: &str,
) -> String {
    format!(
        "Multimodal content cannot be sent to ai_federation provider '{}' ({}) with multimodal_mode='{}': {reason}; found {} non-text content part(s), types [{}], roles [{}]",
        provider.name,
        provider.provider_type.as_str(),
        provider.multimodal_mode.as_str(),
        usage.non_text_parts,
        usage.types_csv(),
        usage.roles_csv()
    )
}

fn validate_multimodal_policy(
    provider: &ResolvedProvider,
    openai_body: &Value,
    usage: &MultimodalUsage,
) -> Result<(), String> {
    if usage.is_empty() {
        return Ok(());
    }

    match provider.multimodal_mode {
        MultimodalMode::Reject => Err(multimodal_unsupported_message(
            provider,
            usage,
            "the provider is configured to reject non-text content",
        )),
        MultimodalMode::TextOnlyWithWarning => Ok(()),
        MultimodalMode::Translate => validate_multimodal_translate_support(provider, openai_body)
            .map_err(|reason| multimodal_unsupported_message(provider, usage, &reason)),
    }
}

fn validate_multimodal_translate_support(
    provider: &ResolvedProvider,
    openai_body: &Value,
) -> Result<(), String> {
    if provider.provider_type.is_openai_compatible()
        || provider.provider_type == ProviderType::Cohere
    {
        return Ok(());
    }

    let messages = openai_body["messages"]
        .as_array()
        .ok_or_else(|| "request missing 'messages' array".to_string())?;

    for message in messages {
        let role = message
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let Some(parts) = message.get("content").and_then(Value::as_array) else {
            continue;
        };

        for part in parts {
            if part.get("type").and_then(Value::as_str) == Some("text") {
                if part.get("text").and_then(Value::as_str).is_some() {
                    continue;
                }
                return Err("text content part missing text field".to_string());
            }

            let part_type = part
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            if is_instruction_role(role) {
                return Err(format!(
                    "non-text content part '{}' is not supported in {} messages for provider-native translation",
                    bounded_error_value(part_type),
                    bounded_error_value(role)
                ));
            }
            if role != "user" && role != "assistant" {
                return Err(format!(
                    "non-text content part '{}' is not supported for role '{}'",
                    bounded_error_value(part_type),
                    bounded_error_value(role)
                ));
            }
            if part_type != "image_url" {
                return Err(format!(
                    "non-text content part '{}' has no provider-native translation",
                    bounded_error_value(part_type)
                ));
            }

            // Bedrock only allows image (and document) content blocks on
            // `user` messages — the Converse `Message` API rejects images in
            // `assistant` messages. Reject here so it is a clean gate 400
            // instead of an upstream 502 that the default fallback never
            // retries. (Instruction roles are already rejected above; this
            // narrows the remaining user/assistant set to user-only.)
            if provider.provider_type == ProviderType::AwsBedrock && role != "user" {
                return Err(format!(
                    "AWS Bedrock Converse only allows image content in user messages, not '{}' messages",
                    bounded_error_value(role)
                ));
            }

            match provider.provider_type {
                // Anthropic's Messages API accepts both base64 data URLs and
                // remote `https`/`http` image sources. Validate the data-URL
                // media type here (jpeg/png/gif/webp only) so an unsupported
                // type like `image/svg+xml` is a clean gate 400 rather than an
                // upstream 502 the default fallback never retries; remote URLs
                // carry no media type, so only their scheme is checked.
                ProviderType::Anthropic => {
                    let url = image_url_value(part)?;
                    if url.starts_with("data:") {
                        let parsed = parse_image_data_url(url)?;
                        anthropic_image_media_type(parsed.media_type)?;
                    } else {
                        validate_openai_image_url(part)?;
                    }
                }
                // Gemini/Vertex translation accepts a base64 data URL
                // (`inlineData`) or a provider-fetchable URI — a `gs://` GCS URI
                // or a Files API URI (`.../v1beta/files/...`) emitted as
                // `fileData.fileUri`. This plugin does not fetch/inline arbitrary
                // public `http(s)` URLs, so those are rejected at the gate
                // instead of producing an opaque provider rejection (502).
                ProviderType::GoogleGemini | ProviderType::GoogleVertex => {
                    classify_gemini_image_url(part)?;
                }
                ProviderType::AwsBedrock => {
                    let url = image_url_value(part)?;
                    let parsed = parse_image_data_url(url).map_err(|e| {
                        format!("AWS Bedrock Converse only supports image_url data URLs: {e}")
                    })?;
                    // Validate the concrete format here so the gate (a clean
                    // 400) is the single source of truth — otherwise an
                    // unsupported format (e.g. svg+xml/bmp/tiff) passes the
                    // gate and fails later in `openai_content_to_bedrock_blocks`
                    // via the translation-error path as a 502.
                    bedrock_image_format(parsed.media_type)?;
                }
                _ => {}
            }
        }
    }

    Ok(())
}

fn validate_openai_image_url(part: &Value) -> Result<(), String> {
    let url = image_url_value(part)?;

    if url.starts_with("data:") {
        parse_image_data_url(url)?;
        return Ok(());
    }

    let parsed = Url::parse(url).map_err(|e| format!("image_url.url is not a valid URL: {e}"))?;
    match parsed.scheme() {
        "https" | "http" => Ok(()),
        other => Err(format!(
            "image_url.url scheme '{}' is unsupported (expected https, http, or data)",
            bounded_error_value(other)
        )),
    }
}

struct ParsedImageDataUrl<'a> {
    media_type: &'a str,
    data: &'a str,
}

/// Decode a base64 image payload from a `data:` URL. Padding is indifferent
/// (clients sometimes strip trailing `=`); the alphabet is the standard `+/`
/// set so a URL-safe payload is rejected rather than silently corrupting the
/// image bytes on the provider side.
fn decode_image_base64(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine as _;
    use base64::alphabet;
    use base64::engine::DecodePaddingMode;
    use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};

    const DECODER: GeneralPurpose = GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_encode_padding(true)
            .with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    DECODER.decode(data.as_bytes())
}

fn parse_image_data_url(url: &str) -> Result<ParsedImageDataUrl<'_>, String> {
    let rest = url
        .strip_prefix("data:")
        .ok_or("image_url.url is not a data URL")?;
    let (metadata, data) = rest
        .split_once(',')
        .ok_or("image_url data URL missing comma separator")?;
    let metadata = metadata
        .strip_suffix(";base64")
        .ok_or("image_url data URL must be base64 encoded")?;

    // The media type may carry parameters (e.g. `image/png;charset=utf-8`).
    // Strip them so the bare type is what providers receive and what
    // per-provider media-type checks see — Anthropic/Bedrock reject an
    // unexpected parameterized `media_type`/`mimeType` string.
    let media_type = metadata.split(';').next().unwrap_or(metadata).trim();

    if !media_type.starts_with("image/") {
        return Err(format!(
            "image_url data URL media type '{}' is not an image",
            bounded_error_value(media_type)
        ));
    }
    if data.is_empty() {
        return Err("image_url data URL has empty image data".to_string());
    }
    // Validate the payload is actually base64 so a malformed value
    // (e.g. `not@@base64`) is a clean policy-gate 400 instead of an opaque
    // provider 502 — the translators copy `data` verbatim into the provider
    // request (Anthropic `source.data`, Gemini `inlineData.data`, Bedrock
    // `source.bytes`), all of which expect valid base64 image bytes. Padding is
    // indifferent (some clients strip trailing `=`); the alphabet stays
    // standard (`+/`) so we never silently accept a URL-safe payload that would
    // corrupt the image on the provider side.
    decode_image_base64(data)
        .map_err(|e| format!("image_url data URL has invalid base64 image data: {e}"))?;

    Ok(ParsedImageDataUrl { media_type, data })
}

fn image_url_value(part: &Value) -> Result<&str, String> {
    part.get("image_url")
        .and_then(Value::as_object)
        .and_then(|image_url| image_url.get("url"))
        .and_then(Value::as_str)
        .ok_or_else(|| "image_url content part must include image_url.url".to_string())
}

fn openai_content_to_anthropic(content: &Value, mode: MultimodalMode) -> Result<Value, String> {
    if mode == MultimodalMode::TextOnlyWithWarning {
        return Ok(Value::String(flatten_openai_message_text(content)));
    }
    if let Some(text) = content.as_str() {
        return Ok(Value::String(text.to_string()));
    }
    let Some(parts) = content.as_array() else {
        return Ok(Value::String(String::new()));
    };

    let mut out = Vec::with_capacity(parts.len());
    for part in parts {
        match part.get("type").and_then(Value::as_str) {
            Some("text") => {
                if let Some(text) = part.get("text").and_then(Value::as_str)
                    && !text.is_empty()
                {
                    out.push(json!({ "type": "text", "text": text }));
                }
            }
            Some("image_url") => {
                let url = image_url_value(part)?;
                if url.starts_with("data:") {
                    let parsed = parse_image_data_url(url).map_err(|e| {
                        format!("ai_federation: invalid image_url data URL for Anthropic translation: {e}")
                    })?;
                    // Defense-in-depth: the policy gate already rejects
                    // unsupported media types, but re-validate so the translator
                    // never emits an Anthropic `media_type` the API will reject.
                    let media_type = anthropic_image_media_type(parsed.media_type)?;
                    out.push(json!({
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": media_type,
                            "data": parsed.data
                        }
                    }));
                } else {
                    out.push(json!({
                        "type": "image",
                        "source": {
                            "type": "url",
                            "url": url
                        }
                    }));
                }
            }
            Some(other) => {
                return Err(format!(
                    "ai_federation: unsupported multimodal content part '{other}' for Anthropic translation"
                ));
            }
            None => {
                return Err(
                    "ai_federation: content part missing 'type' for Anthropic translation"
                        .to_string(),
                );
            }
        }
    }

    Ok(Value::Array(out))
}

fn openai_content_to_gemini_parts(
    content: &Value,
    mode: MultimodalMode,
) -> Result<Vec<Value>, String> {
    if mode == MultimodalMode::TextOnlyWithWarning {
        return Ok(vec![
            json!({ "text": flatten_openai_message_text(content) }),
        ]);
    }
    if let Some(text) = content.as_str() {
        return Ok(vec![json!({ "text": text })]);
    }
    let Some(parts) = content.as_array() else {
        return Ok(vec![json!({ "text": "" })]);
    };

    let mut out = Vec::with_capacity(parts.len());
    for part in parts {
        match part.get("type").and_then(Value::as_str) {
            Some("text") => {
                if let Some(text) = part.get("text").and_then(Value::as_str) {
                    out.push(json!({ "text": text }));
                }
            }
            Some("image_url") => {
                // Data URLs inline as `inlineData`; `gs://` GCS URIs and Files
                // API URIs pass through as `fileData.fileUri`; arbitrary public
                // `http(s)` URLs are rejected (Gemini cannot fetch them and this
                // plugin does not fetch/inline them). The policy gate normally
                // catches an unsupported URL first; this keeps the translator
                // honest if it is ever called on its own.
                match classify_gemini_image_url(part).map_err(|e| format!("ai_federation: {e}"))? {
                    GeminiImageRef::Inline { parsed, mime_type } => {
                        out.push(json!({
                            "inlineData": {
                                "mimeType": mime_type,
                                "data": parsed.data
                            }
                        }));
                    }
                    GeminiImageRef::FileUri { uri, mime_type } => {
                        // Google's `FileData` requires `mimeType` whenever
                        // `fileUri` is set; emit the inferred type alongside it.
                        out.push(json!({
                            "fileData": {
                                "mimeType": mime_type,
                                "fileUri": uri
                            }
                        }));
                    }
                }
            }
            Some(other) => {
                return Err(format!(
                    "ai_federation: unsupported multimodal content part '{other}' for Gemini translation"
                ));
            }
            None => {
                return Err(
                    "ai_federation: content part missing 'type' for Gemini translation".to_string(),
                );
            }
        }
    }

    if out.is_empty() {
        out.push(json!({ "text": "" }));
    }
    Ok(out)
}

/// How a Gemini/Vertex `image_url` should be translated.
enum GeminiImageRef<'a> {
    /// `data:` URL → inlined as `inlineData` (base64 bytes). Carries the
    /// validated/canonical Gemini `mimeType`.
    Inline {
        parsed: ParsedImageDataUrl<'a>,
        mime_type: &'static str,
    },
    /// `gs://` GCS URI or Files API URI → passed through as `fileData.fileUri`.
    /// Google's `FileData` requires `mimeType` whenever `fileUri` is set, so we
    /// infer it from the URI's file extension.
    FileUri {
        uri: &'a str,
        mime_type: &'static str,
    },
}

/// Classify a Gemini/Vertex `image_url` content part. Gemini `generateContent`
/// accepts base64-inlined images (`inlineData`) and provider-fetchable URIs
/// (`fileData.fileUri`): a `gs://` GCS URI or a Files API URI
/// (`https://generativelanguage.googleapis.com/v1beta/files/...`). It does NOT
/// fetch arbitrary public `http(s)` URLs, and this plugin never fetches/inlines
/// them either, so those are rejected.
///
/// For both forms the MIME type is validated/derived here so the gate (a clean
/// 400) is the single source of truth: an inline data URL with an unsupported
/// type (e.g. `image/svg+xml`) and a `fileData` URI whose `mimeType` cannot be
/// determined are rejected before dispatch instead of producing an opaque
/// upstream 400 the default fallback never retries.
///
/// For `fileData` URIs the `mimeType` is resolved from (1) an explicit
/// `image_url.mime_type` field on the part, else (2) the URI's file extension.
/// Files API URIs (`files/abc123`) carry no extension, so callers reference them
/// by adding `mime_type` to the `image_url` object.
fn classify_gemini_image_url(part: &Value) -> Result<GeminiImageRef<'_>, String> {
    let url = image_url_value(part)?;
    if url.starts_with("data:") {
        let parsed = parse_image_data_url(url).map_err(|e| {
            format!("Gemini/Vertex image translation: invalid image_url data URL: {e}")
        })?;
        let mime_type = gemini_image_mime_type(parsed.media_type)?;
        return Ok(GeminiImageRef::Inline { parsed, mime_type });
    }
    if url.starts_with("gs://") || is_gemini_files_api_uri(url) {
        let mime_type = gemini_file_uri_mime_type(part, url)?;
        return Ok(GeminiImageRef::FileUri {
            uri: url,
            mime_type,
        });
    }
    Err(format!(
        "Gemini/Vertex image translation only supports image_url data URLs, gs:// GCS URIs, or Files API URIs (arbitrary remote URL '{}' is not fetched/inlined)",
        bounded_error_value(url)
    ))
}

/// Gemini's `generateContent` vision input accepts a limited set of image MIME
/// types. Returns the canonical `mimeType` string to send upstream, or an error
/// for anything else (e.g. `image/svg+xml`, `image/bmp`, `image/tiff`).
fn gemini_image_mime_type(media_type: &str) -> Result<&'static str, String> {
    match media_type {
        "image/jpeg" | "image/jpg" => Ok("image/jpeg"),
        "image/png" => Ok("image/png"),
        "image/webp" => Ok("image/webp"),
        "image/heic" => Ok("image/heic"),
        "image/heif" => Ok("image/heif"),
        other => Err(format!(
            "ai_federation: unsupported Gemini image media type '{}' (expected jpeg, png, webp, heic, or heif)",
            bounded_error_value(other)
        )),
    }
}

/// Resolve the Gemini `fileData.mimeType` for a `gs://`/Files API URI. Google's
/// `FileData` requires `mimeType` whenever `fileUri` is set, but the URI itself
/// carries no declared type, so it is resolved from an explicit
/// `image_url.mime_type` field first, then the URI's file extension. When
/// neither is available (e.g. an extensionless Files API URI without an explicit
/// `mime_type`) the request is rejected at the gate rather than emitting a
/// `fileData` block the provider rejects.
fn gemini_file_uri_mime_type(part: &Value, uri: &str) -> Result<&'static str, String> {
    if let Some(explicit) = part
        .get("image_url")
        .and_then(Value::as_object)
        .and_then(|image_url| image_url.get("mime_type"))
        .and_then(Value::as_str)
    {
        return gemini_image_mime_type(explicit);
    }

    // Strip any query/fragment, then take the segment after the last '.'.
    let path = uri
        .split(['?', '#'])
        .next()
        .unwrap_or(uri)
        .trim_end_matches('/');
    let ext = path
        .rsplit('/')
        .next()
        .and_then(|seg| seg.rsplit_once('.').map(|(_, ext)| ext))
        .map(str::to_ascii_lowercase);
    match ext.as_deref() {
        Some("jpg") | Some("jpeg") => Ok("image/jpeg"),
        Some("png") => Ok("image/png"),
        Some("webp") => Ok("image/webp"),
        Some("heic") => Ok("image/heic"),
        Some("heif") => Ok("image/heif"),
        _ => Err(format!(
            "Gemini/Vertex image translation: cannot determine a supported image mimeType for fileData URI '{}' (add an explicit image_url.mime_type, or use a .jpg/.jpeg/.png/.webp/.heic/.heif extension)",
            bounded_error_value(uri)
        )),
    }
}

/// True for a Gemini Files API URI, e.g.
/// `https://generativelanguage.googleapis.com/v1beta/files/abc123`. The host
/// must be the Generative Language API and the path must reference `/files/`.
fn is_gemini_files_api_uri(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url) else {
        return false;
    };
    if parsed.scheme() != "https" {
        return false;
    }
    if parsed.host_str() != Some("generativelanguage.googleapis.com") {
        return false;
    }
    parsed.path().contains("/files/")
}

fn bedrock_image_format(media_type: &str) -> Result<&'static str, String> {
    match media_type {
        "image/png" => Ok("png"),
        "image/jpeg" | "image/jpg" => Ok("jpeg"),
        "image/gif" => Ok("gif"),
        "image/webp" => Ok("webp"),
        other => Err(format!(
            "ai_federation: unsupported Bedrock image media type '{}'",
            bounded_error_value(other)
        )),
    }
}

/// Anthropic's Messages API only accepts JPEG, PNG, GIF, and WebP image media
/// types. Returns the canonical `media_type` string to send upstream, or an
/// error for anything else (e.g. `image/svg+xml`, `image/bmp`).
fn anthropic_image_media_type(media_type: &str) -> Result<&'static str, String> {
    match media_type {
        "image/jpeg" | "image/jpg" => Ok("image/jpeg"),
        "image/png" => Ok("image/png"),
        "image/gif" => Ok("image/gif"),
        "image/webp" => Ok("image/webp"),
        other => Err(format!(
            "ai_federation: unsupported Anthropic image media type '{}' (expected jpeg, png, gif, or webp)",
            bounded_error_value(other)
        )),
    }
}

fn openai_content_to_bedrock_blocks(
    content: &Value,
    mode: MultimodalMode,
) -> Result<Vec<Value>, String> {
    if mode == MultimodalMode::TextOnlyWithWarning {
        return Ok(vec![
            json!({ "text": flatten_openai_message_text(content) }),
        ]);
    }
    if let Some(text) = content.as_str() {
        return Ok(vec![json!({ "text": text })]);
    }
    let Some(parts) = content.as_array() else {
        return Ok(vec![json!({ "text": "" })]);
    };

    let mut out = Vec::with_capacity(parts.len());
    for part in parts {
        match part.get("type").and_then(Value::as_str) {
            Some("text") => {
                if let Some(text) = part.get("text").and_then(Value::as_str) {
                    out.push(json!({ "text": text }));
                }
            }
            Some("image_url") => {
                let url = image_url_value(part)?;
                let parsed = parse_image_data_url(url).map_err(|e| {
                    format!(
                        "ai_federation: AWS Bedrock Converse image_url translation requires a data URL: {e}"
                    )
                })?;
                out.push(json!({
                    "image": {
                        "format": bedrock_image_format(parsed.media_type)?,
                        "source": {
                            "bytes": parsed.data
                        }
                    }
                }));
            }
            Some(other) => {
                return Err(format!(
                    "ai_federation: unsupported multimodal content part '{other}' for Bedrock translation"
                ));
            }
            None => {
                return Err(
                    "ai_federation: content part missing 'type' for Bedrock translation"
                        .to_string(),
                );
            }
        }
    }

    if out.is_empty() {
        out.push(json!({ "text": "" }));
    }
    Ok(out)
}

fn translate_to_anthropic(
    provider: &ResolvedProvider,
    openai_body: &Value,
    resolved_model: &str,
) -> Result<TranslatedRequest, String> {
    let messages = openai_body["messages"]
        .as_array()
        .ok_or("ai_federation: request missing 'messages' array")?;

    // Extract system messages into a single string. System content may
    // be either a plain string or an OpenAI-style content parts array
    // (multimodal); flatten both forms so guardrails aren't silently
    // dropped.
    let system_parts: Vec<String> = messages
        .iter()
        .filter(|m| m["role"].as_str().is_some_and(is_instruction_role))
        .map(|m| flatten_openai_message_text(&m["content"]))
        .filter(|s| !s.is_empty())
        .collect();

    let mut filtered_messages = Vec::with_capacity(messages.len());
    let mut message_index = 0;
    while message_index < messages.len() {
        let message = &messages[message_index];
        let role = message["role"].as_str().unwrap_or("");
        if is_instruction_role(role) {
            message_index += 1;
            continue;
        }
        if role == "tool" {
            let mut tool_results = Vec::new();
            while message_index < messages.len()
                && messages[message_index]["role"].as_str() == Some("tool")
            {
                let tool_message = &messages[message_index];
                let tool_use_id = tool_message["tool_call_id"].as_str().ok_or_else(|| {
                    format!(
                        "ai_federation: messages[{message_index}] tool message missing tool_call_id"
                    )
                })?;
                tool_results.push(json!({
                    "type": "tool_result",
                    "tool_use_id": tool_use_id,
                    "content": tool_result_text(&tool_message["content"])?
                }));
                message_index += 1;
            }
            filtered_messages.push(json!({
                "role": "user",
                "content": tool_results
            }));
            continue;
        }

        let translated_content =
            openai_content_to_anthropic(&message["content"], provider.multimodal_mode)?;
        let tool_calls = if role == "assistant" {
            parse_openai_tool_calls(message, message_index)?
        } else {
            Vec::new()
        };
        let content = if tool_calls.is_empty() {
            let representable = match &translated_content {
                Value::String(text) => !text.is_empty(),
                Value::Array(blocks) => !blocks.is_empty(),
                _ => false,
            };
            if !representable {
                return Err(format!(
                    "ai_federation: messages[{message_index}] has no Anthropic-representable content"
                ));
            }
            // Anthropic accepts either a string or a content-block array. Keep
            // the client's string shape when no tool block has to be appended.
            translated_content
        } else {
            let mut content = anthropic_content_blocks(translated_content);
            for call in tool_calls {
                content.push(json!({
                    "type": "tool_use",
                    "id": call.id,
                    "name": call.name,
                    "input": call.arguments,
                }));
            }
            Value::Array(content)
        };
        filtered_messages.push(json!({
            "role": role,
            "content": content,
        }));
        message_index += 1;
    }

    let max_tokens = openai_body["max_tokens"]
        .as_u64()
        .or_else(|| openai_body["max_completion_tokens"].as_u64())
        .unwrap_or(4096);

    let mut body = json!({
        "model": resolved_model,
        "messages": filtered_messages,
        "max_tokens": max_tokens,
    });

    if !system_parts.is_empty() {
        body["system"] = Value::String(system_parts.join("\n\n"));
    }

    // Map optional fields
    if let Some(temp) = openai_body.get("temperature") {
        body["temperature"] = temp.clone();
    }
    if let Some(top_p) = openai_body.get("top_p") {
        body["top_p"] = top_p.clone();
    }
    if let Some(stop) = normalized_stop_sequences(openai_body)? {
        body["stop_sequences"] = stop;
    }
    if let Some(tools) = parse_openai_tools(openai_body)? {
        body["tools"] = Value::Array(
            tools
                .into_iter()
                .map(|tool| {
                    let mut native = serde_json::Map::new();
                    native.insert("name".to_string(), tool["name"].clone());
                    if let Some(description) = tool["description"].as_str() {
                        native.insert(
                            "description".to_string(),
                            Value::String(description.to_string()),
                        );
                    }
                    native.insert("input_schema".to_string(), tool["parameters"].clone());
                    Value::Object(native)
                })
                .collect(),
        );
    }
    if let Some(choice) = anthropic_tool_choice(openai_body)? {
        body["tool_choice"] = choice;
    }

    let url = provider
        .base_url
        .clone()
        .unwrap_or_else(|| ProviderType::Anthropic.default_base_url().to_string());
    let headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("anthropic-version".to_string(), "2023-06-01".to_string()),
    ];
    let body_bytes = serialize_translated_request(&body, "Anthropic")?;

    Ok((url, headers, body_bytes))
}

fn anthropic_content_blocks(content: Value) -> Vec<Value> {
    match content {
        Value::String(text) if text.is_empty() => Vec::new(),
        Value::String(text) => vec![json!({ "type": "text", "text": text })],
        Value::Array(blocks) => blocks,
        _ => Vec::new(),
    }
}

fn anthropic_tool_choice(openai_body: &Value) -> Result<Option<Value>, String> {
    let Some(choice) = openai_body.get("tool_choice") else {
        return Ok(None);
    };
    let translated = match choice {
        Value::String(value) if value == "none" => json!({ "type": "none" }),
        Value::String(value) if value == "auto" => json!({ "type": "auto" }),
        Value::String(value) if value == "required" => json!({ "type": "any" }),
        Value::Object(object) => json!({
            "type": "tool",
            "name": object["function"]["name"],
        }),
        _ => return Err("ai_federation: unsupported Anthropic tool_choice".to_string()),
    };
    Ok(Some(translated))
}

fn translate_to_gemini(
    provider: &ResolvedProvider,
    openai_body: &Value,
    resolved_model: &str,
) -> Result<TranslatedRequest, String> {
    let messages = openai_body["messages"]
        .as_array()
        .ok_or("ai_federation: request missing 'messages' array")?;

    // Extract system messages → systemInstruction. Content may be a
    // string or a multimodal parts array; flatten to text either way.
    let system_parts: Vec<Value> = messages
        .iter()
        .filter(|m| m["role"].as_str().is_some_and(is_instruction_role))
        .map(|m| flatten_openai_message_text(&m["content"]))
        .filter(|s| !s.is_empty())
        .map(|text| json!({ "text": text }))
        .collect();

    let tool_names = tool_names_by_id(messages)?;
    let mut contents = Vec::with_capacity(messages.len());
    let mut message_index = 0;
    while message_index < messages.len() {
        let message = &messages[message_index];
        let role = message["role"].as_str().unwrap_or("");
        if is_instruction_role(role) {
            message_index += 1;
            continue;
        }
        if role == "tool" {
            let mut parts = Vec::new();
            while message_index < messages.len()
                && messages[message_index]["role"].as_str() == Some("tool")
            {
                let tool_message = &messages[message_index];
                let tool_call_id = tool_message["tool_call_id"].as_str().ok_or_else(|| {
                    format!(
                        "ai_federation: messages[{message_index}] tool message missing tool_call_id"
                    )
                })?;
                let tool_name = tool_names.get(tool_call_id).ok_or_else(|| {
                    format!(
                        "ai_federation: messages[{message_index}] tool_call_id has no matching assistant tool call"
                    )
                })?;
                let text = tool_result_text(&tool_message["content"])?;
                let response = match serde_json::from_str::<Value>(&text) {
                    Ok(Value::Object(object)) => Value::Object(object),
                    Ok(value) => json!({ "output": value }),
                    Err(_) => json!({ "output": text }),
                };
                parts.push(json!({
                    "functionResponse": {
                        "name": tool_name,
                        "response": response,
                    }
                }));
                message_index += 1;
            }
            contents.push(json!({
                "role": "user",
                "parts": parts
            }));
            continue;
        }

        let native_role = if role == "assistant" { "model" } else { role };
        let mut parts =
            openai_content_to_gemini_parts(&message["content"], provider.multimodal_mode)?;
        let tool_calls = if role == "assistant" {
            parse_openai_tool_calls(message, message_index)?
        } else {
            Vec::new()
        };
        if !tool_calls.is_empty()
            && parts.len() == 1
            && parts[0].get("text").and_then(Value::as_str) == Some("")
        {
            parts.clear();
        }
        for call in tool_calls {
            parts.push(json!({
                "functionCall": {
                    "name": call.name,
                    "args": call.arguments,
                }
            }));
        }
        if parts.is_empty() {
            return Err(format!(
                "ai_federation: messages[{message_index}] has no Gemini-representable content"
            ));
        }
        contents.push(json!({ "role": native_role, "parts": parts }));
        message_index += 1;
    }

    let mut body = json!({ "contents": contents });

    if !system_parts.is_empty() {
        body["systemInstruction"] = json!({ "parts": system_parts });
    }

    // generationConfig
    let mut gen_config = serde_json::Map::new();
    if let Some(max_tokens) = openai_body
        .get("max_tokens")
        .or_else(|| openai_body.get("max_completion_tokens"))
    {
        gen_config.insert("maxOutputTokens".to_string(), max_tokens.clone());
    }
    if let Some(temp) = openai_body.get("temperature") {
        gen_config.insert("temperature".to_string(), temp.clone());
    }
    if let Some(top_p) = openai_body.get("top_p") {
        gen_config.insert("topP".to_string(), top_p.clone());
    }
    if let Some(stop) = normalized_stop_sequences(openai_body)? {
        gen_config.insert("stopSequences".to_string(), stop);
    }
    if !gen_config.is_empty() {
        body["generationConfig"] = Value::Object(gen_config);
    }

    if let Some(tools) = parse_openai_tools(openai_body)? {
        let declarations = tools
            .into_iter()
            .map(|tool| {
                let mut declaration = serde_json::Map::new();
                declaration.insert("name".to_string(), tool["name"].clone());
                if let Some(description) = tool["description"].as_str() {
                    declaration.insert(
                        "description".to_string(),
                        Value::String(description.to_string()),
                    );
                }
                declaration.insert("parameters".to_string(), tool["parameters"].clone());
                Value::Object(declaration)
            })
            .collect::<Vec<_>>();
        body["tools"] = json!([{ "functionDeclarations": declarations }]);
    }
    if let Some(choice) = gemini_tool_choice(openai_body)? {
        body["toolConfig"] = json!({ "functionCallingConfig": choice });
    }

    let url = build_provider_url(provider, resolved_model);
    let headers = vec![("content-type".to_string(), "application/json".to_string())];
    let body_bytes = serialize_translated_request(&body, "Gemini")?;

    Ok((url, headers, body_bytes))
}

fn gemini_tool_choice(openai_body: &Value) -> Result<Option<Value>, String> {
    let Some(choice) = openai_body.get("tool_choice") else {
        return Ok(None);
    };
    let translated = match choice {
        Value::String(value) if value == "none" => json!({ "mode": "NONE" }),
        Value::String(value) if value == "auto" => json!({ "mode": "AUTO" }),
        Value::String(value) if value == "required" => json!({ "mode": "ANY" }),
        Value::Object(object) => json!({
            "mode": "ANY",
            "allowedFunctionNames": [object["function"]["name"].clone()],
        }),
        _ => return Err("ai_federation: unsupported Gemini tool_choice".to_string()),
    };
    Ok(Some(translated))
}

fn translate_to_bedrock(
    provider: &ResolvedProvider,
    openai_body: &Value,
    resolved_model: &str,
) -> Result<TranslatedRequest, String> {
    let messages = openai_body["messages"]
        .as_array()
        .ok_or("ai_federation: request missing 'messages' array")?;

    // Extract system messages. Content may be string or multimodal
    // parts array; flatten both forms.
    let system_blocks: Vec<Value> = messages
        .iter()
        .filter(|m| m["role"].as_str().is_some_and(is_instruction_role))
        .map(|m| flatten_openai_message_text(&m["content"]))
        .filter(|s| !s.is_empty())
        .map(|text| json!({ "text": text }))
        .collect();

    let mut bedrock_messages = Vec::with_capacity(messages.len());
    let mut message_index = 0;
    while message_index < messages.len() {
        let message = &messages[message_index];
        let role = message["role"].as_str().unwrap_or("");
        if is_instruction_role(role) {
            message_index += 1;
            continue;
        }
        if role == "tool" {
            let mut tool_results = Vec::new();
            while message_index < messages.len()
                && messages[message_index]["role"].as_str() == Some("tool")
            {
                let tool_message = &messages[message_index];
                let tool_use_id = tool_message["tool_call_id"].as_str().ok_or_else(|| {
                    format!(
                        "ai_federation: messages[{message_index}] tool message missing tool_call_id"
                    )
                })?;
                let text = tool_result_text(&tool_message["content"])?;
                let result_content = match serde_json::from_str::<Value>(&text) {
                    Ok(value) => json!([{ "json": value }]),
                    Err(_) => json!([{ "text": text }]),
                };
                tool_results.push(json!({
                    "toolResult": {
                        "toolUseId": tool_use_id,
                        "content": result_content,
                    }
                }));
                message_index += 1;
            }
            bedrock_messages.push(json!({
                "role": "user",
                "content": tool_results
            }));
            continue;
        }

        let mut content =
            openai_content_to_bedrock_blocks(&message["content"], provider.multimodal_mode)?;
        let tool_calls = if role == "assistant" {
            parse_openai_tool_calls(message, message_index)?
        } else {
            Vec::new()
        };
        if !tool_calls.is_empty()
            && content.len() == 1
            && content[0].get("text").and_then(Value::as_str) == Some("")
        {
            content.clear();
        }
        for call in tool_calls {
            content.push(json!({
                "toolUse": {
                    "toolUseId": call.id,
                    "name": call.name,
                    "input": call.arguments,
                }
            }));
        }
        if content.is_empty() {
            return Err(format!(
                "ai_federation: messages[{message_index}] has no Bedrock-representable content"
            ));
        }
        bedrock_messages.push(json!({ "role": role, "content": content }));
        message_index += 1;
    }

    let mut body = json!({ "messages": bedrock_messages });

    if !system_blocks.is_empty() {
        body["system"] = Value::Array(system_blocks);
    }

    // inferenceConfig
    let mut inference_config = serde_json::Map::new();
    if let Some(max_tokens) = openai_body
        .get("max_tokens")
        .or_else(|| openai_body.get("max_completion_tokens"))
    {
        inference_config.insert("maxTokens".to_string(), max_tokens.clone());
    }
    if let Some(temp) = openai_body.get("temperature") {
        inference_config.insert("temperature".to_string(), temp.clone());
    }
    if let Some(top_p) = openai_body.get("top_p") {
        inference_config.insert("topP".to_string(), top_p.clone());
    }
    if let Some(stop) = normalized_stop_sequences(openai_body)? {
        inference_config.insert("stopSequences".to_string(), stop);
    }
    if !inference_config.is_empty() {
        body["inferenceConfig"] = Value::Object(inference_config);
    }

    let tool_choice = bedrock_tool_choice(openai_body)?;
    match (parse_openai_tools(openai_body)?, tool_choice) {
        (_, BedrockToolChoice::Disabled) => {}
        (Some(tools), BedrockToolChoice::Enabled(choice)) => {
            let native_tools = tools
                .into_iter()
                .map(|tool| {
                    let mut spec = serde_json::Map::new();
                    spec.insert("name".to_string(), tool["name"].clone());
                    if let Some(description) = tool["description"].as_str() {
                        spec.insert(
                            "description".to_string(),
                            Value::String(description.to_string()),
                        );
                    }
                    spec.insert(
                        "inputSchema".to_string(),
                        json!({ "json": tool["parameters"].clone() }),
                    );
                    json!({ "toolSpec": Value::Object(spec) })
                })
                .collect::<Vec<_>>();
            let mut tool_config = json!({ "tools": native_tools });
            if let Some(choice) = choice {
                tool_config["toolChoice"] = choice;
            }
            body["toolConfig"] = tool_config;
        }
        (None, BedrockToolChoice::Enabled(Some(_))) => {
            return Err("ai_federation: Bedrock tool_choice requires tools".to_string());
        }
        (None, BedrockToolChoice::Enabled(None)) => {}
    }

    let url = build_provider_url(provider, resolved_model);
    let headers = vec![("content-type".to_string(), "application/json".to_string())];
    let body_bytes = serialize_translated_request(&body, "Bedrock")?;

    Ok((url, headers, body_bytes))
}

enum BedrockToolChoice {
    Disabled,
    Enabled(Option<Value>),
}

fn bedrock_tool_choice(openai_body: &Value) -> Result<BedrockToolChoice, String> {
    let Some(choice) = openai_body.get("tool_choice") else {
        return Ok(BedrockToolChoice::Enabled(None));
    };
    let translated = match choice {
        // Bedrock Converse has no native disabled choice. Omitting the entire
        // toolConfig is the lossless representation: no tools are available.
        Value::String(value) if value == "none" => return Ok(BedrockToolChoice::Disabled),
        Value::String(value) if value == "auto" => json!({ "auto": {} }),
        Value::String(value) if value == "required" => json!({ "any": {} }),
        Value::Object(object) => json!({
            "tool": { "name": object["function"]["name"].clone() }
        }),
        _ => return Err("ai_federation: unsupported Bedrock tool_choice".to_string()),
    };
    Ok(BedrockToolChoice::Enabled(Some(translated)))
}

fn translate_to_cohere(
    provider: &ResolvedProvider,
    openai_body: &Value,
    resolved_model: &str,
) -> Result<TranslatedRequest, String> {
    // Cohere v2 Chat API accepts OpenAI-style messages, but with its own model field
    let mut body = if provider.multimodal_mode == MultimodalMode::TextOnlyWithWarning {
        text_only_openai_body(openai_body)
    } else {
        openai_body.clone()
    };
    body["model"] = Value::String(resolved_model.to_string());

    // Remove fields Cohere doesn't support
    if let Some(obj) = body.as_object_mut() {
        obj.remove("max_completion_tokens");
        obj.remove("stop");
    }
    if let Some(stop) = normalized_stop_sequences(openai_body)? {
        body["stop_sequences"] = stop;
    }

    let url = provider
        .base_url
        .clone()
        .unwrap_or_else(|| ProviderType::Cohere.default_base_url().to_string());
    let headers = vec![("content-type".to_string(), "application/json".to_string())];
    let body_bytes = serialize_translated_request(&body, "Cohere")?;

    Ok((url, headers, body_bytes))
}

/// Build the provider-specific URL by rendering the pre-computed template.
///
/// The template is constructed once per provider at config-load time
/// (see `build_url_template`), so the only per-request work here is one
/// `String` allocation that concatenates the cached prefix, the request
/// model, and the cached suffix.
fn build_provider_url(provider: &ResolvedProvider, model: &str) -> String {
    provider.url_template.render(model)
}

// ---------------------------------------------------------------------------
// Response normalization
// ---------------------------------------------------------------------------

/// Maximum number of characters of the client-supplied `model` reflected back
/// in a no-match error body.
///
/// The unmatched-model 404 echoes the requested model so operators can see what
/// failed to route, but the value is fully client-controlled and only bounded by
/// the request-body limit. Capping it keeps a hostile caller from forcing the
/// gateway to clone and serialize a multi-megabyte string into the error
/// response. Any real model id is far shorter than this.
const MAX_ECHOED_MODEL_CHARS: usize = 128;

/// Bound the client-supplied `model` string echoed back in error responses.
///
/// Truncates on a UTF-8 character boundary (not a byte boundary) so the result
/// is always valid UTF-8, and appends an ellipsis marker when the value was
/// shortened so the message stays unambiguous. The returned string is still
/// JSON-escaped by `serde_json` when serialized into the error body.
fn truncate_model_for_error(model: &str) -> String {
    if model.chars().count() <= MAX_ECHOED_MODEL_CHARS {
        return model.to_string();
    }
    let truncated: String = model.chars().take(MAX_ECHOED_MODEL_CHARS).collect();
    format!("{truncated}… (truncated)")
}

fn openai_error_body(
    message: &str,
    error_type: &str,
    param: Option<&str>,
    code: Option<&str>,
) -> Value {
    json!({
        "error": {
            "message": message,
            "type": error_type,
            "param": param,
            "code": code,
        }
    })
}

/// Normalize a provider response to OpenAI Chat Completions format.
fn normalize_response(
    provider_type: ProviderType,
    status: u16,
    body: &[u8],
    resolved_model: &str,
) -> Result<(Value, TokenCounts), String> {
    // Only 2xx responses may enter a provider success normalizer. Redirects
    // are never followed by PluginHttpClient and remain redirects; treating a
    // JSON 3xx body as a completion would rewrite it into a false 200.
    if !(200..300).contains(&status) {
        return Ok((
            openai_error_body(
                &format!("Upstream provider returned status {status}"),
                "upstream_error",
                None,
                Some("upstream_error"),
            ),
            TokenCounts::default(),
        ));
    }

    let resp: Value = serde_json::from_slice(body)
        .map_err(|e| format!("ai_federation: failed to parse provider response: {e}"))?;

    let response_object = resp
        .as_object()
        .ok_or("ai_federation: provider success response must be a JSON object")?;
    if response_object
        .get("error")
        .is_some_and(|error| !error.is_null())
    {
        return Err(
            "ai_federation: provider returned an error envelope with a success status".to_string(),
        );
    }

    match provider_type {
        ProviderType::OpenAi
        | ProviderType::AzureOpenAi
        | ProviderType::Mistral
        | ProviderType::Xai
        | ProviderType::DeepSeek
        | ProviderType::MetaLlama
        | ProviderType::HuggingFace => normalize_from_openai_compatible(&resp),
        ProviderType::Anthropic => normalize_from_anthropic(&resp, resolved_model),
        ProviderType::GoogleGemini | ProviderType::GoogleVertex => {
            normalize_from_gemini(&resp, resolved_model)
        }
        ProviderType::AwsBedrock => normalize_from_bedrock(&resp, resolved_model),
        ProviderType::Cohere => normalize_from_cohere(&resp, resolved_model),
    }
}

fn normalize_from_openai_compatible(resp: &Value) -> Result<(Value, TokenCounts), String> {
    required_non_empty_string(resp, "id", "OpenAI-compatible response")?;
    required_model_identifier(resp, "model", "OpenAI-compatible response")?;
    if resp["object"].as_str() != Some("chat.completion") {
        return Err(
            "ai_federation: OpenAI-compatible response object must be 'chat.completion'"
                .to_string(),
        );
    }
    let choices = resp["choices"]
        .as_array()
        .filter(|choices| !choices.is_empty())
        .ok_or("ai_federation: OpenAI-compatible response missing non-empty choices array")?;
    for (index, choice) in choices.iter().enumerate() {
        let choice_object = choice.as_object().ok_or_else(|| {
            format!("ai_federation: OpenAI-compatible choices[{index}] must be an object")
        })?;
        if choice_object.get("index").and_then(Value::as_u64).is_none() {
            return Err(format!(
                "ai_federation: OpenAI-compatible choices[{index}] missing non-negative integer index"
            ));
        }
        let message = choice_object
            .get("message")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                format!("ai_federation: OpenAI-compatible choices[{index}] missing message object")
            })?;
        if message.get("role").and_then(Value::as_str) != Some("assistant") {
            return Err(format!(
                "ai_federation: OpenAI-compatible choices[{index}] message role must be assistant"
            ));
        }
        let finish_reason = choice_object
            .get("finish_reason")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!("ai_federation: OpenAI-compatible choices[{index}] missing finish_reason")
            })?;
        if !matches!(
            finish_reason,
            "stop" | "length" | "tool_calls" | "content_filter"
        ) {
            return Err(format!(
                "ai_federation: OpenAI-compatible choices[{index}] has unsupported finish_reason"
            ));
        }
        let tool_calls = parse_provider_tool_calls(message, index, "OpenAI-compatible")?;
        let has_refusal = match message.get("refusal") {
            None | Some(Value::Null) => false,
            Some(Value::String(refusal)) => !refusal.is_empty(),
            Some(_) => {
                return Err(format!(
                    "ai_federation: OpenAI-compatible choices[{index}] refusal must be a string or null"
                ));
            }
        };
        let has_non_empty_content = match message.get("content") {
            None | Some(Value::Null) => false,
            Some(Value::String(content)) => !content.is_empty(),
            Some(_) => {
                return Err(format!(
                    "ai_federation: OpenAI-compatible choices[{index}] content must be a string or null"
                ));
            }
        };
        let has_filtered_content_shape = finish_reason == "content_filter"
            && matches!(
                message.get("content"),
                None | Some(Value::Null) | Some(Value::String(_))
            );
        if !has_non_empty_content
            && tool_calls.is_empty()
            && !has_filtered_content_shape
            && !has_refusal
        {
            return Err(format!(
                "ai_federation: OpenAI-compatible choices[{index}] has neither text content, tool calls, nor refusal"
            ));
        }
        let has_tool_calls = !tool_calls.is_empty();
        if (finish_reason == "tool_calls") != has_tool_calls {
            return Err(format!(
                "ai_federation: OpenAI-compatible choices[{index}] tool calls and finish_reason disagree"
            ));
        }
    }

    validate_optional_usage_object(
        resp.get("usage"),
        &["prompt_tokens", "completion_tokens", "total_tokens"],
    )?;
    let tokens = TokenCounts {
        prompt_tokens: resp["usage"]["prompt_tokens"].as_u64(),
        completion_tokens: resp["usage"]["completion_tokens"].as_u64(),
        total_tokens: resp["usage"]["total_tokens"].as_u64(),
        model: resp["model"].as_str().map(String::from),
    };
    Ok((resp.clone(), tokens))
}

fn validate_optional_usage_object(usage: Option<&Value>, fields: &[&str]) -> Result<(), String> {
    let Some(usage) = usage.filter(|value| !value.is_null()) else {
        return Ok(());
    };
    let usage = usage
        .as_object()
        .ok_or("ai_federation: response usage must be an object")?;
    for field in fields {
        if usage.get(*field).is_some_and(|value| !value.is_u64()) {
            return Err(format!(
                "ai_federation: response usage.{field} must be a non-negative integer"
            ));
        }
    }
    Ok(())
}

fn required_non_empty_string<'a>(
    value: &'a Value,
    key: &str,
    scope: &str,
) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("ai_federation: {scope} missing non-empty {key}"))
}

fn required_model_identifier<'a>(
    value: &'a Value,
    key: &str,
    scope: &str,
) -> Result<&'a str, String> {
    let model = required_non_empty_string(value, key, scope)?;
    if !is_valid_model_identifier(model) {
        return Err(format!(
            "ai_federation: {scope} contains an invalid model identifier"
        ));
    }
    Ok(model)
}

fn required_tool_name<'a>(value: &'a Value, key: &str, scope: &str) -> Result<&'a str, String> {
    let name = required_non_empty_string(value, key, scope)?;
    if !valid_tool_name(name) {
        return Err(format!(
            "ai_federation: {scope} {key} must contain 1-64 alphanumeric, underscore, or hyphen characters"
        ));
    }
    Ok(name)
}

fn openai_tool_call(id: &str, name: &str, arguments: &Value) -> Result<Value, String> {
    if id.is_empty() || id.len() > 128 {
        return Err(
            "ai_federation: provider tool-call id must contain 1-128 characters".to_string(),
        );
    }
    if !valid_tool_name(name) {
        return Err(
            "ai_federation: provider tool-call name contains unsupported characters".to_string(),
        );
    }
    if !arguments.is_object() {
        return Err("ai_federation: provider tool-call arguments must be an object".to_string());
    }
    let arguments = match serialize_json_bounded(arguments, MAX_PROVIDER_RESPONSE_BYTES) {
        Ok(arguments) => String::from_utf8(arguments).map_err(|_| {
            "ai_federation: tool-call arguments serialization produced invalid UTF-8".to_string()
        })?,
        Err(BoundedJsonSerializationError::LimitExceeded) => {
            return Err(
                "ai_federation: provider tool-call arguments exceeded the global response limit"
                    .to_string(),
            );
        }
        Err(BoundedJsonSerializationError::Serialization) => {
            return Err("ai_federation: tool-call arguments serialization failed".to_string());
        }
    };
    Ok(json!({
        "id": id,
        "type": "function",
        "function": {
            "name": name,
            "arguments": arguments,
        }
    }))
}

fn native_usage_pair(
    usage: Option<&Value>,
    input_key: &str,
    output_key: &str,
    provider: &str,
) -> Result<(Option<u64>, Option<u64>), String> {
    let Some(usage) = usage.filter(|value| !value.is_null()) else {
        return Ok((None, None));
    };
    let usage = usage
        .as_object()
        .ok_or_else(|| format!("ai_federation: {provider} usage must be an object"))?;
    for key in [input_key, output_key] {
        if usage.get(key).is_some_and(|value| !value.is_u64()) {
            return Err(format!(
                "ai_federation: {provider} usage.{key} must be a non-negative integer"
            ));
        }
    }
    Ok((
        usage.get(input_key).and_then(Value::as_u64),
        usage.get(output_key).and_then(Value::as_u64),
    ))
}

fn summed_usage(
    input: Option<u64>,
    output: Option<u64>,
    provider: &str,
) -> Result<Option<u64>, String> {
    match (input, output) {
        (Some(input), Some(output)) => input
            .checked_add(output)
            .map(Some)
            .ok_or_else(|| format!("ai_federation: {provider} token usage total overflowed")),
        _ => Ok(None),
    }
}

fn insert_normalized_usage(
    normalized: &mut Value,
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
    total_tokens: Option<u64>,
) {
    let mut usage = serde_json::Map::new();
    if let Some(value) = prompt_tokens {
        usage.insert("prompt_tokens".to_string(), Value::from(value));
    }
    if let Some(value) = completion_tokens {
        usage.insert("completion_tokens".to_string(), Value::from(value));
    }
    if let Some(value) = total_tokens {
        usage.insert("total_tokens".to_string(), Value::from(value));
    }
    if !usage.is_empty() {
        normalized["usage"] = Value::Object(usage);
    }
}

fn normalize_from_anthropic(resp: &Value, _model: &str) -> Result<(Value, TokenCounts), String> {
    if resp["type"].as_str() != Some("message") || resp["role"].as_str() != Some("assistant") {
        return Err(
            "ai_federation: Anthropic success response must be an assistant message".to_string(),
        );
    }
    let id = required_non_empty_string(resp, "id", "Anthropic response")?;
    let resp_model = required_model_identifier(resp, "model", "Anthropic response")?;
    let stop_reason = required_non_empty_string(resp, "stop_reason", "Anthropic response")?;
    let content_blocks = resp["content"]
        .as_array()
        .filter(|blocks| !blocks.is_empty())
        .ok_or("ai_federation: Anthropic response missing non-empty content array")?;

    let mut text = String::new();
    let mut tool_calls = Vec::new();
    for (index, block) in content_blocks.iter().enumerate() {
        match block.get("type").and_then(Value::as_str) {
            Some("text") => {
                text.push_str(block.get("text").and_then(Value::as_str).ok_or_else(|| {
                    format!("ai_federation: Anthropic content[{index}] text block missing text")
                })?)
            }
            Some("tool_use") => {
                let tool_id = required_non_empty_string(
                    block,
                    "id",
                    &format!("Anthropic content[{index}] tool_use"),
                )?;
                let tool_name = required_tool_name(
                    block,
                    "name",
                    &format!("Anthropic content[{index}] tool_use"),
                )?;
                let input = block.get("input").filter(|value| value.is_object()).ok_or_else(|| {
                    format!(
                        "ai_federation: Anthropic content[{index}] tool_use input must be an object"
                    )
                })?;
                tool_calls.push(openai_tool_call(tool_id, tool_name, input)?);
            }
            Some(_) => {
                return Err(format!(
                    "ai_federation: Anthropic content[{index}] has a block type that cannot be represented by Chat Completions"
                ));
            }
            None => {
                return Err(format!(
                    "ai_federation: Anthropic content[{index}] missing block type"
                ));
            }
        }
    }
    if text.is_empty() && tool_calls.is_empty() {
        return Err(
            "ai_federation: Anthropic response has no non-empty text or tool calls".to_string(),
        );
    }

    let has_tool_calls = !tool_calls.is_empty();
    if (stop_reason == "tool_use") != has_tool_calls {
        return Err(
            "ai_federation: Anthropic tool_use content and stop_reason disagree".to_string(),
        );
    }
    let finish_reason = match stop_reason {
        "end_turn" | "stop_sequence" | "pause_turn" => "stop",
        "max_tokens" => "length",
        "tool_use" => "tool_calls",
        "refusal" => "content_filter",
        _ => {
            return Err(
                "ai_federation: Anthropic response has an unsupported stop_reason".to_string(),
            );
        }
    };

    let (input_tokens, output_tokens) = native_usage_pair(
        resp.get("usage"),
        "input_tokens",
        "output_tokens",
        "Anthropic",
    )?;
    let total = summed_usage(input_tokens, output_tokens, "Anthropic")?;

    let mut message = json!({
        "role": "assistant",
        "content": if text.is_empty() { Value::Null } else { Value::String(text) },
    });
    if !tool_calls.is_empty() {
        message["tool_calls"] = Value::Array(tool_calls);
    }
    let mut normalized = json!({
        "id": id,
        "object": "chat.completion",
        "created": Utc::now().timestamp(),
        "model": resp_model,
        "choices": [{
            "index": 0,
            "message": message,
            "finish_reason": finish_reason
        }]
    });
    insert_normalized_usage(&mut normalized, input_tokens, output_tokens, total);

    let tokens = TokenCounts {
        prompt_tokens: input_tokens,
        completion_tokens: output_tokens,
        total_tokens: total,
        model: Some(resp_model.to_string()),
    };

    Ok((normalized, tokens))
}

fn gemini_prompt_is_blocked(resp: &Value) -> Result<bool, String> {
    let Some(feedback) = resp.get("promptFeedback") else {
        return Ok(false);
    };
    let feedback = feedback
        .as_object()
        .ok_or("ai_federation: Gemini promptFeedback must be an object")?;
    let Some(reason) = feedback.get("blockReason") else {
        return Ok(false);
    };
    match reason.as_str() {
        Some(
            "SAFETY" | "BLOCKLIST" | "PROHIBITED_CONTENT" | "MODEL_ARMOR" | "IMAGE_SAFETY"
            | "JAILBREAK" | "OTHER",
        ) => Ok(true),
        Some("BLOCK_REASON_UNSPECIFIED" | "BLOCKED_REASON_UNSPECIFIED") => Ok(false),
        _ => Err("ai_federation: Gemini promptFeedback has an unsupported blockReason".to_string()),
    }
}

fn normalize_from_gemini(resp: &Value, model: &str) -> Result<(Value, TokenCounts), String> {
    let prompt_is_blocked = gemini_prompt_is_blocked(resp)?;
    let candidates: &[Value] = match resp.get("candidates") {
        Some(Value::Array(candidates)) => candidates,
        None if prompt_is_blocked => &[],
        _ => return Err("ai_federation: Gemini response candidates must be an array".to_string()),
    };
    if candidates.is_empty() && !prompt_is_blocked {
        return Err(
            "ai_federation: Gemini response missing non-empty candidates array".to_string(),
        );
    }
    let response_id = match resp.get("responseId") {
        Some(Value::String(value)) if !value.is_empty() && value.len() <= 128 => value.clone(),
        Some(_) => {
            return Err(
                "ai_federation: Gemini response contains an invalid responseId".to_string(),
            );
        }
        None => format!("chatcmpl-fed-{}", generate_short_id()),
    };
    let call_id_prefix = generate_short_id();
    let mut choices = Vec::with_capacity(candidates.len().max(1));

    if candidates.is_empty() {
        choices.push(json!({
            "index": 0,
            "message": {
                "role": "assistant",
                "content": Value::Null,
            },
            "finish_reason": "content_filter",
        }));
    }

    for (candidate_index, candidate) in candidates.iter().enumerate() {
        let candidate = candidate.as_object().ok_or_else(|| {
            format!("ai_federation: Gemini candidates[{candidate_index}] must be an object")
        })?;
        let native_finish = candidate
            .get("finishReason")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!("ai_federation: Gemini candidates[{candidate_index}] missing finishReason")
            })?;
        let base_finish_reason = match native_finish {
            "STOP" | "OTHER" => "stop",
            "MAX_TOKENS" => "length",
            "SAFETY"
            | "RECITATION"
            | "LANGUAGE"
            | "BLOCKLIST"
            | "PROHIBITED_CONTENT"
            | "SPII"
            | "MODEL_ARMOR"
            | "MALFORMED_FUNCTION_CALL"
            | "IMAGE_SAFETY"
            | "IMAGE_PROHIBITED_CONTENT"
            | "IMAGE_OTHER"
            | "NO_IMAGE"
            | "IMAGE_RECITATION"
            | "UNEXPECTED_TOOL_CALL" => "content_filter",
            _ => {
                return Err(
                    "ai_federation: Gemini candidate has an unsupported finishReason".to_string(),
                );
            }
        };
        let parts: &[Value] = match candidate.get("content") {
            Some(Value::Object(content)) => {
                match content.get("role") {
                    Some(Value::String(role)) if role == "model" => {}
                    None if base_finish_reason == "content_filter" => {}
                    _ => {
                        return Err(format!(
                            "ai_federation: Gemini candidates[{candidate_index}] content role must be model"
                        ));
                    }
                }
                match content.get("parts") {
                    Some(Value::Array(parts)) if !parts.is_empty() => parts,
                    Some(Value::Array(_)) | None if base_finish_reason == "content_filter" => &[],
                    _ => {
                        return Err(format!(
                            "ai_federation: Gemini candidates[{candidate_index}] missing non-empty content.parts"
                        ));
                    }
                }
            }
            None | Some(Value::Null) if base_finish_reason == "content_filter" => &[],
            _ => {
                return Err(format!(
                    "ai_federation: Gemini candidates[{candidate_index}] missing content object"
                ));
            }
        };
        let mut text = String::new();
        let mut tool_calls = Vec::new();
        for (part_index, part) in parts.iter().enumerate() {
            match (
                part.get("text").and_then(Value::as_str),
                part.get("functionCall"),
            ) {
                (Some(part_text), None) => text.push_str(part_text),
                (None, Some(function_call)) => {
                    let name = required_tool_name(
                        function_call,
                        "name",
                        &format!(
                            "Gemini candidates[{candidate_index}].parts[{part_index}].functionCall"
                        ),
                    )?;
                    let args = function_call
                        .get("args")
                        .filter(|value| value.is_object())
                        .ok_or_else(|| {
                            format!(
                                "ai_federation: Gemini candidates[{candidate_index}].parts[{part_index}] functionCall args must be an object"
                            )
                        })?;
                    let call_id =
                        format!("call_fed_{call_id_prefix}_{candidate_index}_{part_index}");
                    tool_calls.push(openai_tool_call(&call_id, name, args)?);
                }
                _ => {
                    return Err(format!(
                        "ai_federation: Gemini candidates[{candidate_index}].parts[{part_index}] must contain exactly one supported text or functionCall value"
                    ));
                }
            }
        }
        let finish_reason = if !tool_calls.is_empty() {
            if native_finish != "STOP" {
                return Err(format!(
                    "ai_federation: Gemini candidates[{candidate_index}] function calls and finishReason disagree"
                ));
            }
            "tool_calls"
        } else {
            base_finish_reason
        };
        if text.is_empty() && tool_calls.is_empty() && finish_reason != "content_filter" {
            return Err(format!(
                "ai_federation: Gemini candidates[{candidate_index}] has no non-empty text or function calls"
            ));
        }
        let mut message = json!({
            "role": "assistant",
            "content": if text.is_empty() { Value::Null } else { Value::String(text) },
        });
        if !tool_calls.is_empty() {
            message["tool_calls"] = Value::Array(tool_calls);
        }
        choices.push(json!({
            "index": candidate_index,
            "message": message,
            "finish_reason": finish_reason,
        }));
    }

    let (prompt_tokens, completion_tokens) = native_usage_pair(
        resp.get("usageMetadata"),
        "promptTokenCount",
        "candidatesTokenCount",
        "Gemini",
    )?;
    let total = match resp["usageMetadata"]["totalTokenCount"].as_u64() {
        Some(total) => Some(total),
        None => summed_usage(prompt_tokens, completion_tokens, "Gemini")?,
    };

    if resp
        .get("usageMetadata")
        .and_then(|usage| usage.get("totalTokenCount"))
        .is_some_and(|value| !value.is_u64())
    {
        return Err(
            "ai_federation: Gemini usageMetadata.totalTokenCount must be an integer".to_string(),
        );
    }
    let resp_model = match resp.get("modelVersion") {
        Some(Value::String(value)) if is_valid_model_identifier(value) => value.as_str(),
        Some(_) => {
            return Err(
                "ai_federation: Gemini response contains an invalid modelVersion".to_string(),
            );
        }
        None => model,
    };

    let mut normalized = json!({
        "id": response_id,
        "object": "chat.completion",
        "created": Utc::now().timestamp(),
        "model": resp_model,
        "choices": choices,
    });
    insert_normalized_usage(&mut normalized, prompt_tokens, completion_tokens, total);

    let tokens = TokenCounts {
        prompt_tokens,
        completion_tokens,
        total_tokens: total,
        model: Some(resp_model.to_string()),
    };

    Ok((normalized, tokens))
}

fn normalize_from_bedrock(resp: &Value, model: &str) -> Result<(Value, TokenCounts), String> {
    let message = resp["output"]["message"]
        .as_object()
        .ok_or("ai_federation: Bedrock response missing output.message")?;
    if message.get("role").and_then(Value::as_str) != Some("assistant") {
        return Err("ai_federation: Bedrock output.message role must be assistant".to_string());
    }
    let blocks = message
        .get("content")
        .and_then(Value::as_array)
        .filter(|blocks| !blocks.is_empty())
        .ok_or("ai_federation: Bedrock response missing non-empty output.message.content")?;
    let mut text = String::new();
    let mut tool_calls = Vec::new();
    for (index, block) in blocks.iter().enumerate() {
        match (
            block.get("text").and_then(Value::as_str),
            block.get("toolUse"),
        ) {
            (Some(block_text), None) => text.push_str(block_text),
            (None, Some(tool_use)) => {
                let tool_id = required_non_empty_string(
                    tool_use,
                    "toolUseId",
                    &format!("Bedrock content[{index}].toolUse"),
                )?;
                let tool_name = required_tool_name(
                    tool_use,
                    "name",
                    &format!("Bedrock content[{index}].toolUse"),
                )?;
                let input = tool_use
                    .get("input")
                    .filter(|value| value.is_object())
                    .ok_or_else(|| {
                        format!(
                            "ai_federation: Bedrock content[{index}].toolUse input must be an object"
                        )
                    })?;
                tool_calls.push(openai_tool_call(tool_id, tool_name, input)?);
            }
            _ => {
                return Err(format!(
                    "ai_federation: Bedrock content[{index}] must contain exactly one supported text or toolUse value"
                ));
            }
        }
    }
    if text.is_empty() && tool_calls.is_empty() {
        return Err(
            "ai_federation: Bedrock response has no non-empty text or tool calls".to_string(),
        );
    }

    let stop_reason = required_non_empty_string(resp, "stopReason", "Bedrock response")?;
    let has_tool_calls = !tool_calls.is_empty();
    if (stop_reason == "tool_use") != has_tool_calls {
        return Err("ai_federation: Bedrock toolUse content and stopReason disagree".to_string());
    }
    let finish_reason = match stop_reason {
        "end_turn" | "stop_sequence" => "stop",
        "max_tokens" | "model_context_window_exceeded" => "length",
        "guardrail_intervened"
        | "content_filtered"
        | "malformed_model_output"
        | "malformed_tool_use" => "content_filter",
        "tool_use" => "tool_calls",
        _ => {
            return Err(
                "ai_federation: Bedrock response has an unsupported stopReason".to_string(),
            );
        }
    };

    let (input_tokens, output_tokens) =
        native_usage_pair(resp.get("usage"), "inputTokens", "outputTokens", "Bedrock")?;
    let total = match resp["usage"]["totalTokens"].as_u64() {
        Some(total) => Some(total),
        None => summed_usage(input_tokens, output_tokens, "Bedrock")?,
    };

    if resp
        .get("usage")
        .and_then(|usage| usage.get("totalTokens"))
        .is_some_and(|value| !value.is_u64())
    {
        return Err("ai_federation: Bedrock usage.totalTokens must be an integer".to_string());
    }
    let mut openai_message = json!({
        "role": "assistant",
        "content": if text.is_empty() { Value::Null } else { Value::String(text) },
    });
    if !tool_calls.is_empty() {
        openai_message["tool_calls"] = Value::Array(tool_calls);
    }
    let mut normalized = json!({
        "id": format!("chatcmpl-fed-{}", generate_short_id()),
        "object": "chat.completion",
        "created": Utc::now().timestamp(),
        "model": model,
        "choices": [{
            "index": 0,
            "message": openai_message,
            "finish_reason": finish_reason
        }]
    });
    insert_normalized_usage(&mut normalized, input_tokens, output_tokens, total);

    let tokens = TokenCounts {
        prompt_tokens: input_tokens,
        completion_tokens: output_tokens,
        total_tokens: total,
        model: Some(model.to_string()),
    };

    Ok((normalized, tokens))
}

fn normalize_from_cohere(resp: &Value, model: &str) -> Result<(Value, TokenCounts), String> {
    let id = required_non_empty_string(resp, "id", "Cohere response")?;
    let message = resp["message"]
        .as_object()
        .ok_or("ai_federation: Cohere response missing message object")?;
    if message.get("role").and_then(Value::as_str) != Some("assistant") {
        return Err("ai_federation: Cohere response message role must be assistant".to_string());
    }
    let content_blocks = message
        .get("content")
        .and_then(Value::as_array)
        .ok_or("ai_federation: Cohere response message.content must be an array")?;
    let mut text = String::new();
    for (index, block) in content_blocks.iter().enumerate() {
        if block.get("type").and_then(Value::as_str) != Some("text") {
            return Err(format!(
                "ai_federation: Cohere message.content[{index}] has unsupported block type"
            ));
        }
        text.push_str(block.get("text").and_then(Value::as_str).ok_or_else(|| {
            format!("ai_federation: Cohere message.content[{index}] missing text")
        })?);
    }
    let tool_calls = parse_provider_tool_calls(message, 0, "Cohere")?;
    if text.is_empty() && tool_calls.is_empty() {
        return Err(
            "ai_federation: Cohere response has no non-empty text or tool calls".to_string(),
        );
    }

    let native_finish_reason = required_non_empty_string(resp, "finish_reason", "Cohere response")?;
    let has_tool_calls = !tool_calls.is_empty();
    if (native_finish_reason == "TOOL_CALL") != has_tool_calls {
        return Err("ai_federation: Cohere tool calls and finish_reason disagree".to_string());
    }
    let finish_reason = match native_finish_reason {
        "COMPLETE" | "STOP_SEQUENCE" => "stop",
        "MAX_TOKENS" => "length",
        "TOOL_CALL" => "tool_calls",
        "ERROR" | "TIMEOUT" => "content_filter",
        _ => {
            return Err(
                "ai_federation: Cohere response has an unsupported finish_reason".to_string(),
            );
        }
    };

    let (input_tokens, output_tokens) = native_usage_pair(
        resp.get("usage").and_then(|usage| usage.get("tokens")),
        "input_tokens",
        "output_tokens",
        "Cohere",
    )?;
    let total = summed_usage(input_tokens, output_tokens, "Cohere")?;

    let resp_model = match resp.get("model") {
        Some(Value::String(value)) if is_valid_model_identifier(value) => value.as_str(),
        Some(_) => {
            return Err("ai_federation: Cohere response contains an invalid model".to_string());
        }
        None => model,
    };

    let mut openai_message = json!({
        "role": "assistant",
        "content": if text.is_empty() { Value::Null } else { Value::String(text) },
    });
    if !tool_calls.is_empty() {
        openai_message["tool_calls"] = Value::Array(
            tool_calls
                .into_iter()
                .map(|call| {
                    json!({
                        "id": call.id,
                        "type": "function",
                        "function": {
                            "name": call.name,
                            "arguments": call.arguments,
                        }
                    })
                })
                .collect(),
        );
    }
    let mut normalized = json!({
        "id": id,
        "object": "chat.completion",
        "created": Utc::now().timestamp(),
        "model": resp_model,
        "choices": [{
            "index": 0,
            "message": openai_message,
            "finish_reason": finish_reason
        }]
    });
    insert_normalized_usage(&mut normalized, input_tokens, output_tokens, total);

    let tokens = TokenCounts {
        prompt_tokens: input_tokens,
        completion_tokens: output_tokens,
        total_tokens: total,
        model: Some(resp_model.to_string()),
    };

    Ok((normalized, tokens))
}

/// Generate a short random ID for synthetic response IDs.
fn generate_short_id() -> String {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:x}", nanos)
}

// ---------------------------------------------------------------------------
// HTTP execution
// ---------------------------------------------------------------------------

impl AiFederation {
    /// Call a provider with bounded response collection and replay-safety
    /// classification for this non-idempotent POST.
    async fn call_provider(
        &self,
        provider: &ResolvedProvider,
        url: &str,
        extra_headers: Vec<(String, String)>,
        body: &[u8],
        latency_accumulator: &AtomicU64,
    ) -> Result<ProviderResponse, ProviderCallFailure> {
        validate_dispatch_url(url).map_err(|_| ProviderCallFailure {
            kind: ProviderCallFailureKind::PreWire,
            error_class: crate::retry::ErrorClass::DispatchPolicyRejected,
            headers: HashMap::new(),
            circuit_failure: false,
        })?;
        let auth_headers = self
            .build_auth_headers(provider, url, body, latency_accumulator)
            .await
            .map_err(|failure| {
                debug!(
                    provider = %provider.name,
                    error = %failure.message,
                    "ai_federation: provider authentication preparation failed"
                );
                ProviderCallFailure {
                    kind: ProviderCallFailureKind::PreWire,
                    error_class: crate::retry::ErrorClass::RequestError,
                    headers: HashMap::new(),
                    circuit_failure: failure.impact == AuthFailureImpact::ProviderUnavailable,
                }
            })?;

        let mut req = self
            .http_client
            .get()
            .post(url)
            .connect_timeout(provider.connect_timeout)
            .timeout(provider.read_timeout);

        for (k, v) in &auth_headers {
            req = req.header(k.as_str(), v.as_str());
        }
        for (k, v) in &extra_headers {
            req = req.header(k.as_str(), v.as_str());
        }
        req = req.body(Bytes::copy_from_slice(body));

        let resp = self
            .http_client
            .execute_redacted_tracked_classified(
                req,
                "ai_federation",
                redacted_endpoint_for_log(url),
                latency_accumulator,
            )
            .await
            .map_err(|failure| ProviderCallFailure {
                kind: if failure.request_reached_wire {
                    ProviderCallFailureKind::Ambiguous
                } else {
                    ProviderCallFailureKind::PreWire
                },
                error_class: failure.error_class,
                headers: HashMap::new(),
                circuit_failure: failure.error_class
                    != crate::retry::ErrorClass::DispatchPolicyRejected,
            })?;

        let status = resp.status().as_u16();
        let headers = safe_provider_response_headers(resp.headers());
        let body_read_started = std::time::Instant::now();
        let body_result = read_response_body_bounded(resp, provider.max_response_body_bytes).await;
        add_external_io_elapsed(latency_accumulator, body_read_started);
        let resp_body = body_result.map_err(|error| match error {
            BoundedReadError::LimitExceeded { .. } => ProviderCallFailure {
                kind: ProviderCallFailureKind::ResponseTooLarge,
                error_class: crate::retry::ErrorClass::ResponseBodyTooLarge,
                headers: headers.clone(),
                circuit_failure: true,
            },
            BoundedReadError::Stream(error) => ProviderCallFailure {
                kind: ProviderCallFailureKind::Ambiguous,
                error_class: crate::retry::classify_reqwest_error(&error),
                headers: headers.clone(),
                circuit_failure: true,
            },
        })?;

        Ok(ProviderResponse {
            status,
            headers,
            body: resp_body,
        })
    }

    /// Build authentication headers for a provider.
    async fn build_auth_headers(
        &self,
        provider: &ResolvedProvider,
        url: &str,
        payload: &[u8],
        latency_accumulator: &AtomicU64,
    ) -> Result<Vec<(String, String)>, AuthFailure> {
        match &provider.auth {
            AuthMethod::BearerToken { api_key } => Ok(vec![(
                "authorization".to_string(),
                format!("Bearer {api_key}"),
            )]),

            AuthMethod::CustomHeader {
                header_name,
                api_key,
            } => Ok(vec![(header_name.clone(), api_key.clone())]),

            AuthMethod::AwsSigV4 { config } => {
                let now = Utc::now();
                aws_sigv4::sign_request(
                    config,
                    "bedrock",
                    "POST",
                    url,
                    "application/json",
                    payload,
                    &now,
                )
                .map_err(AuthFailure::local)
            }

            AuthMethod::GoogleOAuth2 { cache } => {
                let token = cache
                    .get_token(&self.http_client, latency_accumulator)
                    .await?;
                Ok(vec![(
                    "authorization".to_string(),
                    format!("Bearer {token}"),
                )])
            }
        }
    }
}

fn validate_dispatch_url(url: &str) -> Result<(), String> {
    let parsed = Url::parse(url)
        .map_err(|_| "ai_federation: rendered provider endpoint is invalid".to_string())?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err("ai_federation: rendered provider endpoint violates URL policy".to_string());
    }
    Ok(())
}

fn safe_provider_response_headers(headers: &reqwest::header::HeaderMap) -> HashMap<String, String> {
    let mut safe = HashMap::new();
    for (name, value) in headers {
        let name = name.as_str();
        if !is_safe_provider_response_header(name) {
            continue;
        }
        if let Ok(value) = value.to_str() {
            if value.len() > MAX_FORWARDED_PROVIDER_HEADER_VALUE_BYTES {
                continue;
            }
            // These allowlisted fields are singular protocol/correlation
            // metadata. Keep the first value and drop duplicates instead of
            // creating an ambiguous comma-folded Retry-After or request ID.
            if safe.len() < MAX_FORWARDED_PROVIDER_HEADERS {
                safe.entry(name.to_string())
                    .or_insert_with(|| value.to_string());
            }
        }
    }
    safe
}

fn is_safe_provider_response_header(name: &str) -> bool {
    matches!(
        name,
        "retry-after"
            | "request-id"
            | "x-request-id"
            | "x-ms-request-id"
            | "x-goog-request-id"
            | "anthropic-request-id"
            | "openai-request-id"
    ) || name.starts_with("x-ratelimit-")
        || name.starts_with("ratelimit-")
        || name.starts_with("anthropic-ratelimit-")
}

// ---------------------------------------------------------------------------
// Plugin trait implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl Plugin for AiFederation {
    fn name(&self) -> &str {
        "ai_federation"
    }

    fn priority(&self) -> u16 {
        super::priority::AI_FEDERATION
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_ONLY_PROTOCOLS
    }

    fn requires_request_body_buffering(&self) -> bool {
        true
    }

    /// Keep the body-finalization boundary ahead of backend dispatch. Provider
    /// I/O itself runs in `dispatch_finalized_request_egress`, after the entire
    /// final request-body hook pass, so an operator priority override cannot
    /// move it ahead of WAF/OpenAPI/body/size policy (GHSA-4vr5-4wm3-x5xv).
    fn requires_final_request_body_before_backend_dispatch(&self) -> bool {
        true
    }

    fn dispatches_finalized_request_egress(&self) -> bool {
        true
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        if ctx.method != "POST" {
            return false;
        }
        let Some(content_type) = ctx.headers.get("content-type") else {
            return false;
        };
        is_json_content_type(content_type)
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        let mut hostnames = Vec::new();
        for provider in &self.providers {
            // Use a representative model name for URL building
            let model = provider.default_model.as_deref().unwrap_or("placeholder");
            let url = build_provider_url(provider, model);
            if let Ok(parsed) = Url::parse(&url)
                && let Some(host) = normalized_url_hostname(&parsed)
            {
                hostnames.push(host);
            }
        }
        hostnames
    }

    async fn dispatch_finalized_request_egress(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
        body: &[u8],
        _backend_header_overlay: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Coordinate with `ai_stream_router` (priority 2984, runs first). When it
        // claims a streaming request, or explicitly passes one through because
        // the operator disabled fail-closed missing/unmatched-model behavior,
        // `ai_federation` must not re-inspect or reject that same `stream:true`
        // request.
        //
        // A successful claim is read from the PRIVATE typed claim, never from
        // the public `ai_stream_router_claimed` metadata key: that key is
        // observability/backward coordination only and a later plugin can
        // delete or rewrite it, which would make this federation path
        // re-inspect and re-dispatch a request already bound to a third-party
        // provider (`GHSA-xhp5-hqj8-3mwg`). Intentional pass-through is a
        // genuinely UNCLAIMED request, so it still coordinates via metadata.
        if ctx.has_ai_stream_router_claim()
            || ctx
                .metadata
                .get("ai_stream_router_pass_through")
                .map(String::as_str)
                == Some("true")
        {
            return PluginResult::Continue;
        }

        // Only handle POST requests with JSON content-type
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

        // `request_deduplication` may already own an in-flight key because its
        // before-proxy hook runs earlier. Until provider I/O commits, every
        // federation rejection is safe to retry and must release that ownership
        // from the final committed-response hook. A committed or ambiguous
        // provider call replaces this marker with the non-replayable external
        // operation marker below.
        ctx.metadata.insert(
            RELEASE_INFLIGHT_ON_COMMIT_METADATA_KEY.to_string(),
            "true".to_string(),
        );

        // Provider dispatch happens only after the complete final-body hook pass
        // so decompression, request transforms, and every final request policy
        // inspect and accept the same representation that leaves the gateway.
        // Keeping this out of `on_final_request_body_with_context` is
        // load-bearing: `priority_override` may reorder that hook pass, while
        // the finalized-egress phase is an unconditional later boundary.
        let body_str = match std::str::from_utf8(body) {
            Ok(value) if !value.is_empty() => value,
            _ => {
                if self.fail_on_missing_model {
                    debug!("ai_federation: rejecting JSON POST without a final UTF-8 request body");
                    return self.openai_error_response(
                        400,
                        "Request body is required and must be UTF-8 JSON for ai_federation model routing",
                        "invalid_request_error",
                        None,
                        Some("missing_request_body"),
                    );
                }
                debug!(
                    "ai_federation: final body is empty or non-UTF-8, passing through by explicit opt-in"
                );
                ctx.metadata.remove(RELEASE_INFLIGHT_ON_COMMIT_METADATA_KEY);
                return PluginResult::Continue;
            }
        };

        let openai_body: Value = match serde_json::from_str(body_str) {
            Ok(v) => v,
            Err(e) => {
                if self.fail_on_missing_model {
                    debug!("ai_federation: rejecting request body that is not valid JSON: {e}");
                    return self.openai_error_response(
                        400,
                        "Request body is not valid JSON",
                        "invalid_request_error",
                        None,
                        Some("invalid_json"),
                    );
                }
                debug!(
                    "ai_federation: request body is not valid JSON, passing through by explicit opt-in: {e}"
                );
                ctx.metadata.remove(RELEASE_INFLIGHT_ON_COMMIT_METADATA_KEY);
                return PluginResult::Continue;
            }
        };

        // Extract model from the standard "model" field
        let model = match openai_body.get("model") {
            Some(Value::String(m)) => m.to_string(),
            Some(_) => {
                if self.fail_on_missing_model {
                    debug!("ai_federation: rejecting request with non-string 'model' field");
                    return self.openai_error_response(
                        400,
                        "Invalid 'model' field: expected a string",
                        "invalid_request_error",
                        Some("model"),
                        Some("invalid_model"),
                    );
                }
                debug!(
                    "ai_federation: request has non-string 'model' field, passing through by explicit opt-in"
                );
                ctx.metadata.remove(RELEASE_INFLIGHT_ON_COMMIT_METADATA_KEY);
                return PluginResult::Continue;
            }
            None => {
                if self.fail_on_missing_model {
                    debug!("ai_federation: rejecting request missing 'model' field");
                    return self.openai_error_response(
                        400,
                        "Missing required 'model' field",
                        "invalid_request_error",
                        Some("model"),
                        Some("missing_model"),
                    );
                }
                debug!(
                    "ai_federation: request missing 'model' field, passing through by explicit opt-in"
                );
                ctx.metadata.remove(RELEASE_INFLIGHT_ON_COMMIT_METADATA_KEY);
                return PluginResult::Continue;
            }
        };
        if !is_valid_model_identifier(&model) {
            return self.openai_error_response(
                400,
                "Invalid 'model' field: use a bounded provider model identifier without URL query, fragment, userinfo, traversal, whitespace, or control characters",
                "invalid_request_error",
                Some("model"),
                Some("invalid_model"),
            );
        }

        // Find matching providers
        let matching_providers = self.find_providers_for_model(&model);
        if matching_providers.is_empty() {
            if self.fail_on_no_matching_provider {
                debug!(
                    model = %model,
                    "ai_federation: rejecting request because no provider matches model"
                );
                let echoed_model = truncate_model_for_error(&model);
                return self.openai_error_response(
                    404,
                    &format!("No ai_federation provider is configured for model '{echoed_model}'"),
                    "invalid_request_error",
                    Some("model"),
                    Some("model_not_found"),
                );
            }
            debug!(
                model = %model,
                "ai_federation: no provider matches model, passing through by explicit opt-in"
            );
            ctx.metadata.remove(RELEASE_INFLIGHT_ON_COMMIT_METADATA_KEY);
            return PluginResult::Continue;
        }

        // Streaming is not supported by the terminate-and-respond design. We
        // only check after model routing has found a provider; missing models
        // and unmatched models have already followed the configured fail-closed
        // or explicit pass-through policy. Reject with a clear, OpenAI-shaped
        // error rather than forwarding `stream: true` to the provider — which
        // would either yield an SSE body that fails JSON normalization (opaque
        // 502) or silently degrade to a single buffered object for the
        // translating providers. See finding #11.
        if request_wants_streaming(&openai_body) {
            debug!(
                model = %model,
                "ai_federation: rejecting streaming request — streaming responses are not supported"
            );
            return self.openai_error_response(
                501,
                "Streaming responses (\"stream\": true) are not supported by ai_federation",
                "invalid_request_error",
                Some("stream"),
                Some("streaming_not_supported"),
            );
        }

        let deferred_non_text_validation_error =
            match validate_openai_request(&openai_body, false) {
                Ok(()) => None,
                Err(strict_message) => {
                    if let Err(message) = validate_openai_request(&openai_body, true) {
                        return self.openai_error_response(
                            400,
                            &message,
                            "invalid_request_error",
                            None,
                            Some("invalid_request"),
                        );
                    }
                    if !matching_providers.iter().any(|provider| {
                        provider.multimodal_mode == MultimodalMode::TextOnlyWithWarning
                    }) {
                        return self.openai_error_response(
                            400,
                            &strict_message,
                            "invalid_request_error",
                            None,
                            Some("invalid_request"),
                        );
                    }
                    Some(strict_message)
                }
            };

        let _request_permit = match self.request_slots.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                return self.openai_error_response(
                    503,
                    "ai_federation provider concurrency limit reached",
                    "server_error",
                    None,
                    Some("provider_concurrency_exhausted"),
                );
            }
        };

        let multimodal_usage = analyze_multimodal_usage(&openai_body);
        let mut last_client_rejection: Option<String> = None;
        let mut last_failure_result: Option<PluginResult> = None;
        let mut attempted_provider = false;
        let mut skipped_open_circuit = false;

        for (idx, provider) in matching_providers.iter().enumerate() {
            let has_later_provider = matching_providers[idx + 1..].iter().any(|candidate| {
                candidate
                    .circuit
                    .as_ref()
                    .is_none_or(ProviderCircuit::may_admit)
            });
            let admission = provider
                .circuit
                .as_ref()
                .map(ProviderCircuit::admit)
                .unwrap_or(CircuitAdmission::Closed);
            let mut half_open_probe_guard = match (provider.circuit.as_ref(), admission) {
                (Some(circuit), CircuitAdmission::HalfOpenProbe) => {
                    Some(HalfOpenProbeGuard::new(circuit))
                }
                _ => None,
            };
            if admission == CircuitAdmission::Open {
                skipped_open_circuit = true;
                super::prometheus_metrics::global_registry().record_ai_federation_open_skip();
                let skips = ctx
                    .metadata
                    .get("ai_federation_circuit_open_skips")
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(0)
                    .saturating_add(1);
                ctx.metadata.insert(
                    "ai_federation_circuit_open_skips".to_string(),
                    skips.to_string(),
                );
                ctx.metadata.insert(
                    "ai_federation_circuit_last_provider".to_string(),
                    provider.name.clone(),
                );
                ctx.metadata.insert(
                    "ai_federation_circuit_last_state".to_string(),
                    "open".to_string(),
                );
                debug!(
                    provider = %provider.name,
                    "ai_federation: skipping provider with open circuit"
                );
                if !self.fallback_enabled {
                    return self.openai_error_response(
                        503,
                        "The selected AI provider circuit is open and fallback is disabled",
                        "server_error",
                        None,
                        Some("provider_circuit_open"),
                    );
                }
                continue;
            }
            if provider.multimodal_mode != MultimodalMode::TextOnlyWithWarning
                && let Some(message) = &deferred_non_text_validation_error
            {
                if let Some(guard) = half_open_probe_guard.as_mut() {
                    guard.release();
                }
                last_client_rejection = Some(message.clone());
                if self.fallback_enabled && has_later_provider {
                    continue;
                }
                break;
            }
            if provider.circuit.is_some() {
                ctx.metadata.insert(
                    "ai_federation_circuit_last_provider".to_string(),
                    provider.name.clone(),
                );
                ctx.metadata.insert(
                    "ai_federation_circuit_last_state".to_string(),
                    match admission {
                        CircuitAdmission::Closed => "closed",
                        CircuitAdmission::HalfOpenProbe => "half_open_probe",
                        CircuitAdmission::Open => "open",
                    }
                    .to_string(),
                );
                if admission == CircuitAdmission::HalfOpenProbe {
                    let probes = ctx
                        .metadata
                        .get("ai_federation_circuit_half_open_probes")
                        .and_then(|value| value.parse::<u64>().ok())
                        .unwrap_or(0)
                        .saturating_add(1);
                    ctx.metadata.insert(
                        "ai_federation_circuit_half_open_probes".to_string(),
                        probes.to_string(),
                    );
                    info!(
                        provider = %provider.name,
                        "ai_federation: provider circuit admitted a half-open probe"
                    );
                }
            }
            let resolved_model = Self::resolve_model(provider, &model);

            // Defense against URL injection via the user-controlled `model`
            // field for providers that embed the resolved model directly in
            // the URL path (Gemini, Vertex AI, Bedrock). Without this, a
            // request with `"model": "gemini-../foo:streamGenerateContent"`
            // and a permissive `model_patterns: ["gemini-*"]` (or no
            // patterns at all — empty == catch-all) reaches
            // `build_provider_url` with an attacker-controlled path
            // component on the operator's API key. Reject early — do not
            // fall through to the next provider, since the dangerous
            // payload would just hit a different provider's URL.
            if provider_embeds_model_in_url(provider.provider_type)
                && !is_valid_url_model_component(&resolved_model)
            {
                if let Some(guard) = half_open_probe_guard.as_mut() {
                    guard.release();
                }
                warn!(
                    provider = %provider.name,
                    provider_type = %provider.provider_type.as_str(),
                    "ai_federation: rejected request — resolved model contains characters not permitted in URL path"
                );
                return self.openai_error_response(
                    400,
                    "Invalid 'model' field: must contain only alphanumeric characters, dot, hyphen, underscore, or colon",
                    "invalid_request_error",
                    Some("model"),
                    Some("invalid_model"),
                );
            }

            if let Err(message) =
                validate_multimodal_policy(provider, &openai_body, &multimodal_usage)
            {
                warn!(
                    provider = %provider.name,
                    provider_type = %provider.provider_type.as_str(),
                    multimodal_mode = %provider.multimodal_mode.as_str(),
                    non_text_parts = multimodal_usage.non_text_parts,
                    "ai_federation: provider cannot serve multimodal request, trying fallback"
                );
                if let Some(guard) = half_open_probe_guard.as_mut() {
                    guard.release();
                }
                last_client_rejection = Some(message);
                if self.fallback_enabled && has_later_provider {
                    continue;
                }
                break;
            }

            if provider.multimodal_mode == MultimodalMode::TextOnlyWithWarning
                && !multimodal_usage.is_empty()
            {
                // Per-attempt warning only. The `ai_federation_multimodal_*`
                // audit/chargeback metadata is written at COMMIT time (next to
                // `write_token_metadata`, once this provider actually serves the
                // request) — not here. If this provider later fails over to a
                // `translate`-mode provider that preserves the image, writing the
                // "dropped" metadata now would misreport the serving provider.
                warn!(
                    provider = %provider.name,
                    provider_type = %provider.provider_type.as_str(),
                    non_text_parts = multimodal_usage.non_text_parts,
                    "ai_federation: dropping non-text multimodal content by explicit text_only_with_warning policy"
                );
            }

            let translated = match translate_request(provider, &openai_body, &resolved_model) {
                Ok(t) => t,
                Err(e) => {
                    warn!(
                        provider = %provider.name,
                        "ai_federation: request translation failed"
                    );
                    if let Some(guard) = half_open_probe_guard.as_mut() {
                        guard.release();
                    }
                    last_client_rejection = Some(e);
                    if self.fallback_enabled && has_later_provider {
                        continue;
                    }
                    break;
                }
            };

            let (url, extra_headers, body_bytes) = translated;

            debug!(
                provider = %provider.name,
                provider_type = %provider.provider_type.as_str(),
                model = %resolved_model,
                endpoint = redacted_endpoint_for_log(&url),
                "ai_federation: calling provider"
            );

            attempted_provider = true;
            let response = match self
                .call_provider(
                    provider,
                    &url,
                    extra_headers,
                    &body_bytes,
                    ctx.plugin_http_call_ns.as_ref(),
                )
                .await
            {
                Ok(response) => {
                    // A provider returned response headers, so the billable
                    // operation has a committed outcome even if its body or
                    // schema later fails. Request deduplication consumes this
                    // internal marker only after the final client-visible
                    // response is committed and publishes a non-replayable
                    // tombstone for an idempotency-key retry.
                    ctx.metadata.remove(RELEASE_INFLIGHT_ON_COMMIT_METADATA_KEY);
                    ctx.metadata.insert(
                        EXTERNAL_OPERATION_COMPLETED_METADATA_KEY.to_string(),
                        "true".to_string(),
                    );
                    response
                }
                Err(failure) => {
                    if failure.kind != ProviderCallFailureKind::PreWire {
                        // Ambiguous writes may have completed remotely, and an
                        // oversized body proves that response headers arrived.
                        // Both must suppress an independent client retry under
                        // the same idempotency key even when provider fallback
                        // itself is disabled.
                        ctx.metadata.remove(RELEASE_INFLIGHT_ON_COMMIT_METADATA_KEY);
                        ctx.metadata.insert(
                            EXTERNAL_OPERATION_COMPLETED_METADATA_KEY.to_string(),
                            "true".to_string(),
                        );
                    }
                    if let Some(circuit) = &provider.circuit {
                        if failure.circuit_failure {
                            circuit.record_failure(&provider.name, admission);
                            if let Some(guard) = half_open_probe_guard.as_mut() {
                                guard.resolve();
                            }
                        } else if let Some(guard) = half_open_probe_guard.as_mut() {
                            guard.release();
                        }
                    }
                    warn!(
                        provider = %provider.name,
                        error_class = failure.error_class.as_str(),
                        failure_kind = ?failure.kind,
                        "ai_federation: provider request failed"
                    );
                    if failure.kind == ProviderCallFailureKind::ResponseTooLarge {
                        return self.openai_error_response_with_headers(
                            502,
                            "Provider response exceeded the configured size limit",
                            "server_error",
                            None,
                            Some("provider_response_too_large"),
                            failure.headers,
                        );
                    }
                    let fallback_allowed = self.fallback_enabled
                        && has_later_provider
                        && match failure.kind {
                            ProviderCallFailureKind::PreWire => self.fallback_on_network_errors,
                            ProviderCallFailureKind::Ambiguous => self.fallback_on_ambiguous_errors,
                            ProviderCallFailureKind::ResponseTooLarge => false,
                        };
                    if fallback_allowed {
                        let (message, code) = if failure.kind == ProviderCallFailureKind::Ambiguous
                        {
                            (
                                "Provider request failed after the outcome became ambiguous; automatic replay was explicitly enabled",
                                "ambiguous_provider_outcome",
                            )
                        } else {
                            (
                                "Provider request failed before a response was received",
                                "provider_request_failed",
                            )
                        };
                        last_failure_result = Some(self.openai_error_response_with_headers(
                            502,
                            message,
                            "server_error",
                            None,
                            Some(code),
                            failure.headers.clone(),
                        ));
                        continue;
                    }
                    let (message, code) = if failure.kind == ProviderCallFailureKind::Ambiguous {
                        (
                            "Provider request failed after the outcome became ambiguous; automatic replay was suppressed",
                            "ambiguous_provider_outcome",
                        )
                    } else {
                        (
                            "Provider request failed before a response was received",
                            "provider_request_failed",
                        )
                    };
                    return self.openai_error_response_with_headers(
                        502,
                        message,
                        "server_error",
                        None,
                        Some(code),
                        failure.headers,
                    );
                }
            };

            let status = response.status;
            // Record provider provenance and its ORIGINAL status before
            // normalization or bounded serialization can fail. In particular,
            // `ai_rate_limiter` must treat a usage-less provider 2xx followed by
            // a synthetic 502 as an unmetered provider success, not as a free
            // gateway rejection that releases the pre-reservation.
            ctx.metadata
                .insert("ai_federation_provider".to_string(), provider.name.clone());
            ctx.metadata
                .insert("ai_federation_status".to_string(), status.to_string());
            if self.fallback_status_codes.contains(&status) {
                if let Some(circuit) = &provider.circuit {
                    circuit.record_failure(&provider.name, admission);
                    if let Some(guard) = half_open_probe_guard.as_mut() {
                        guard.resolve();
                    }
                }
                if self.fallback_enabled && has_later_provider {
                    warn!(
                        provider = %provider.name,
                        status,
                        "ai_federation: provider returned fallback-eligible status"
                    );
                    last_failure_result = Some(self.openai_error_response_with_headers(
                        status,
                        &format!("Upstream provider returned status {status}"),
                        "upstream_error",
                        None,
                        Some("upstream_error"),
                        response.headers.clone(),
                    ));
                    continue;
                }
            } else if (300..400).contains(&status) {
                if let Some(circuit) = &provider.circuit {
                    circuit.record_failure(&provider.name, admission);
                    if let Some(guard) = half_open_probe_guard.as_mut() {
                        guard.resolve();
                    }
                }
                if self.fallback_enabled && self.fallback_on_protocol_errors && has_later_provider {
                    last_failure_result = Some(self.openai_error_response_with_headers(
                        status,
                        &format!("Upstream provider returned status {status}"),
                        "upstream_error",
                        None,
                        Some("upstream_error"),
                        response.headers.clone(),
                    ));
                    continue;
                }
            }

            match normalize_response(
                provider.provider_type,
                status,
                &response.body,
                &resolved_model,
            ) {
                Ok((normalized, token_counts)) => {
                    if let Some(circuit) = &provider.circuit
                        && !self.fallback_status_codes.contains(&status)
                        && !(300..400).contains(&status)
                    {
                        circuit.record_success(&provider.name, admission);
                        if let Some(guard) = half_open_probe_guard.as_mut() {
                            guard.resolve();
                        }
                    }
                    if (200..300).contains(&status) {
                        self.write_token_metadata(
                            ctx,
                            &token_counts,
                            provider.provider_type,
                            &provider.name,
                            &resolved_model,
                        );
                    }

                    // Record the multimodal-drop audit/chargeback metadata only
                    // now that THIS provider has committed to serving the
                    // request. Writing it pre-dispatch would leave stale "parts
                    // dropped" keys (naming the wrong provider) in the
                    // transaction log if a `text_only_with_warning` provider
                    // failed over to a later `translate` provider that preserved
                    // the image.
                    if (200..300).contains(&status)
                        && provider.multimodal_mode == MultimodalMode::TextOnlyWithWarning
                        && !multimodal_usage.is_empty()
                    {
                        self.write_multimodal_text_only_metadata(ctx, provider, &multimodal_usage);
                    }

                    info!(
                        provider = %provider.name,
                        model = %resolved_model,
                        status = %status,
                        total_tokens = ?token_counts.total_tokens,
                        "ai_federation: request completed"
                    );

                    let bytes_received = match serialize_json_bounded(
                        &normalized,
                        provider.max_response_body_bytes,
                    ) {
                        Ok(b) => b,
                        Err(BoundedJsonSerializationError::LimitExceeded) => {
                            warn!(
                                provider = %provider.name,
                                "ai_federation: normalized provider response exceeded configured size limit"
                            );
                            return self.openai_error_response_with_headers(
                                502,
                                "Normalized provider response exceeded the configured size limit",
                                "server_error",
                                None,
                                Some("provider_response_too_large"),
                                response.headers,
                            );
                        }
                        Err(BoundedJsonSerializationError::Serialization) => {
                            warn!(
                                provider = %provider.name,
                                error_class = "serialization_error",
                                "ai_federation: failed to serialize normalized response"
                            );
                            return self.openai_error_response_with_headers(
                                502,
                                "Provider response serialization failed",
                                "server_error",
                                None,
                                Some("response_serialization_failed"),
                                response.headers,
                            );
                        }
                    };
                    let mut resp_headers = response.headers;
                    resp_headers.insert("content-type".to_string(), "application/json".to_string());

                    return PluginResult::RejectBinary {
                        status_code: status,
                        body: Bytes::from(bytes_received),
                        headers: resp_headers,
                    };
                }
                Err(e) => {
                    if let Some(circuit) = &provider.circuit {
                        circuit.record_failure(&provider.name, admission);
                        if let Some(guard) = half_open_probe_guard.as_mut() {
                            guard.resolve();
                        }
                    }
                    warn!(
                        provider = %provider.name,
                        error = %e,
                        "ai_federation: response normalization failed"
                    );
                    if self.fallback_enabled
                        && self.fallback_on_protocol_errors
                        && has_later_provider
                    {
                        last_failure_result = Some(self.openai_error_response_with_headers(
                            502,
                            "Provider returned a malformed success response",
                            "server_error",
                            None,
                            Some("response_normalization_failed"),
                            response.headers,
                        ));
                        continue;
                    }
                    return self.openai_error_response_with_headers(
                        502,
                        "Provider returned a malformed success response",
                        "server_error",
                        None,
                        Some("response_normalization_failed"),
                        response.headers,
                    );
                }
            }
        }

        if let Some(result) = last_failure_result {
            result
        } else if !attempted_provider && let Some(message) = last_client_rejection {
            self.openai_error_response(
                400,
                &message,
                "invalid_request_error",
                None,
                Some("provider_translation_failed"),
            )
        } else if !attempted_provider && skipped_open_circuit {
            self.openai_error_response(
                503,
                "All matching AI provider circuits are open",
                "server_error",
                None,
                Some("provider_circuit_open"),
            )
        } else {
            self.openai_error_response(
                502,
                "All matching AI providers failed",
                "server_error",
                None,
                Some("provider_error"),
            )
        }
    }
}

impl AiFederation {
    /// Write token metadata to ctx.metadata using the same keys as ai_token_metrics.
    fn write_token_metadata(
        &self,
        ctx: &mut RequestContext,
        tokens: &TokenCounts,
        provider_type: ProviderType,
        provider_name: &str,
        model: &str,
    ) {
        if let Some(total) = tokens.total_tokens {
            ctx.metadata
                .insert("ai_total_tokens".to_string(), total.to_string());
        }
        if let Some(prompt) = tokens.prompt_tokens {
            ctx.metadata
                .insert("ai_prompt_tokens".to_string(), prompt.to_string());
        }
        if let Some(completion) = tokens.completion_tokens {
            ctx.metadata
                .insert("ai_completion_tokens".to_string(), completion.to_string());
        }
        ctx.metadata.insert(
            "ai_model".to_string(),
            tokens.model.clone().unwrap_or_else(|| model.to_string()),
        );
        ctx.metadata.insert(
            "ai_provider".to_string(),
            provider_type.as_str().to_string(),
        );
        ctx.metadata.insert(
            "ai_federation_provider".to_string(),
            provider_name.to_string(),
        );
        ctx.stage_ai_usage_export(AiUsageExport {
            prefix: Arc::from("ai"),
            provider: provider_type.as_str(),
            prompt_tokens: tokens.prompt_tokens,
            completion_tokens: tokens.completion_tokens,
            total_tokens: tokens.total_tokens,
            cost: None,
        });
    }

    fn write_multimodal_text_only_metadata(
        &self,
        ctx: &mut RequestContext,
        provider: &ResolvedProvider,
        usage: &MultimodalUsage,
    ) {
        ctx.metadata.insert(
            "ai_federation_multimodal_mode".to_string(),
            provider.multimodal_mode.as_str().to_string(),
        );
        ctx.metadata.insert(
            "ai_federation_multimodal_dropped_parts".to_string(),
            usage.non_text_parts.to_string(),
        );
        ctx.metadata.insert(
            "ai_federation_multimodal_dropped_types".to_string(),
            usage.types_csv(),
        );
        ctx.metadata.insert(
            "ai_federation_multimodal_dropped_roles".to_string(),
            usage.roles_csv(),
        );
        ctx.metadata.insert(
            "ai_federation_multimodal_provider".to_string(),
            provider.name.clone(),
        );
    }

    fn openai_error_response(
        &self,
        status: u16,
        message: &str,
        error_type: &str,
        param: Option<&str>,
        code: Option<&str>,
    ) -> PluginResult {
        self.json_reject_response(status, openai_error_body(message, error_type, param, code))
    }

    fn openai_error_response_with_headers(
        &self,
        status: u16,
        message: &str,
        error_type: &str,
        param: Option<&str>,
        code: Option<&str>,
        headers: HashMap<String, String>,
    ) -> PluginResult {
        self.json_reject_response_with_headers(
            status,
            openai_error_body(message, error_type, param, code),
            headers,
        )
    }

    fn json_reject_response(&self, status: u16, body: Value) -> PluginResult {
        self.json_reject_response_with_headers(status, body, HashMap::new())
    }

    fn json_reject_response_with_headers(
        &self,
        status: u16,
        body: Value,
        mut headers: HashMap<String, String>,
    ) -> PluginResult {
        // Serializing a `Value` built entirely from primitives cannot actually
        // fail, so this fallback is unreachable defensive code. If it ever does
        // fire we override the caller's status to 500 so the HTTP status line
        // stays consistent with the `server_error` / `internal_error` body.
        let (status_code, response_body) = match serde_json::to_vec(&body) {
            Ok(body) => (status, Bytes::from(body)),
            Err(e) => {
                warn!(
                    error = %e,
                    "ai_federation: failed to serialize JSON error response"
                );
                (
                    500,
                    Bytes::from_static(
                        br#"{"error":{"message":"Failed to serialize error response","type":"server_error","param":null,"code":"internal_error"}}"#,
                    ),
                )
            }
        };
        headers.insert("content-type".to_string(), "application/json".to_string());
        PluginResult::RejectBinary {
            status_code,
            body: response_body,
            headers,
        }
    }
}

// ---------------------------------------------------------------------------
// Public test helpers
// ---------------------------------------------------------------------------

/// Test helpers — exposed for unit tests.
#[doc(hidden)]
#[allow(dead_code)]
pub mod test_helpers {
    use super::*;

    /// Close the request semaphore so external regression tests can exercise
    /// the deterministic pre-I/O concurrency rejection path.
    pub fn close_request_slots_for_test(plugin: &AiFederation) {
        plugin.request_slots.close();
    }

    /// Resource-bound constants used by external runtime/schema parity tests.
    pub fn resource_bounds_for_test() -> (usize, usize, usize, usize) {
        (
            DEFAULT_MAX_PROVIDER_RESPONSE_BYTES,
            MAX_PROVIDER_RESPONSE_BYTES,
            MAX_TRANSLATED_REQUEST_BYTES,
            MAX_OAUTH_RESPONSE_BYTES,
        )
    }

    /// Resolved response bound for a configured provider.
    pub fn provider_response_limit_for_test(plugin: &AiFederation, index: usize) -> Option<usize> {
        plugin
            .providers
            .get(index)
            .map(|provider| provider.max_response_body_bytes)
    }

    /// Exercise the real Vertex token refresh path against a test-controlled
    /// endpoint. Production construction still pins token_uri to Google; this
    /// helper only substitutes the first-hop endpoint after validating the
    /// supplied service-account key.
    pub async fn vertex_oauth_exchange_for_test(
        service_account_json: String,
        token_uri: String,
        http_client: PluginHttpClient,
    ) -> Result<String, (String, bool)> {
        let mut cache =
            OAuth2Cache::new(service_account_json).map_err(|message| (message, false))?;
        cache.token_uri = token_uri;
        let latency = AtomicU64::new(0);
        cache
            .get_token(&http_client, &latency)
            .await
            .map_err(|failure| {
                (
                    failure.message,
                    failure.impact == AuthFailureImpact::ProviderUnavailable,
                )
            })
    }

    /// Force a post-construction local JWT key failure to verify that local
    /// auth-build errors stay provider-circuit neutral.
    pub async fn vertex_oauth_local_signing_failure_for_test(
        service_account_json: String,
        http_client: PluginHttpClient,
    ) -> Result<String, (String, bool)> {
        let mut cache =
            OAuth2Cache::new(service_account_json).map_err(|message| (message, false))?;
        cache.private_key_pem = "invalid-test-key".to_string();
        let latency = AtomicU64::new(0);
        cache
            .get_token(&http_client, &latency)
            .await
            .map_err(|failure| {
                (
                    failure.message,
                    failure.impact == AuthFailureImpact::ProviderUnavailable,
                )
            })
    }

    /// Lock the SigV4 classification: signer/build errors are local and must
    /// never count as evidence that the remote provider is unavailable.
    pub fn sigv4_local_failure_is_circuit_neutral_for_test() -> bool {
        let config = aws_sigv4::AwsSigV4Config {
            region: "us-east-1".to_string(),
            access_key_id: "test-access-key".to_string(),
            secret_access_key: "test-secret-key".to_string(),
            session_token: None,
        };
        let result = aws_sigv4::sign_request(
            &config,
            "bedrock",
            "POST",
            "not a valid URL",
            "application/json",
            b"{}",
            &Utc::now(),
        )
        .map_err(AuthFailure::local);
        matches!(
            result,
            Err(AuthFailure {
                impact: AuthFailureImpact::CircuitNeutral,
                ..
            })
        )
    }

    /// Expose glob matching for tests.
    pub fn glob_match(pattern: &str, input: &str) -> bool {
        simple_glob_match(pattern, input)
    }

    /// Expose the URL-path-component validator for tests.
    pub fn is_valid_url_model_component(model: &str) -> bool {
        super::is_valid_url_model_component(model)
    }

    /// Expose the URL-embedding provider classifier for tests.
    pub fn provider_embeds_model_in_url(provider_type: &str) -> Result<bool, String> {
        let pt = ProviderType::from_str(provider_type)?;
        Ok(super::provider_embeds_model_in_url(pt))
    }

    /// Expose the multimodal content-flattening helper for tests.
    pub fn flatten_openai_message_text(content: &Value) -> String {
        super::flatten_openai_message_text(content)
    }

    /// Expose the streaming-request detector for tests.
    pub fn request_wants_streaming(openai_body: &Value) -> bool {
        super::request_wants_streaming(openai_body)
    }

    /// Expose bounded multimodal usage rendering for security regression tests.
    pub fn multimodal_usage_csv_for_test(openai_body: &Value) -> (String, String) {
        let usage = super::analyze_multimodal_usage(openai_body);
        (usage.types_csv(), usage.roles_csv())
    }

    /// Maximum characters of the echoed `model` reflected in no-match errors.
    pub const MAX_ECHOED_MODEL_CHARS: usize = super::MAX_ECHOED_MODEL_CHARS;

    /// Expose the no-match `model` echo bounding helper for tests.
    pub fn truncate_model_for_error(model: &str) -> String {
        super::truncate_model_for_error(model)
    }

    /// Expose request translation for tests.
    pub fn translate_request_test(
        provider_type: &str,
        openai_body: &Value,
        model: &str,
        provider_config: &Value,
    ) -> Result<TranslatedRequest, String> {
        let pt = ProviderType::from_str(provider_type)?;
        let base_url = provider_config["base_url"].as_str().map(String::from);
        let azure_resource = provider_config["azure_resource"].as_str().map(String::from);
        let azure_deployment = provider_config["azure_deployment"]
            .as_str()
            .map(String::from);
        let azure_api_version = provider_config["azure_api_version"]
            .as_str()
            .unwrap_or("2024-06-01")
            .to_string();
        let google_project_id = provider_config["google_project_id"]
            .as_str()
            .map(String::from);
        let google_region = provider_config["google_region"].as_str().map(String::from);
        let aws_region = provider_config["aws_region"].as_str().map(String::from);
        let multimodal_mode = match provider_config["multimodal_mode"].as_str() {
            Some(mode) => MultimodalMode::from_str(mode, "test")?,
            None => MultimodalMode::default_for_provider(pt),
        };

        let url_template = build_url_template(
            pt,
            base_url.as_deref(),
            azure_resource.as_deref(),
            azure_deployment.as_deref(),
            &azure_api_version,
            google_region.as_deref(),
            google_project_id.as_deref(),
            aws_region.as_deref(),
        )?;

        let provider = ResolvedProvider {
            name: "test".to_string(),
            provider_type: pt,
            auth: AuthMethod::BearerToken {
                api_key: "test-key".to_string(),
            },
            priority: 1,
            model_patterns: Vec::new(),
            model_mapping: HashMap::new(),
            default_model: None,
            multimodal_mode,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(60),
            max_response_body_bytes: DEFAULT_MAX_PROVIDER_RESPONSE_BYTES,
            circuit: None,
            base_url,
            url_template,
        };
        translate_request(&provider, openai_body, model)
    }

    /// Expose the multimodal `translate`-mode policy gate for tests.
    ///
    /// This is the single source of the HTTP `400` returned for unsupported
    /// multimodal parts (e.g. Bedrock with a non-image / unsupported image
    /// format, or Gemini/Vertex with a remote HTTP(S) image URL). It runs
    /// before any provider is dialed.
    pub fn validate_multimodal_translate_support_test(
        provider_type: &str,
        openai_body: &Value,
    ) -> Result<(), String> {
        let pt = ProviderType::from_str(provider_type)?;
        let provider = ResolvedProvider {
            name: "test".to_string(),
            provider_type: pt,
            auth: AuthMethod::BearerToken {
                api_key: "test-key".to_string(),
            },
            priority: 1,
            model_patterns: Vec::new(),
            model_mapping: HashMap::new(),
            default_model: None,
            multimodal_mode: MultimodalMode::Translate,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(60),
            max_response_body_bytes: DEFAULT_MAX_PROVIDER_RESPONSE_BYTES,
            circuit: None,
            base_url: None,
            url_template: UrlTemplate::Static(Arc::from("https://example.test/")),
        };
        validate_multimodal_translate_support(&provider, openai_body)
    }

    /// Expose URL building for tests so we can assert the template logic.
    pub fn build_provider_url_for_test(
        provider_type: &str,
        provider_config: &Value,
        model: &str,
    ) -> Result<String, String> {
        let pt = ProviderType::from_str(provider_type)?;
        let base_url = provider_config["base_url"].as_str();
        let azure_resource = provider_config["azure_resource"].as_str();
        let azure_deployment = provider_config["azure_deployment"].as_str();
        let azure_api_version = provider_config["azure_api_version"]
            .as_str()
            .unwrap_or("2024-06-01");
        let google_project_id = provider_config["google_project_id"].as_str();
        let google_region = provider_config["google_region"].as_str();
        let aws_region = provider_config["aws_region"].as_str();
        let template = build_url_template(
            pt,
            base_url,
            azure_resource,
            azure_deployment,
            azure_api_version,
            google_region,
            google_project_id,
            aws_region,
        )?;
        Ok(template.render(model))
    }

    /// Expose response normalization for tests.
    pub fn normalize_response_test(
        provider_type: &str,
        status: u16,
        body: &[u8],
        model: &str,
    ) -> Result<(Value, u64, u64, u64), String> {
        let pt = ProviderType::from_str(provider_type)?;
        let (normalized, tokens) = normalize_response(pt, status, body, model)?;
        Ok((
            normalized,
            tokens.prompt_tokens.unwrap_or(0),
            tokens.completion_tokens.unwrap_or(0),
            tokens.total_tokens.unwrap_or(0),
        ))
    }

    /// Expose `base_url` validation for tests with an explicit IP policy.
    ///
    /// Mirrors what `AiFederation::new` does per provider once the policy has
    /// been resolved by gateway startup.
    pub fn validate_base_url_test(
        provider_name: &str,
        base_url: &str,
        allow_plaintext: bool,
        policy: &str,
    ) -> Result<(), String> {
        use crate::config::{BackendAllowIps, BackendEgressPolicy};
        let policy = match policy {
            "private" => BackendEgressPolicy::from_allow_ips(BackendAllowIps::Private),
            "public" => BackendEgressPolicy::from_allow_ips(BackendAllowIps::Public),
            "both" => BackendEgressPolicy::from_allow_ips(BackendAllowIps::Both),
            other => return Err(format!("invalid policy '{other}'")),
        };
        validate_base_url(provider_name, base_url, allow_plaintext, &policy)
    }

    /// Drive threshold/open/cooldown/half-open/close transitions without a
    /// wall-clock sleep so external tests can verify the lock-free state
    /// machine deterministically.
    pub fn circuit_transition_sequence_for_test() -> Vec<&'static str> {
        let circuit = ProviderCircuit::new(ProviderCircuitConfig {
            failure_threshold: 2,
            cooldown: Duration::from_secs(60),
            success_threshold: 1,
        });
        let mut states = Vec::new();
        let first = circuit.admit();
        states.push(circuit_admission_label(first));
        circuit.record_failure("test", first);
        let second = circuit.admit();
        states.push(circuit_admission_label(second));
        circuit.record_failure("test", second);
        states.push(circuit_admission_label(circuit.admit()));
        circuit
            .open_until_monotonic_ms
            .store(circuit_monotonic_millis(), Ordering::Release);
        let probe = circuit.admit();
        states.push(circuit_admission_label(probe));
        circuit.record_success("test", probe);
        states.push(circuit_admission_label(circuit.admit()));
        states
    }

    /// Simulate cancellation after half-open admission and verify the RAII
    /// lease makes the probe slot immediately available again.
    pub fn cancelled_half_open_probe_is_released_for_test() -> bool {
        let circuit = ProviderCircuit::new(ProviderCircuitConfig {
            failure_threshold: 1,
            cooldown: Duration::from_secs(60),
            success_threshold: 1,
        });
        circuit
            .open_until_monotonic_ms
            .store(circuit_monotonic_millis(), Ordering::Release);
        {
            let admission = circuit.admit();
            if admission != CircuitAdmission::HalfOpenProbe {
                return false;
            }
            let _cancelled_dispatch = HalfOpenProbeGuard::new(&circuit);
        }
        circuit.admit() == CircuitAdmission::HalfOpenProbe
    }

    /// Reproduce the completion/re-arm interleaving for a success threshold
    /// greater than one. Once the second probe owns the slot, resolving the
    /// first probe's guard must not allow a third concurrent probe.
    pub fn completed_half_open_probe_does_not_release_successor_for_test() -> bool {
        let circuit = ProviderCircuit::new(ProviderCircuitConfig {
            failure_threshold: 1,
            cooldown: Duration::from_secs(60),
            success_threshold: 2,
        });
        circuit
            .open_until_monotonic_ms
            .store(circuit_monotonic_millis(), Ordering::Release);

        let first_admission = circuit.admit();
        if first_admission != CircuitAdmission::HalfOpenProbe {
            return false;
        }
        let mut first_guard = HalfOpenProbeGuard::new(&circuit);
        circuit.record_success("test", first_admission);

        let second_admission = circuit.admit();
        if second_admission != CircuitAdmission::HalfOpenProbe {
            return false;
        }
        let _second_guard = HalfOpenProbeGuard::new(&circuit);

        first_guard.resolve();
        drop(first_guard);
        circuit.admit() == CircuitAdmission::Open
    }

    fn circuit_admission_label(admission: CircuitAdmission) -> &'static str {
        match admission {
            CircuitAdmission::Closed => "closed",
            CircuitAdmission::HalfOpenProbe => "half_open_probe",
            CircuitAdmission::Open => "open",
        }
    }
}

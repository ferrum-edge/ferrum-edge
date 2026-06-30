//! AI Federation Plugin
//!
//! Universal AI gateway that translates OpenAI Chat Completions format to any
//! of 11 supported AI providers and normalizes responses back to OpenAI format.
//!
//! Uses the "terminate and respond" pattern: runs in `before_proxy` at priority
//! 2985, makes its own HTTP call to the matched AI provider via a per-provider
//! `reqwest::Client`, and returns `PluginResult::RejectBinary` with the
//! normalized response. The normal proxy dispatch is skipped entirely.
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
//! ai_prompt_shield (2925) → ai_request_guard (2975) → ai_federation (2985)
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
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use url::{Host, Url};

use super::utils::aws_sigv4;
use super::utils::body_transform::is_json_content_type;
use super::{Plugin, PluginHttpClient, PluginResult, RequestContext};

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
            other => Err(format!("ai_federation: unknown provider_type '{other}'")),
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
#[derive(Debug, Clone)]
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

/// Thread-safe OAuth2 token cache for Google Vertex AI.
#[derive(Debug)]
struct OAuth2Cache {
    cache: ArcSwapOption<CachedToken>,
    refresh_lock: Mutex<()>,
    service_account_json: String,
}

impl OAuth2Cache {
    fn new(service_account_json: String) -> Self {
        Self {
            cache: ArcSwapOption::empty(),
            refresh_lock: Mutex::new(()),
            service_account_json,
        }
    }

    async fn get_token(&self, http_client: &PluginHttpClient) -> Result<String, String> {
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

        let token = self.refresh_token(http_client).await?;
        let result = token.token.clone();
        self.cache.store(Some(Arc::new(token)));
        Ok(result)
    }

    async fn refresh_token(&self, http_client: &PluginHttpClient) -> Result<CachedToken, String> {
        let sa: Value = serde_json::from_str(&self.service_account_json)
            .map_err(|e| format!("ai_federation: invalid service account JSON: {e}"))?;

        let client_email = sa["client_email"]
            .as_str()
            .ok_or("ai_federation: service account JSON missing client_email")?;
        let private_key_pem = sa["private_key"]
            .as_str()
            .ok_or("ai_federation: service account JSON missing private_key")?;
        let token_uri = sa["token_uri"]
            .as_str()
            .unwrap_or("https://oauth2.googleapis.com/token");

        let now = Utc::now().timestamp();
        let claims = json!({
            "iss": client_email,
            "scope": "https://www.googleapis.com/auth/cloud-platform",
            "aud": token_uri,
            "iat": now,
            "exp": now + 3600,
        });

        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
            .map_err(|e| format!("ai_federation: invalid RSA private key: {e}"))?;
        let jwt = jsonwebtoken::encode(&header, &claims, &key)
            .map_err(|e| format!("ai_federation: JWT signing failed: {e}"))?;

        let body = format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={}",
            jwt
        );

        let req = http_client
            .get()
            .post(token_uri)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body);
        let resp = http_client
            .execute(req, "ai_federation_oauth2")
            .await
            .map_err(|e| format!("ai_federation: OAuth2 token request failed: {e}"))?;

        let status = resp.status().as_u16();
        let resp_body = resp
            .bytes()
            .await
            .map_err(|e| format!("ai_federation: OAuth2 response read failed: {e}"))?;

        if status != 200 {
            return Err(format!(
                "ai_federation: OAuth2 token endpoint returned {}: {}",
                status,
                String::from_utf8_lossy(&resp_body)
            ));
        }

        let token_resp: Value = serde_json::from_slice(&resp_body)
            .map_err(|e| format!("ai_federation: OAuth2 response parse failed: {e}"))?;

        let access_token = token_resp["access_token"]
            .as_str()
            .ok_or("ai_federation: OAuth2 response missing access_token")?
            .to_string();
        let expires_in = token_resp["expires_in"].as_u64().unwrap_or(3600);

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
        format!("ai_federation: provider '{provider_name}' invalid base_url '{base_url}': {e}")
    })?;

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
            "ai_federation: provider '{provider_name}' base_url '{base_url}' has no host"
        ));
    }

    let host = normalized_url_hostname(&parsed).ok_or_else(|| {
        format!("ai_federation: provider '{provider_name}' base_url '{base_url}' has no host")
    })?;

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
) -> UrlTemplate {
    if let Some(base) = base_url {
        return UrlTemplate::Static(Arc::from(base));
    }

    match provider_type {
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
    }
}

// ---------------------------------------------------------------------------
// Main plugin struct
// ---------------------------------------------------------------------------

pub struct AiFederation {
    providers: Vec<ResolvedProvider>,
    fallback_enabled: bool,
    fallback_status_codes: HashSet<u16>,
    fallback_on_network_errors: bool,
    fail_on_missing_model: bool,
    fail_on_no_matching_provider: bool,
    http_client: PluginHttpClient,
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

impl AiFederation {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        if !config.is_object() {
            return Err("ai_federation: config must be an object".to_string());
        }

        reject_unsupported_streaming_config(config, "config")?;

        let providers_val = config
            .get("providers")
            .and_then(|v| v.as_array())
            .ok_or("ai_federation: 'providers' must be a non-empty array")?;

        if providers_val.is_empty() {
            return Err("ai_federation: 'providers' array must not be empty".to_string());
        }

        let mut providers = Vec::with_capacity(providers_val.len());

        // Use the already-resolved gateway IP allowlist policy so provider
        // validation honors CLI/env/conf/default precedence.
        let backend_allow_ips = http_client.backend_allow_ips().clone();

        for (i, pv) in providers_val.iter().enumerate() {
            let name = pv["name"]
                .as_str()
                .ok_or(format!("ai_federation: provider[{i}] missing 'name'"))?
                .to_string();

            reject_unsupported_streaming_config(pv, &format!("provider '{name}'"))?;

            let provider_type_str = pv["provider_type"].as_str().ok_or(format!(
                "ai_federation: provider '{name}' missing 'provider_type'"
            ))?;
            let provider_type = ProviderType::from_str(provider_type_str)?;

            let priority_u64 = optional_u64(pv, "priority")?.unwrap_or((i as u64) + 1);
            let priority = u32::try_from(priority_u64)
                .map_err(|_| format!("ai_federation: provider '{name}' priority is too large"))?;

            let model_patterns = optional_string_vec(pv, "model_patterns")?.unwrap_or_default();

            let model_mapping = optional_string_map(pv, "model_mapping")?.unwrap_or_default();

            let default_model = pv["default_model"].as_str().map(String::from);
            let multimodal_mode = match optional_str(pv, "multimodal_mode")? {
                Some(mode) => MultimodalMode::from_str(mode, &name)?,
                None => MultimodalMode::default_for_provider(provider_type),
            };

            let connect_timeout =
                Duration::from_secs(optional_u64(pv, "connect_timeout_seconds")?.unwrap_or(5));
            let read_timeout =
                Duration::from_secs(optional_u64(pv, "read_timeout_seconds")?.unwrap_or(60));

            let base_url = pv["base_url"].as_str().map(String::from);
            let allow_plaintext = pv["allow_plaintext"].as_bool().unwrap_or(false);

            // SSRF guard: validate operator-supplied base_url before storing
            // it. Provider `default_base_url` literals are static `https://`
            // strings and are inherently safe (covered by inspection — see
            // `ProviderType::default_base_url`); only the operator override
            // needs runtime validation.
            if let Some(ref url) = base_url {
                validate_base_url(&name, url, allow_plaintext, &backend_allow_ips)?;
            }

            let auth = build_auth(provider_type, pv, &name)?;

            let azure_resource = pv["azure_resource"].as_str().map(String::from);
            let azure_deployment = pv["azure_deployment"].as_str().map(String::from);
            let azure_api_version = pv["azure_api_version"]
                .as_str()
                .unwrap_or("2024-06-01")
                .to_string();

            let google_project_id = pv["google_project_id"].as_str().map(String::from);
            let google_region = pv["google_region"].as_str().map(String::from);
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
            );

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

        let fail_on_missing_model = optional_bool(config, "fail_on_missing_model")?.unwrap_or(true);
        let fail_on_no_matching_provider =
            optional_bool(config, "fail_on_no_matching_provider")?.unwrap_or(true);

        Ok(Self {
            providers,
            fallback_enabled,
            fallback_status_codes,
            fallback_on_network_errors,
            fail_on_missing_model,
            fail_on_no_matching_provider,
            http_client,
        })
    }
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
            // Validate the JSON is parseable
            serde_json::from_str::<Value>(&sa_json).map_err(|e| {
                format!("ai_federation: provider '{name}' invalid service account JSON: {e}")
            })?;
            Ok(AuthMethod::GoogleOAuth2 {
                cache: Arc::new(OAuth2Cache::new(sa_json)),
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
/// Rather than break either way, `before_proxy` rejects streaming requests it
/// would otherwise intercept with a clear, OpenAI-shaped error. We only treat
/// `stream: true` (a real boolean) as streaming; a stringly-typed `"true"` or a
/// missing field is not streaming.
fn request_wants_streaming(openai_body: &Value) -> bool {
    openai_body["stream"].as_bool() == Some(true)
}

/// Translate an OpenAI Chat Completions request to the provider's native format.
fn translate_request(
    provider: &ResolvedProvider,
    openai_body: &Value,
    resolved_model: &str,
) -> Result<TranslatedRequest, String> {
    match provider.provider_type {
        pt if pt.is_openai_compatible() => {
            translate_openai_compatible(provider, openai_body, resolved_model)
        }
        ProviderType::Anthropic => translate_to_anthropic(provider, openai_body, resolved_model),
        ProviderType::GoogleGemini | ProviderType::GoogleVertex => {
            translate_to_gemini(provider, openai_body, resolved_model)
        }
        ProviderType::AwsBedrock => translate_to_bedrock(provider, openai_body, resolved_model),
        ProviderType::Cohere => translate_to_cohere(provider, openai_body, resolved_model),
        // All variants covered above (is_openai_compatible catches the rest)
        _ => unreachable!(),
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
    body["model"] = Value::String(resolved_model.to_string());

    // For Azure, strip the model field — the deployment is in the URL
    if provider.provider_type == ProviderType::AzureOpenAi
        && let Some(obj) = body.as_object_mut()
    {
        obj.remove("model");
    }

    let url = build_provider_url(provider, resolved_model);
    let headers = vec![("content-type".to_string(), "application/json".to_string())];
    let body_bytes = serde_json::to_vec(&body)
        .map_err(|e| format!("ai_federation: failed to serialize request: {e}"))?;

    Ok((url, headers, body_bytes))
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
            "image_url.url scheme '{other}' is unsupported (expected https, http, or data)"
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
            "image_url data URL media type '{media_type}' is not an image"
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
            "ai_federation: unsupported Gemini image media type '{other}' (expected jpeg, png, webp, heic, or heif)"
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
            "Gemini/Vertex image translation: cannot determine a supported image mimeType for fileData URI '{uri}' (add an explicit image_url.mime_type, or use a .jpg/.jpeg/.png/.webp/.heic/.heif extension)"
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
            "ai_federation: unsupported Bedrock image media type '{other}'"
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
            "ai_federation: unsupported Anthropic image media type '{other}' (expected jpeg, png, gif, or webp)"
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

    // Filter to user/assistant messages only
    let filtered_messages: Vec<Value> = messages
        .iter()
        .filter(|m| {
            let role = m["role"].as_str().unwrap_or("");
            role == "user" || role == "assistant"
        })
        .map(|m| {
            let role = m["role"].as_str().unwrap_or("user");
            Ok(json!({
                "role": role,
                "content": openai_content_to_anthropic(&m["content"], provider.multimodal_mode)?
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;

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
    if let Some(stop) = openai_body.get("stop") {
        body["stop_sequences"] = stop.clone();
    }

    let url = provider
        .base_url
        .clone()
        .unwrap_or_else(|| ProviderType::Anthropic.default_base_url().to_string());
    let headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("anthropic-version".to_string(), "2023-06-01".to_string()),
    ];
    let body_bytes = serde_json::to_vec(&body)
        .map_err(|e| format!("ai_federation: failed to serialize Anthropic request: {e}"))?;

    Ok((url, headers, body_bytes))
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

    // Map user/assistant messages → Gemini contents, preserving supported
    // image_url parts when `multimodal_mode = translate`.
    let contents: Vec<Value> = messages
        .iter()
        .filter(|m| {
            let role = m["role"].as_str().unwrap_or("");
            role == "user" || role == "assistant"
        })
        .map(|m| {
            let role = match m["role"].as_str().unwrap_or("user") {
                "assistant" => "model",
                other => other,
            };
            Ok(json!({
                "role": role,
                "parts": openai_content_to_gemini_parts(&m["content"], provider.multimodal_mode)?
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;

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
    if let Some(stop) = openai_body.get("stop") {
        gen_config.insert("stopSequences".to_string(), stop.clone());
    }
    if !gen_config.is_empty() {
        body["generationConfig"] = Value::Object(gen_config);
    }

    let url = build_provider_url(provider, resolved_model);
    let headers = vec![("content-type".to_string(), "application/json".to_string())];
    let body_bytes = serde_json::to_vec(&body)
        .map_err(|e| format!("ai_federation: failed to serialize Gemini request: {e}"))?;

    Ok((url, headers, body_bytes))
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

    // Map user/assistant messages to Bedrock Converse format, preserving
    // supported data URL image_url parts when `multimodal_mode = translate`.
    let bedrock_messages: Vec<Value> = messages
        .iter()
        .filter(|m| {
            let role = m["role"].as_str().unwrap_or("");
            role == "user" || role == "assistant"
        })
        .map(|m| {
            Ok(json!({
                "role": m["role"].as_str().unwrap_or("user"),
                "content": openai_content_to_bedrock_blocks(&m["content"], provider.multimodal_mode)?
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;

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
    if let Some(stop) = openai_body.get("stop") {
        inference_config.insert("stopSequences".to_string(), stop.clone());
    }
    if !inference_config.is_empty() {
        body["inferenceConfig"] = Value::Object(inference_config);
    }

    let url = build_provider_url(provider, resolved_model);
    let headers = vec![("content-type".to_string(), "application/json".to_string())];
    let body_bytes = serde_json::to_vec(&body)
        .map_err(|e| format!("ai_federation: failed to serialize Bedrock request: {e}"))?;

    Ok((url, headers, body_bytes))
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
    }

    let url = provider
        .base_url
        .clone()
        .unwrap_or_else(|| ProviderType::Cohere.default_base_url().to_string());
    let headers = vec![("content-type".to_string(), "application/json".to_string())];
    let body_bytes = serde_json::to_vec(&body)
        .map_err(|e| format!("ai_federation: failed to serialize Cohere request: {e}"))?;

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

/// Maximum number of raw upstream-response bytes reflected back to the caller.
///
/// Both the error-passthrough path and the parse-failure path truncate the
/// provider's body to this many bytes before lossy UTF-8 conversion. Slicing
/// the raw bytes (not the lossy `String`) keeps the cut on a byte boundary, and
/// `from_utf8_lossy` then repairs any code point split by the cut. Bounding the
/// reflected text avoids forwarding an unbounded, provider-controlled error
/// body to arbitrary downstream callers. See finding #52.
const MAX_UPSTREAM_ERROR_BYTES: usize = 512;

fn cap_upstream_error_body(body: Vec<u8>) -> Vec<u8> {
    // Return a complete JSON error document even when the upstream body is
    // truncated, so fallback exhaustion never sends malformed JSON with an
    // application/json content type.
    let error_text = String::from_utf8_lossy(&body[..body.len().min(MAX_UPSTREAM_ERROR_BYTES)]);
    openai_error_body(
        &format!("Upstream provider error: {error_text}"),
        "upstream_error",
        None,
        Some("upstream_error"),
    )
    .to_string()
    .into_bytes()
}

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
    // For error responses, pass through the raw error (capped — the upstream
    // body is provider-controlled and may be large or detail-rich).
    if status >= 400 {
        let error_text = String::from_utf8_lossy(&body[..body.len().min(MAX_UPSTREAM_ERROR_BYTES)]);
        return Ok((
            openai_error_body(
                &format!("Upstream provider returned {}: {}", status, error_text),
                "upstream_error",
                None,
                Some("upstream_error"),
            ),
            TokenCounts::default(),
        ));
    }

    let resp: Value = serde_json::from_slice(body).map_err(|e| {
        format!(
            "ai_federation: failed to parse provider response: {e} (body: {})",
            String::from_utf8_lossy(&body[..body.len().min(MAX_UPSTREAM_ERROR_BYTES)])
        )
    })?;

    if provider_type.is_openai_compatible() {
        normalize_from_openai_compatible(&resp)
    } else {
        match provider_type {
            ProviderType::Anthropic => normalize_from_anthropic(&resp, resolved_model),
            ProviderType::GoogleGemini | ProviderType::GoogleVertex => {
                normalize_from_gemini(&resp, resolved_model)
            }
            ProviderType::AwsBedrock => normalize_from_bedrock(&resp, resolved_model),
            ProviderType::Cohere => normalize_from_cohere(&resp, resolved_model),
            _ => unreachable!(),
        }
    }
}

fn normalize_from_openai_compatible(resp: &Value) -> Result<(Value, TokenCounts), String> {
    let tokens = TokenCounts {
        prompt_tokens: resp["usage"]["prompt_tokens"].as_u64(),
        completion_tokens: resp["usage"]["completion_tokens"].as_u64(),
        total_tokens: resp["usage"]["total_tokens"].as_u64(),
        model: resp["model"].as_str().map(String::from),
    };
    Ok((resp.clone(), tokens))
}

fn normalize_from_anthropic(resp: &Value, model: &str) -> Result<(Value, TokenCounts), String> {
    let content = resp["content"]
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|c| c["text"].as_str())
        .unwrap_or("");

    let finish_reason = match resp["stop_reason"].as_str() {
        Some("end_turn") => "stop",
        Some("max_tokens") => "length",
        Some("stop_sequence") => "stop",
        Some(other) => other,
        None => "stop",
    };

    let input_tokens = resp["usage"]["input_tokens"].as_u64();
    let output_tokens = resp["usage"]["output_tokens"].as_u64();
    let total = match (input_tokens, output_tokens) {
        (Some(i), Some(o)) => Some(i + o),
        _ => None,
    };

    let resp_model = resp["model"].as_str().unwrap_or(model);
    let id = resp["id"]
        .as_str()
        .map(String::from)
        .unwrap_or_else(|| format!("chatcmpl-fed-{}", generate_short_id()));

    let normalized = json!({
        "id": id,
        "object": "chat.completion",
        "created": Utc::now().timestamp(),
        "model": resp_model,
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": content
            },
            "finish_reason": finish_reason
        }],
        "usage": {
            "prompt_tokens": input_tokens.unwrap_or(0),
            "completion_tokens": output_tokens.unwrap_or(0),
            "total_tokens": total.unwrap_or(0)
        }
    });

    let tokens = TokenCounts {
        prompt_tokens: input_tokens,
        completion_tokens: output_tokens,
        total_tokens: total,
        model: Some(resp_model.to_string()),
    };

    Ok((normalized, tokens))
}

fn normalize_from_gemini(resp: &Value, model: &str) -> Result<(Value, TokenCounts), String> {
    let content = resp["candidates"]
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|c| c["content"]["parts"].as_array())
        .and_then(|parts| parts.first())
        .and_then(|p| p["text"].as_str())
        .unwrap_or("");

    let finish_reason = resp["candidates"]
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|c| c["finishReason"].as_str())
        .map(|r| match r {
            "STOP" => "stop",
            "MAX_TOKENS" => "length",
            "SAFETY" => "content_filter",
            other => other,
        })
        .unwrap_or("stop");

    let prompt_tokens = resp["usageMetadata"]["promptTokenCount"].as_u64();
    let completion_tokens = resp["usageMetadata"]["candidatesTokenCount"].as_u64();
    let total = resp["usageMetadata"]["totalTokenCount"]
        .as_u64()
        .or_else(|| match (prompt_tokens, completion_tokens) {
            (Some(p), Some(c)) => Some(p + c),
            _ => None,
        });

    let resp_model = resp["modelVersion"].as_str().unwrap_or(model);

    let normalized = json!({
        "id": format!("chatcmpl-fed-{}", generate_short_id()),
        "object": "chat.completion",
        "created": Utc::now().timestamp(),
        "model": resp_model,
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": content
            },
            "finish_reason": finish_reason
        }],
        "usage": {
            "prompt_tokens": prompt_tokens.unwrap_or(0),
            "completion_tokens": completion_tokens.unwrap_or(0),
            "total_tokens": total.unwrap_or(0)
        }
    });

    let tokens = TokenCounts {
        prompt_tokens,
        completion_tokens,
        total_tokens: total,
        model: Some(resp_model.to_string()),
    };

    Ok((normalized, tokens))
}

fn normalize_from_bedrock(resp: &Value, model: &str) -> Result<(Value, TokenCounts), String> {
    let content = resp["output"]["message"]["content"]
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|c| c["text"].as_str())
        .unwrap_or("");

    let finish_reason = match resp["stopReason"].as_str() {
        Some("end_turn") => "stop",
        Some("max_tokens") => "length",
        Some("stop_sequence") => "stop",
        Some(other) => other,
        None => "stop",
    };

    let input_tokens = resp["usage"]["inputTokens"].as_u64();
    let output_tokens = resp["usage"]["outputTokens"].as_u64();
    let total =
        resp["usage"]["totalTokens"]
            .as_u64()
            .or_else(|| match (input_tokens, output_tokens) {
                (Some(i), Some(o)) => Some(i + o),
                _ => None,
            });

    let normalized = json!({
        "id": format!("chatcmpl-fed-{}", generate_short_id()),
        "object": "chat.completion",
        "created": Utc::now().timestamp(),
        "model": model,
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": content
            },
            "finish_reason": finish_reason
        }],
        "usage": {
            "prompt_tokens": input_tokens.unwrap_or(0),
            "completion_tokens": output_tokens.unwrap_or(0),
            "total_tokens": total.unwrap_or(0)
        }
    });

    let tokens = TokenCounts {
        prompt_tokens: input_tokens,
        completion_tokens: output_tokens,
        total_tokens: total,
        model: Some(model.to_string()),
    };

    Ok((normalized, tokens))
}

fn normalize_from_cohere(resp: &Value, model: &str) -> Result<(Value, TokenCounts), String> {
    let content = resp["message"]["content"]
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|c| c["text"].as_str())
        .unwrap_or("");

    let finish_reason = match resp["finish_reason"].as_str() {
        Some("COMPLETE") => "stop",
        Some("MAX_TOKENS") => "length",
        Some("STOP_SEQUENCE") => "stop",
        Some(other) => other,
        None => "stop",
    };

    let input_tokens = resp["usage"]["tokens"]["input_tokens"].as_u64();
    let output_tokens = resp["usage"]["tokens"]["output_tokens"].as_u64();
    let total = match (input_tokens, output_tokens) {
        (Some(i), Some(o)) => Some(i + o),
        _ => None,
    };

    let resp_model = resp["model"].as_str().unwrap_or(model);

    let normalized = json!({
        "id": resp["id"].as_str().map(String::from).unwrap_or_else(|| format!("chatcmpl-fed-{}", generate_short_id())),
        "object": "chat.completion",
        "created": Utc::now().timestamp(),
        "model": resp_model,
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": content
            },
            "finish_reason": finish_reason
        }],
        "usage": {
            "prompt_tokens": input_tokens.unwrap_or(0),
            "completion_tokens": output_tokens.unwrap_or(0),
            "total_tokens": total.unwrap_or(0)
        }
    });

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
    /// Call a provider and return (status, body_bytes).
    async fn call_provider(
        &self,
        provider: &ResolvedProvider,
        url: &str,
        extra_headers: Vec<(String, String)>,
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), String> {
        let auth_headers = self.build_auth_headers(provider, url, body).await?;

        let req = self
            .http_client
            .get()
            .post(url)
            .connect_timeout(provider.connect_timeout)
            .timeout(provider.read_timeout);

        let mut req = req;
        for (k, v) in &auth_headers {
            req = req.header(k.as_str(), v.as_str());
        }
        for (k, v) in &extra_headers {
            req = req.header(k.as_str(), v.as_str());
        }
        req = req.body(body.to_vec());

        let resp = self
            .http_client
            .execute(req, "ai_federation")
            .await
            .map_err(|e| {
                format!(
                    "ai_federation: provider '{}' request failed: {e}",
                    provider.name
                )
            })?;

        let status = resp.status().as_u16();
        let resp_body = resp
            .bytes()
            .await
            .map_err(|e| {
                format!(
                    "ai_federation: provider '{}' response read failed: {e}",
                    provider.name
                )
            })?
            .to_vec();

        Ok((status, resp_body))
    }

    /// Build authentication headers for a provider.
    async fn build_auth_headers(
        &self,
        provider: &ResolvedProvider,
        url: &str,
        payload: &[u8],
    ) -> Result<Vec<(String, String)>, String> {
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
            }

            AuthMethod::GoogleOAuth2 { cache } => {
                let token = cache.get_token(&self.http_client).await?;
                Ok(vec![(
                    "authorization".to_string(),
                    format!("Bearer {token}"),
                )])
            }
        }
    }

    /// Determine if an error should trigger fallback.
    fn should_fallback(&self, result: &Result<(u16, Vec<u8>), String>) -> bool {
        if !self.fallback_enabled {
            return false;
        }
        match result {
            Err(_) => self.fallback_on_network_errors,
            Ok((status, _)) => self.fallback_status_codes.contains(status),
        }
    }
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
        super::HTTP_GRPC_PROTOCOLS
    }

    fn requires_request_body_before_before_proxy(&self) -> bool {
        true
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        if ctx.method != "POST" {
            return false;
        }
        let Some(content_type) = ctx.headers.get("content-type") else {
            return false;
        };
        // Mirror the native-gRPC pass-through in `before_proxy`: `is_json_content_type`
        // accepts the `+json` suffix, so `application/grpc+json` would otherwise be
        // buffered here — and this predicate is evaluated by the H1/H2 path in
        // `src/proxy/mod.rs` *before* any `before_proxy` hook runs (via
        // `requires_request_body_before_before_proxy`). Buffering a native gRPC
        // request fully drains client-streaming / large bodies even though
        // `before_proxy` then returns `Continue`, so the gRPC exclusion must apply
        // to the buffering decision too, not just the hook.
        if crate::proxy::backend_dispatch::is_native_grpc_content_type(content_type.as_bytes()) {
            return false;
        }
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

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
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

        // Native gRPC bodies are length-prefixed framing (5-byte
        // compression/length header + payload), not raw OpenAI JSON. Because
        // this plugin advertises `HTTP_GRPC_PROTOCOLS` and `is_json_content_type`
        // accepts the `+json` suffix, a `content-type: application/grpc+json`
        // request would otherwise be buffered and reach the JSON parse below,
        // which would reject the gRPC frame as malformed JSON under the
        // fail-closed policy. gRPC model-routing is out of scope for this
        // OpenAI-format gateway, so pass framed gRPC traffic through untouched —
        // matching how `ai_token_metrics` opts native gRPC out of JSON parsing.
        if crate::proxy::backend_dispatch::is_native_grpc_content_type(content_type.as_bytes()) {
            debug!(
                "ai_federation: native gRPC content-type, passing through (gRPC model routing unsupported)"
            );
            return PluginResult::Continue;
        }

        // Read request body. `store_request_body_metadata()` in
        // `src/proxy/mod.rs` only inserts `request_body` for UTF-8 bodies and
        // removes the key for non-UTF-8 bodies, so this `None` branch covers
        // both "no body was sent" and "a body was sent but isn't UTF-8". The
        // message reflects both cases; either way a binary body cannot be JSON,
        // so the 400 reject is the correct fail-closed outcome.
        let body_str = match ctx.metadata.get("request_body") {
            Some(b) => b.as_str(),
            None => {
                if self.fail_on_missing_model {
                    debug!(
                        "ai_federation: rejecting JSON POST without a buffered UTF-8 request body"
                    );
                    return self.openai_error_response(
                        400,
                        "Request body is required and must be UTF-8 JSON for ai_federation model routing",
                        "invalid_request_error",
                        None,
                        Some("missing_request_body"),
                    );
                }
                debug!(
                    "ai_federation: no request_body in metadata, passing through by explicit opt-in"
                );
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
                return PluginResult::Continue;
            }
        };

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

        let multimodal_usage = analyze_multimodal_usage(&openai_body);

        // Try providers in priority order with fallback
        let mut last_error: Option<String> = None;
        let mut last_status: Option<u16> = None;
        let mut last_body: Option<Vec<u8>> = None;
        // Multimodal capability is provider-SPECIFIC: a reject-mode (or a
        // translate-mode provider that can't translate this particular part,
        // e.g. Bedrock + an unsupported image format) provider failing the
        // policy gate must not abort the whole fallback chain — a later
        // provider may still serve the request. We record the last such
        // rejection so that, if EVERY provider is exhausted on policy alone
        // (no provider was ever dialed), we can return a clean 400 instead of
        // a generic 502.
        let mut last_multimodal_rejection: Option<String> = None;

        let provider_count = matching_providers.len();
        for (idx, provider) in matching_providers.iter().enumerate() {
            let is_last_provider = idx + 1 == provider_count;
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
                warn!(
                    provider = %provider.name,
                    provider_type = %provider.provider_type.as_str(),
                    model = %resolved_model,
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
                    part_types = %multimodal_usage.types_csv(),
                    roles = %multimodal_usage.roles_csv(),
                    "ai_federation: provider cannot serve multimodal request, trying fallback"
                );
                last_multimodal_rejection = Some(message);
                // Per-provider policy rejection — fall through to the next
                // provider exactly like a per-provider translation failure
                // does, instead of aborting the whole chain. This lets a
                // mixed list (e.g. a reject-mode provider followed by a
                // translate-mode one) serve the image from the later provider.
                if self.fallback_enabled && !is_last_provider {
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
                    part_types = %multimodal_usage.types_csv(),
                    roles = %multimodal_usage.roles_csv(),
                    "ai_federation: dropping non-text multimodal content by explicit text_only_with_warning policy"
                );
            }

            let translated = match translate_request(provider, &openai_body, &resolved_model) {
                Ok(t) => t,
                Err(e) => {
                    warn!(
                        provider = %provider.name,
                        error = %e,
                        "ai_federation: request translation failed"
                    );
                    last_error = Some(e);
                    if self.fallback_enabled && !is_last_provider {
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
                url = %url,
                "ai_federation: calling provider"
            );

            let result = self
                .call_provider(provider, &url, extra_headers, &body_bytes)
                .await;

            // Only fallback to the next provider if there is one remaining.
            // On the last provider, fall through to process the response
            // normally so normalization and token metadata writes still happen.
            if self.should_fallback(&result) && !is_last_provider {
                match &result {
                    Err(e) => {
                        warn!(
                            provider = %provider.name,
                            error = %e,
                            "ai_federation: provider failed, trying fallback"
                        );
                        last_error = Some(e.clone());
                    }
                    Ok((status, body)) => {
                        warn!(
                            provider = %provider.name,
                            status = %status,
                            "ai_federation: provider returned fallback-eligible status"
                        );
                        last_status = Some(*status);
                        last_body = Some(cap_upstream_error_body(body.clone()));
                    }
                }
                continue;
            }

            // No fallback needed — process the response
            let (status, resp_body) = match result {
                Ok(r) => r,
                Err(e) => {
                    return self.openai_error_response(
                        502,
                        &format!("Provider '{}' request failed: {e}", provider.name),
                        "server_error",
                        None,
                        Some("provider_request_failed"),
                    );
                }
            };

            match normalize_response(provider.provider_type, status, &resp_body, &resolved_model) {
                Ok((normalized, token_counts)) => {
                    // Write token metadata for downstream plugins
                    self.write_token_metadata(
                        ctx,
                        &token_counts,
                        provider.provider_type,
                        &provider.name,
                        &resolved_model,
                    );

                    // Record the multimodal-drop audit/chargeback metadata only
                    // now that THIS provider has committed to serving the
                    // request. Writing it pre-dispatch would leave stale "parts
                    // dropped" keys (naming the wrong provider) in the
                    // transaction log if a `text_only_with_warning` provider
                    // failed over to a later `translate` provider that preserved
                    // the image.
                    if provider.multimodal_mode == MultimodalMode::TextOnlyWithWarning
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

                    let bytes_received = match serde_json::to_vec(&normalized) {
                        Ok(b) => b,
                        Err(e) => {
                            // Practically unreachable: `normalized` is built from
                            // `serde_json::json!()` macros over plain primitives,
                            // so serialization cannot fail. Returning a 502 with
                            // a structured error keeps callers from receiving an
                            // empty-body 200 in the impossible case.
                            warn!(
                                provider = %provider.name,
                                error = %e,
                                "ai_federation: failed to serialize normalized response"
                            );
                            return self.openai_error_response(
                                502,
                                &format!(
                                    "Provider '{}' response serialization failed: {e}",
                                    provider.name
                                ),
                                "server_error",
                                None,
                                Some("response_serialization_failed"),
                            );
                        }
                    };
                    let mut resp_headers = HashMap::new();
                    resp_headers.insert("content-type".to_string(), "application/json".to_string());

                    let status_code = if status >= 400 { status } else { 200 };
                    // Record the synthetic response status alongside the token
                    // metadata so `ai_rate_limiter` can reconcile a pre-reservation
                    // against the provider's ORIGINAL status. This response is a
                    // `before_proxy` short-circuit, so a later response-body
                    // guardrail can replace it with a 5xx before `ai_rate_limiter`'s
                    // after_proxy runs; without this signal a usage-less federation
                    // response that gets guard-rejected would release the
                    // reservation for a provider call that already consumed tokens.
                    ctx.metadata
                        .insert("ai_federation_status".to_string(), status_code.to_string());

                    return PluginResult::RejectBinary {
                        status_code,
                        body: Bytes::from(bytes_received),
                        headers: resp_headers,
                    };
                }
                Err(e) => {
                    warn!(
                        provider = %provider.name,
                        error = %e,
                        "ai_federation: response normalization failed"
                    );
                    return self.openai_error_response(
                        502,
                        &format!(
                            "Provider '{}' response normalization failed: {e}",
                            provider.name
                        ),
                        "server_error",
                        None,
                        Some("response_normalization_failed"),
                    );
                }
            }
        }

        // All providers exhausted
        if let Some(body) = last_body {
            // Return the last provider's capped error as valid JSON.
            let status = last_status.unwrap_or(502);
            let mut resp_headers = HashMap::new();
            resp_headers.insert("content-type".to_string(), "application/json".to_string());
            PluginResult::RejectBinary {
                status_code: status,
                body: Bytes::from(body),
                headers: resp_headers,
            }
        } else if last_error.is_none()
            && let Some(message) = last_multimodal_rejection
        {
            // No provider was ever dialed and no wire error occurred — every
            // matching provider declined the multimodal request at the policy
            // gate. This is purely a client-input problem, so return a clean
            // 400 (preserving the single-provider behavior) rather than a
            // generic 502.
            self.error_response(400, &message)
        } else {
            self.openai_error_response(
                502,
                &format!(
                    "All AI providers failed for model '{}': {}",
                    model,
                    last_error.unwrap_or_else(|| "unknown error".to_string())
                ),
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

    /// Build a JSON error response using the ai_federation error envelope.
    fn error_response(&self, status: u16, message: &str) -> PluginResult {
        self.json_reject_response(
            status,
            json!({
                "error": {
                    "message": message,
                    "type": "ai_federation_error",
                    "code": status
                }
            }),
        )
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

    fn json_reject_response(&self, status: u16, body: Value) -> PluginResult {
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
        let mut headers = HashMap::new();
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

    /// Maximum raw upstream-error bytes reflected to callers (finding #52).
    pub const MAX_UPSTREAM_ERROR_BYTES: usize = super::MAX_UPSTREAM_ERROR_BYTES;

    pub fn cap_upstream_error_body(body: Vec<u8>) -> Vec<u8> {
        super::cap_upstream_error_body(body)
    }

    /// Maximum characters of the echoed `model` reflected in no-match errors.
    pub const MAX_ECHOED_MODEL_CHARS: usize = super::MAX_ECHOED_MODEL_CHARS;

    /// Expose the no-match `model` echo bounding helper for tests.
    pub fn truncate_model_for_error(model: &str) -> String {
        super::truncate_model_for_error(model)
    }

    /// Expose the native gRPC content-type classifier used to skip gRPC framing.
    pub fn is_native_grpc_content_type(content_type: &str) -> bool {
        crate::proxy::backend_dispatch::is_native_grpc_content_type(content_type.as_bytes())
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
        );

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
        );
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
}

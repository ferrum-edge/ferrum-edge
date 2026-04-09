//! AI Federation Plugin
//!
//! Universal AI gateway that translates OpenAI Chat Completions format to any
//! of 11 supported AI providers and normalizes responses back to OpenAI format.
//!
//! Uses the "terminate and respond" pattern: runs in `before_proxy` at priority
//! 2985, makes its own HTTP call to the matched AI provider via a per-provider
//! `reqwest::Client`, and returns `PluginResult::RejectBinary` with the
//! normalized response. The normal proxy dispatch is skipped entirely.
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
//! Since `RejectBinary` bypasses `on_response_body`, this plugin writes token
//! metadata directly into `ctx.metadata` using the same keys as `ai_token_metrics`.

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::utils::aws_sigv4;
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

/// Cached OAuth2 access token with expiry.
#[derive(Debug, Clone)]
struct CachedToken {
    token: String,
    expires_at: std::time::Instant,
}

/// Thread-safe OAuth2 token cache for Google Vertex AI.
#[derive(Debug)]
struct OAuth2Cache {
    cache: RwLock<Option<CachedToken>>,
    service_account_json: String,
}

impl OAuth2Cache {
    fn new(service_account_json: String) -> Self {
        Self {
            cache: RwLock::new(None),
            service_account_json,
        }
    }

    async fn get_token(&self, http_client: &PluginHttpClient) -> Result<String, String> {
        // Check cache first (read lock)
        {
            let cached = self.cache.read().await;
            if let Some(ref token) = *cached
                && token.expires_at > std::time::Instant::now() + Duration::from_secs(60)
            {
                return Ok(token.token.clone());
            }
        }

        // Refresh token (write lock)
        let mut cached = self.cache.write().await;

        // Double-check after acquiring write lock
        if let Some(ref token) = *cached
            && token.expires_at > std::time::Instant::now() + Duration::from_secs(60)
        {
            return Ok(token.token.clone());
        }

        let token = self.refresh_token(http_client).await?;
        let result = token.token.clone();
        *cached = Some(token);
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
    connect_timeout: Duration,
    read_timeout: Duration,
    // Provider-specific URL parameters
    base_url: Option<String>,
    azure_resource: Option<String>,
    azure_deployment: Option<String>,
    azure_api_version: String,
    google_project_id: Option<String>,
    google_region: Option<String>,
    aws_region: Option<String>,
}

// ---------------------------------------------------------------------------
// Main plugin struct
// ---------------------------------------------------------------------------

pub struct AiFederation {
    providers: Vec<ResolvedProvider>,
    fallback_enabled: bool,
    fallback_status_codes: HashSet<u16>,
    fallback_on_network_errors: bool,
    http_client: PluginHttpClient,
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

impl AiFederation {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let providers_val = config
            .get("providers")
            .and_then(|v| v.as_array())
            .ok_or("ai_federation: 'providers' must be a non-empty array")?;

        if providers_val.is_empty() {
            return Err("ai_federation: 'providers' array must not be empty".to_string());
        }

        let mut providers = Vec::with_capacity(providers_val.len());

        for (i, pv) in providers_val.iter().enumerate() {
            let name = pv["name"]
                .as_str()
                .ok_or(format!("ai_federation: provider[{i}] missing 'name'"))?
                .to_string();

            let provider_type_str = pv["provider_type"].as_str().ok_or(format!(
                "ai_federation: provider '{name}' missing 'provider_type'"
            ))?;
            let provider_type = ProviderType::from_str(provider_type_str)?;

            let priority = pv["priority"].as_u64().unwrap_or((i as u64) + 1) as u32;

            let model_patterns: Vec<String> = pv
                .get("model_patterns")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            let model_mapping: HashMap<String, String> = pv
                .get("model_mapping")
                .and_then(|v| v.as_object())
                .map(|obj| {
                    obj.iter()
                        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                        .collect()
                })
                .unwrap_or_default();

            let default_model = pv["default_model"].as_str().map(String::from);

            let connect_timeout =
                Duration::from_secs(pv["connect_timeout_seconds"].as_u64().unwrap_or(5));
            let read_timeout =
                Duration::from_secs(pv["read_timeout_seconds"].as_u64().unwrap_or(60));

            let base_url = pv["base_url"].as_str().map(String::from);

            let auth = build_auth(provider_type, pv, &name)?;

            let azure_resource = pv["azure_resource"].as_str().map(String::from);
            let azure_deployment = pv["azure_deployment"].as_str().map(String::from);
            let azure_api_version = pv["azure_api_version"]
                .as_str()
                .unwrap_or("2024-06-01")
                .to_string();

            let google_project_id = pv["google_project_id"].as_str().map(String::from);
            let google_region = pv["google_region"].as_str().map(String::from);
            let aws_region = pv
                .get("aws_region")
                .and_then(|v| v.as_str())
                .map(String::from);

            // Validate provider-specific required fields
            validate_provider_config(provider_type, &name, pv)?;

            providers.push(ResolvedProvider {
                name,
                provider_type,
                auth,
                priority,
                model_patterns,
                model_mapping,
                default_model,
                connect_timeout,
                read_timeout,
                base_url,
                azure_resource,
                azure_deployment,
                azure_api_version,
                google_project_id,
                google_region,
                aws_region,
            });
        }

        // Sort by priority (ascending — lower = tried first)
        providers.sort_by_key(|p| p.priority);

        let fallback_enabled = config["fallback_enabled"].as_bool().unwrap_or(true);

        let fallback_status_codes: HashSet<u16> = config
            .get("fallback_on_status_codes")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_u64().map(|n| n as u16))
                    .collect()
            })
            .unwrap_or_else(|| [429, 500, 502, 503].into_iter().collect());

        let fallback_on_network_errors = config["fallback_on_network_errors"]
            .as_bool()
            .unwrap_or(true);

        Ok(Self {
            providers,
            fallback_enabled,
            fallback_status_codes,
            fallback_on_network_errors,
            http_client,
        })
    }
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

/// Simple glob match supporting only `*` as a wildcard (matches any sequence).
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
            pos += found + part.len();
        } else {
            return false;
        }
    }

    // If the pattern doesn't end with *, input must be consumed
    if !pattern.ends_with('*') && pos != input.len() {
        return false;
    }

    true
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
    let mut body = openai_body.clone();
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

fn translate_to_anthropic(
    provider: &ResolvedProvider,
    openai_body: &Value,
    resolved_model: &str,
) -> Result<TranslatedRequest, String> {
    let messages = openai_body["messages"]
        .as_array()
        .ok_or("ai_federation: request missing 'messages' array")?;

    // Extract system messages into a single string
    let system_parts: Vec<&str> = messages
        .iter()
        .filter(|m| m["role"].as_str() == Some("system"))
        .filter_map(|m| m["content"].as_str())
        .collect();

    // Filter to user/assistant messages only
    let filtered_messages: Vec<Value> = messages
        .iter()
        .filter(|m| {
            let role = m["role"].as_str().unwrap_or("");
            role == "user" || role == "assistant"
        })
        .cloned()
        .collect();

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

    // Extract system messages → systemInstruction
    let system_parts: Vec<Value> = messages
        .iter()
        .filter(|m| m["role"].as_str() == Some("system"))
        .filter_map(|m| m["content"].as_str())
        .map(|text| json!({"text": text}))
        .collect();

    // Map user/assistant messages → contents
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
            json!({
                "role": role,
                "parts": [{"text": m["content"].as_str().unwrap_or("")}]
            })
        })
        .collect();

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

    // Extract system messages
    let system_blocks: Vec<Value> = messages
        .iter()
        .filter(|m| m["role"].as_str() == Some("system"))
        .filter_map(|m| m["content"].as_str())
        .map(|text| json!({"text": text}))
        .collect();

    // Map user/assistant messages to Bedrock Converse format
    let bedrock_messages: Vec<Value> = messages
        .iter()
        .filter(|m| {
            let role = m["role"].as_str().unwrap_or("");
            role == "user" || role == "assistant"
        })
        .map(|m| {
            json!({
                "role": m["role"].as_str().unwrap_or("user"),
                "content": [{"text": m["content"].as_str().unwrap_or("")}]
            })
        })
        .collect();

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
    let mut body = openai_body.clone();
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

/// Build the provider-specific URL.
fn build_provider_url(provider: &ResolvedProvider, model: &str) -> String {
    if let Some(ref base) = provider.base_url {
        return base.clone();
    }

    match provider.provider_type {
        ProviderType::AzureOpenAi => {
            let resource = provider.azure_resource.as_deref().unwrap_or("default");
            let deployment = provider.azure_deployment.as_deref().unwrap_or("default");
            format!(
                "https://{}.openai.azure.com/openai/deployments/{}/chat/completions?api-version={}",
                resource, deployment, provider.azure_api_version
            )
        }

        ProviderType::GoogleGemini => {
            format!(
                "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent",
                model
            )
        }

        ProviderType::GoogleVertex => {
            let region = provider.google_region.as_deref().unwrap_or("us-central1");
            let project = provider.google_project_id.as_deref().unwrap_or("default");
            format!(
                "https://{}-aiplatform.googleapis.com/v1/projects/{}/locations/{}/publishers/google/models/{}:generateContent",
                region, project, region, model
            )
        }

        ProviderType::AwsBedrock => {
            let region = provider.aws_region.as_deref().unwrap_or("us-east-1");
            format!(
                "https://bedrock-runtime.{}.amazonaws.com/model/{}/converse",
                region, model
            )
        }

        pt => pt.default_base_url().to_string(),
    }
}

// ---------------------------------------------------------------------------
// Response normalization
// ---------------------------------------------------------------------------

/// Normalize a provider response to OpenAI Chat Completions format.
fn normalize_response(
    provider_type: ProviderType,
    status: u16,
    body: &[u8],
    resolved_model: &str,
) -> Result<(Value, TokenCounts), String> {
    // For error responses, pass through the raw error
    if status >= 400 {
        let error_text = String::from_utf8_lossy(body);
        return Ok((
            json!({
                "error": {
                    "message": format!("Upstream provider returned {}: {}", status, error_text),
                    "type": "upstream_error",
                    "code": status
                }
            }),
            TokenCounts::default(),
        ));
    }

    let resp: Value = serde_json::from_slice(body).map_err(|e| {
        format!(
            "ai_federation: failed to parse provider response: {e} (body: {})",
            String::from_utf8_lossy(&body[..body.len().min(200)])
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
            .timeout(provider.connect_timeout + provider.read_timeout);

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
                Ok(aws_sigv4::sign_request(
                    config,
                    "bedrock",
                    "POST",
                    url,
                    "application/json",
                    payload,
                    &now,
                ))
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
        ctx.method == "POST"
            && ctx
                .headers
                .get("content-type")
                .is_some_and(|ct| ct.to_ascii_lowercase().contains("json"))
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        let mut hostnames = Vec::new();
        for provider in &self.providers {
            // Use a representative model name for URL building
            let model = provider.default_model.as_deref().unwrap_or("placeholder");
            let url = build_provider_url(provider, model);
            if let Ok(parsed) = url::Url::parse(&url)
                && let Some(host) = parsed.host_str()
            {
                hostnames.push(host.to_string());
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
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();
        if !content_type.contains("json") {
            return PluginResult::Continue;
        }

        // Read request body
        let body_str = match ctx.metadata.get("request_body") {
            Some(b) => b.clone(),
            None => {
                debug!("ai_federation: no request_body in metadata, skipping");
                return PluginResult::Continue;
            }
        };

        let openai_body: Value = match serde_json::from_str(&body_str) {
            Ok(v) => v,
            Err(e) => {
                debug!("ai_federation: request body is not valid JSON: {e}");
                return PluginResult::Continue;
            }
        };

        // Extract model from the standard "model" field
        let model = match openai_body["model"].as_str() {
            Some(m) => m.to_string(),
            None => {
                debug!("ai_federation: request missing 'model' field, skipping");
                return PluginResult::Continue;
            }
        };

        // Find matching providers
        let matching_providers = self.find_providers_for_model(&model);
        if matching_providers.is_empty() {
            debug!(
                model = %model,
                "ai_federation: no provider matches model, passing through"
            );
            return PluginResult::Continue;
        }

        // Try providers in priority order with fallback
        let mut last_error: Option<String> = None;
        let mut last_status: Option<u16> = None;
        let mut last_body: Option<Vec<u8>> = None;

        for provider in &matching_providers {
            let resolved_model = Self::resolve_model(provider, &model);

            let translated = match translate_request(provider, &openai_body, &resolved_model) {
                Ok(t) => t,
                Err(e) => {
                    warn!(
                        provider = %provider.name,
                        error = %e,
                        "ai_federation: request translation failed"
                    );
                    last_error = Some(e);
                    if self.fallback_enabled {
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

            if self.should_fallback(&result) {
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
                        last_body = Some(body.clone());
                    }
                }
                continue;
            }

            // No fallback needed — process the response
            let (status, resp_body) = match result {
                Ok(r) => r,
                Err(e) => {
                    return self.error_response(
                        502,
                        &format!("Provider '{}' request failed: {e}", provider.name),
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

                    info!(
                        provider = %provider.name,
                        model = %resolved_model,
                        status = %status,
                        total_tokens = ?token_counts.total_tokens,
                        "ai_federation: request completed"
                    );

                    let response_bytes = serde_json::to_vec(&normalized).unwrap_or_default();
                    let mut resp_headers = HashMap::new();
                    resp_headers.insert("content-type".to_string(), "application/json".to_string());

                    return PluginResult::RejectBinary {
                        status_code: if status >= 400 { status } else { 200 },
                        body: Bytes::from(response_bytes),
                        headers: resp_headers,
                    };
                }
                Err(e) => {
                    warn!(
                        provider = %provider.name,
                        error = %e,
                        "ai_federation: response normalization failed"
                    );
                    return self.error_response(
                        502,
                        &format!(
                            "Provider '{}' response normalization failed: {e}",
                            provider.name
                        ),
                    );
                }
            }
        }

        // All providers exhausted
        if let Some(body) = last_body {
            // Return the last provider's actual error response
            let status = last_status.unwrap_or(502);
            let mut resp_headers = HashMap::new();
            resp_headers.insert("content-type".to_string(), "application/json".to_string());
            PluginResult::RejectBinary {
                status_code: status,
                body: Bytes::from(body),
                headers: resp_headers,
            }
        } else {
            self.error_response(
                502,
                &format!(
                    "All AI providers failed for model '{}': {}",
                    model,
                    last_error.unwrap_or_else(|| "unknown error".to_string())
                ),
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

    /// Build a JSON error response.
    fn error_response(&self, status: u16, message: &str) -> PluginResult {
        let body = json!({
            "error": {
                "message": message,
                "type": "ai_federation_error",
                "code": status
            }
        });
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        PluginResult::RejectBinary {
            status_code: status,
            body: Bytes::from(serde_json::to_vec(&body).unwrap_or_default()),
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

    /// Expose request translation for tests.
    pub fn translate_request_test(
        provider_type: &str,
        openai_body: &Value,
        model: &str,
        provider_config: &Value,
    ) -> Result<TranslatedRequest, String> {
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
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(60),
            base_url: provider_config["base_url"].as_str().map(String::from),
            azure_resource: provider_config["azure_resource"].as_str().map(String::from),
            azure_deployment: provider_config["azure_deployment"]
                .as_str()
                .map(String::from),
            azure_api_version: provider_config["azure_api_version"]
                .as_str()
                .unwrap_or("2024-06-01")
                .to_string(),
            google_project_id: provider_config["google_project_id"]
                .as_str()
                .map(String::from),
            google_region: provider_config["google_region"].as_str().map(String::from),
            aws_region: provider_config["aws_region"].as_str().map(String::from),
        };
        translate_request(&provider, openai_body, model)
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
}

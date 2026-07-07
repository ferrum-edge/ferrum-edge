//! AI Stream Router Plugin
//!
//! Streaming counterpart to [`ai_federation`](super::ai_federation). Gives
//! Ferrum a first-class answer to "can I use Ferrum as my OpenAI-compatible
//! streaming AI gateway?".
//!
//! Unlike `ai_federation` — which uses the buffered "terminate and respond"
//! pattern and rejects `"stream": true` — this plugin claims **only** streaming
//! OpenAI Chat Completions requests and preserves true end-to-end streaming. It
//! runs in `before_proxy` at priority 2984 (after `ai_semantic_cache` at 2980,
//! before `ai_federation` at 4060) and, instead of making its own HTTP call,
//! rewrites the routing decision via `RequestContext.route_override_*` so the
//! normal proxy dispatch path streams the provider response straight back to the
//! client. Provider-native SSE (e.g. Anthropic Messages API events) is
//! normalized to OpenAI `chat.completion.chunk` SSE on the fly via a
//! [`ResponseStreamInspector`], never buffering the full response.
//!
//! ## Coordination with `ai_federation`
//!
//! `ai_stream_router` runs first and, when it claims a streaming request, sets
//! `ctx.metadata["ai_stream_router_claimed"] = "true"`. `ai_federation` checks
//! this at the top of its `before_proxy` and immediately `Continue`s, so the two
//! plugins compose: `stream: true` is handled here, `stream: false` falls
//! through to `ai_federation`.
//!
//! ## MVP scope
//!
//! - `openai` / `openai_compatible`: route + header rewrite; body is passed
//!   through untranslated except optional `stream_options.include_usage`
//!   injection. Provider SSE is already OpenAI-shaped, so it streams through
//!   unchanged (zero-overhead — no inspector).
//! - `anthropic`: OpenAI Chat Completions request is translated to the Anthropic
//!   Messages API streaming request; Anthropic SSE events are normalized back to
//!   OpenAI `chat.completion.chunk` SSE.
//! - `google_gemini`: config is accepted and validated but construction fails
//!   with a clear "not yet implemented" error until the second phase lands.
//!
//! Fallback across providers after the first downstream byte is intentionally
//! out of scope: once response headers/bytes have streamed to the client the
//! provider cannot be switched. `ai_stream_router.fallback_attempts` is always
//! `0` in this MVP.

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use percent_encoding::percent_decode_str;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use tracing::debug;
use url::{Host, Url};

use super::utils::body_transform::{is_event_stream_content_type, is_json_content_type};
use super::{
    Plugin, PluginHttpClient, PluginResult, RequestContext, ResponseStreamAction,
    ResponseStreamInspector,
};
use crate::config::types::{BackendScheme, BackendTlsConfig};

// ---------------------------------------------------------------------------
// Metadata keys
// ---------------------------------------------------------------------------

const META_ENABLED: &str = "ai_stream_router.enabled";
const META_CLAIMED: &str = "ai_stream_router.claimed";
/// Coordination key read by `ai_federation` to skip an already-claimed request.
const META_CLAIMED_COORD: &str = "ai_stream_router_claimed";
/// Coordination key for explicit router pass-through of streaming requests.
const META_PASSTHROUGH_COORD: &str = "ai_stream_router_pass_through";
const META_PROVIDER: &str = "ai_stream_router.provider";
const META_PROVIDER_TYPE: &str = "ai_stream_router.provider_type";
const META_MODEL: &str = "ai_stream_router.model";
const META_NORMALIZED: &str = "ai_stream_router.normalized_response_stream";
const META_FALLBACK_ATTEMPTS: &str = "ai_stream_router.fallback_attempts";
/// Shared marker (same contract as `ai_prompt_shield` / `ai_semantic_firewall`)
/// telling response plugins the request asked for a streaming response.
const META_STREAMING_SHARED: &str = "ai_request_streaming";

// ---------------------------------------------------------------------------
// Provider types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProviderType {
    OpenAi,
    OpenAiCompatible,
    Anthropic,
    GoogleGemini,
}

impl ProviderType {
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "openai" => Ok(Self::OpenAi),
            "openai_compatible" => Ok(Self::OpenAiCompatible),
            "anthropic" => Ok(Self::Anthropic),
            "google_gemini" => Ok(Self::GoogleGemini),
            other => Err(format!(
                "ai_stream_router: unknown provider_type '{other}' (expected openai, openai_compatible, anthropic, google_gemini)"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
            Self::OpenAiCompatible => "openai_compatible",
            Self::Anthropic => "anthropic",
            Self::GoogleGemini => "google_gemini",
        }
    }

    /// Whether provider-native response SSE must be normalized to OpenAI
    /// `chat.completion.chunk` SSE.
    fn needs_response_normalization(self) -> bool {
        matches!(self, Self::Anthropic)
    }

    /// Whether MVP can serve this provider. `google_gemini` is designed into the
    /// config now but not yet implemented.
    fn is_implemented(self) -> bool {
        !matches!(self, Self::GoogleGemini)
    }
}

/// How a provider API key is injected into the forwarded request.
#[derive(Debug, Clone)]
enum ProviderAuth {
    /// `Authorization: Bearer <api_key>`
    Bearer { api_key: String },
    /// A provider-specific header (e.g. `x-api-key` for Anthropic).
    Header { name: String, api_key: String },
}

/// A resolved, ready-to-route streaming provider.
struct StreamProvider {
    name: String,
    provider_type: ProviderType,
    scheme: BackendScheme,
    host: String,
    port: u16,
    /// Absolute backend path (includes leading `/`, no query). May contain a
    /// literal `{model}` placeholder for future Gemini-style path routing.
    path: String,
    /// Endpoint query string (no leading `?`), e.g. Azure-style
    /// `api-version=...`. Merged with the client's own query at claim time.
    endpoint_query: Option<String>,
    /// `Host` header / SNI authority (`host` when the port is the scheme
    /// default, otherwise `host:port`; IPv6 literals are bracketed).
    authority: String,
    priority: u32,
    model_patterns: Vec<String>,
    auth: ProviderAuth,
    /// Anthropic API version header value.
    anthropic_version: String,
    path_has_model_placeholder: bool,
    /// Keep the proxy's own resolved backend TLS (custom CA / SNI / mTLS
    /// client cert) for this HTTPS provider instead of resetting it to
    /// default public-CA verification. For internal `openai_compatible`
    /// endpoints behind private PKI.
    inherit_backend_tls: bool,
}

impl StreamProvider {
    fn matches_model(&self, model: &str) -> bool {
        self.model_patterns
            .iter()
            .any(|pat| simple_glob_match(pat, model))
    }

    /// Whether this provider's response SSE is normalized for `model`, given the
    /// plugin-wide `normalize_response_stream` toggle.
    fn normalizes_response(&self, normalize_response_stream: bool) -> bool {
        normalize_response_stream && self.provider_type.needs_response_normalization()
    }
}

/// Parsed `fallback` block. Stored for admin/observability parity; MVP does not
/// switch providers after the first downstream byte.
#[derive(Debug, Clone)]
struct FallbackConfig {
    enabled: bool,
    on_connect_error: bool,
    on_5xx_before_first_byte: bool,
    max_attempts: u32,
}

impl Default for FallbackConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            on_connect_error: true,
            on_5xx_before_first_byte: true,
            max_attempts: 2,
        }
    }
}

// ---------------------------------------------------------------------------
// Plugin struct
// ---------------------------------------------------------------------------

pub struct AiStreamRouter {
    enabled: bool,
    fail_on_missing_model: bool,
    fail_on_no_matching_provider: bool,
    inject_usage_options: bool,
    normalize_response_stream: bool,
    providers: Vec<StreamProvider>,
    #[allow(dead_code)]
    fallback: FallbackConfig,
    /// Precomputed config-time flag: does any provider need response-stream
    /// normalization (and is normalization enabled)?
    response_stream_hooks: bool,
}

// ---------------------------------------------------------------------------
// Construction / validation
// ---------------------------------------------------------------------------

impl AiStreamRouter {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        if !config.is_object() {
            return Err("ai_stream_router: config must be an object".to_string());
        }

        // Reject ambiguous fields that belong to `ai_federation`'s flat config
        // shape, so an operator does not silently mix a non-streaming fallback
        // config into this plugin (which uses a nested `fallback` block).
        reject_ambiguous_fields(config)?;

        let enabled = optional_bool(config, "enabled")?.unwrap_or(true);
        let fail_on_missing_model = optional_bool(config, "fail_on_missing_model")?.unwrap_or(true);
        let fail_on_no_matching_provider =
            optional_bool(config, "fail_on_no_matching_provider")?.unwrap_or(true);
        let inject_usage_options = optional_bool(config, "inject_usage_options")?.unwrap_or(true);
        let normalize_response_stream =
            optional_bool(config, "normalize_response_stream")?.unwrap_or(true);

        let providers_val = config
            .get("providers")
            .and_then(|v| v.as_array())
            .ok_or("ai_stream_router: 'providers' must be a non-empty array")?;
        if providers_val.is_empty() {
            return Err("ai_stream_router: 'providers' array must not be empty".to_string());
        }

        // Honor the gateway IP allowlist policy (CLI/env/conf/default precedence)
        // for config-time SSRF validation of literal-IP endpoints.
        let backend_allow_ips = http_client.backend_allow_ips().clone();

        let mut providers = Vec::with_capacity(providers_val.len());
        let mut seen_names: HashSet<String> = HashSet::with_capacity(providers_val.len());

        for (i, pv) in providers_val.iter().enumerate() {
            if !pv.is_object() {
                return Err(format!("ai_stream_router: provider[{i}] must be an object"));
            }

            let name = pv["name"]
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or(format!(
                    "ai_stream_router: provider[{i}] missing non-empty 'name'"
                ))?
                .to_string();
            if !seen_names.insert(name.clone()) {
                return Err(format!(
                    "ai_stream_router: duplicate provider name '{name}'"
                ));
            }

            let provider_type_str = pv["provider_type"].as_str().ok_or(format!(
                "ai_stream_router: provider '{name}' missing 'provider_type'"
            ))?;
            let provider_type = ProviderType::from_str(provider_type_str)?;
            if !provider_type.is_implemented() {
                return Err(format!(
                    "ai_stream_router: provider '{name}' provider_type '{}' is not yet implemented in this MVP",
                    provider_type.as_str()
                ));
            }

            let priority_u64 = optional_u64(pv, "priority")?.unwrap_or((i as u64) + 1);
            if priority_u64 == 0 {
                return Err(format!(
                    "ai_stream_router: provider '{name}' priority must be a positive integer"
                ));
            }
            let priority = u32::try_from(priority_u64).map_err(|_| {
                format!("ai_stream_router: provider '{name}' priority is too large")
            })?;

            let model_patterns = optional_string_vec(pv, "model_patterns")?.unwrap_or_default();
            if model_patterns.is_empty() {
                return Err(format!(
                    "ai_stream_router: provider '{name}' requires a non-empty 'model_patterns' array"
                ));
            }

            let endpoint = pv["endpoint"].as_str().ok_or(format!(
                "ai_stream_router: provider '{name}' missing 'endpoint'"
            ))?;
            let allow_plaintext = pv["allow_plaintext"].as_bool().unwrap_or(false);
            let parsed = parse_endpoint(&name, endpoint, allow_plaintext, &backend_allow_ips)?;

            let api_key = config_or_env_str(pv, "api_key").ok_or(format!(
                "ai_stream_router: provider '{name}' missing 'api_key'"
            ))?;
            let auth = build_auth(provider_type, api_key);

            let anthropic_version = pv["anthropic_version"]
                .as_str()
                .unwrap_or("2023-06-01")
                .to_string();

            let inherit_backend_tls = optional_bool(pv, "inherit_backend_tls")?.unwrap_or(false);

            providers.push(StreamProvider {
                name,
                provider_type,
                scheme: parsed.scheme,
                host: parsed.host,
                port: parsed.port,
                path: parsed.path,
                endpoint_query: parsed.query,
                authority: parsed.authority,
                priority,
                model_patterns,
                auth,
                anthropic_version,
                path_has_model_placeholder: parsed.has_model_placeholder,
                inherit_backend_tls,
            });
        }

        // Ascending priority — lowest value is tried first.
        providers.sort_by_key(|p| p.priority);

        let fallback = parse_fallback(config)?;

        let response_stream_hooks = enabled
            && normalize_response_stream
            && providers
                .iter()
                .any(|p| p.provider_type.needs_response_normalization());

        Ok(Self {
            enabled,
            fail_on_missing_model,
            fail_on_no_matching_provider,
            inject_usage_options,
            normalize_response_stream,
            providers,
            fallback,
            response_stream_hooks,
        })
    }

    /// First provider (in priority order) whose patterns match `model`.
    fn select_provider(&self, model: &str) -> Option<&StreamProvider> {
        self.providers.iter().find(|p| p.matches_model(model))
    }

    fn provider_by_name(&self, name: &str) -> Option<&StreamProvider> {
        self.providers.iter().find(|p| p.name == name)
    }
}

/// Fields that belong to `ai_federation`'s flat config surface and would be
/// silently ignored (or misinterpreted) here.
fn reject_ambiguous_fields(config: &Value) -> Result<(), String> {
    const AMBIGUOUS: &[&str] = &[
        "stream",
        "streaming",
        "streaming_enabled",
        "enable_streaming",
        "fallback_enabled",
        "fallback_on_status_codes",
        "fallback_on_network_errors",
    ];
    for field in AMBIGUOUS {
        if config.get(*field).is_some() {
            return Err(format!(
                "ai_stream_router: unsupported field '{field}'; ai_stream_router always claims \"stream\": true requests and configures fallback under the nested 'fallback' block"
            ));
        }
    }
    Ok(())
}

fn parse_fallback(config: &Value) -> Result<FallbackConfig, String> {
    let Some(fb) = config.get("fallback") else {
        return Ok(FallbackConfig::default());
    };
    if !fb.is_object() {
        return Err("ai_stream_router: 'fallback' must be an object".to_string());
    }
    let defaults = FallbackConfig::default();
    Ok(FallbackConfig {
        enabled: optional_bool(fb, "enabled")?.unwrap_or(defaults.enabled),
        on_connect_error: optional_bool(fb, "on_connect_error")?
            .unwrap_or(defaults.on_connect_error),
        on_5xx_before_first_byte: optional_bool(fb, "on_5xx_before_first_byte")?
            .unwrap_or(defaults.on_5xx_before_first_byte),
        max_attempts: optional_u64(fb, "max_attempts")?
            .map(|v| u32::try_from(v).unwrap_or(u32::MAX))
            .unwrap_or(defaults.max_attempts),
    })
}

fn build_auth(provider_type: ProviderType, api_key: String) -> ProviderAuth {
    match provider_type {
        ProviderType::Anthropic => ProviderAuth::Header {
            name: "x-api-key".to_string(),
            api_key,
        },
        ProviderType::GoogleGemini => ProviderAuth::Header {
            name: "x-goog-api-key".to_string(),
            api_key,
        },
        ProviderType::OpenAi | ProviderType::OpenAiCompatible => ProviderAuth::Bearer { api_key },
    }
}

// ---------------------------------------------------------------------------
// Endpoint parsing
// ---------------------------------------------------------------------------

struct ParsedEndpoint {
    scheme: BackendScheme,
    host: String,
    port: u16,
    path: String,
    /// Endpoint query string (no leading `?`), kept separate from `path` so
    /// the request-time router can merge it with the client's own query
    /// instead of producing a second `?` in the forwarded URL.
    query: Option<String>,
    authority: String,
    has_model_placeholder: bool,
}

/// Parse and validate a provider `endpoint` into routing components.
///
/// SSRF defense: `https` is required unless `allow_plaintext: true`, and a
/// literal-IP host is checked against the gateway backend egress policy at
/// construction. Hostnames are re-checked at request time by the shared
/// `DnsCacheResolver` on the normal dispatch path.
fn parse_endpoint(
    provider_name: &str,
    endpoint: &str,
    allow_plaintext: bool,
    backend_allow_ips: &crate::config::BackendEgressPolicy,
) -> Result<ParsedEndpoint, String> {
    // `{model}` is a routing placeholder, not a valid URL character. Swap in a
    // parse-safe token so `Url::parse` accepts the template, then restore it.
    let has_model_placeholder = endpoint.contains("{model}");
    let parse_src = endpoint.replace("{model}", "__FERRUM_MODEL__");

    let parsed = Url::parse(&parse_src).map_err(|e| {
        format!("ai_stream_router: provider '{provider_name}' invalid endpoint '{endpoint}': {e}")
    })?;

    let scheme = match parsed.scheme() {
        "https" => BackendScheme::Https,
        "http" => {
            if !allow_plaintext {
                return Err(format!(
                    "ai_stream_router: provider '{provider_name}' endpoint uses 'http://' which is rejected by default; set 'allow_plaintext: true' on the provider to override"
                ));
            }
            BackendScheme::Http
        }
        other => {
            return Err(format!(
                "ai_stream_router: provider '{provider_name}' endpoint has unsupported scheme '{other}' (expected 'https' or 'http' with allow_plaintext)"
            ));
        }
    };

    let (host, host_is_ipv6) = match parsed.host() {
        Some(Host::Domain(h)) if !h.is_empty() => (h.to_string(), false),
        Some(Host::Ipv4(h)) => (h.to_string(), false),
        Some(Host::Ipv6(h)) => (h.to_string(), true),
        _ => {
            return Err(format!(
                "ai_stream_router: provider '{provider_name}' endpoint '{endpoint}' has no host"
            ));
        }
    };

    if let Ok(ip) = host.parse::<std::net::IpAddr>()
        && !backend_allow_ips.is_allowed(&ip)
    {
        return Err(format!(
            "ai_stream_router: provider '{provider_name}' endpoint IP {ip} denied by backend egress policy ({backend_allow_ips})"
        ));
    }

    let default_port = if scheme == BackendScheme::Https {
        443
    } else {
        80
    };
    let port = parsed.port().unwrap_or(default_port);

    // Rebuild the path and restore the `{model}` placeholder. The endpoint
    // query (Azure-style `api-version=...`) is kept SEPARATE so request-time
    // routing can merge it with the client's own query — folding it into the
    // path would make the dispatch layer append the client query with a
    // second `?`.
    let mut path = parsed.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    let path = path.replace("__FERRUM_MODEL__", "{model}");
    let query = parsed
        .query()
        .filter(|q| !q.is_empty())
        .map(|q| q.replace("__FERRUM_MODEL__", "{model}"));

    // An IPv6 literal must be bracketed in the authority / `Host` header
    // (`[2001:db8::1]:8443`); `Host::Ipv6::to_string()` yields the bare form.
    let authority = match (
        host_is_ipv6,
        parsed.port().is_some() && port != default_port,
    ) {
        (true, true) => format!("[{host}]:{port}"),
        (true, false) => format!("[{host}]"),
        (false, true) => format!("{host}:{port}"),
        (false, false) => host.clone(),
    };

    Ok(ParsedEndpoint {
        scheme,
        host,
        port,
        path,
        query,
        authority,
        has_model_placeholder,
    })
}

// ---------------------------------------------------------------------------
// Config helpers
// ---------------------------------------------------------------------------

fn optional_bool(config: &Value, field: &str) -> Result<Option<bool>, String> {
    match config.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_bool()
            .map(Some)
            .ok_or_else(|| format!("ai_stream_router: '{field}' must be a boolean")),
    }
}

fn optional_u64(config: &Value, field: &str) -> Result<Option<u64>, String> {
    match config.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("ai_stream_router: '{field}' must be an unsigned integer")),
    }
}

fn optional_string_vec(config: &Value, field: &str) -> Result<Option<Vec<String>>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(values) = value.as_array() else {
        return Err(format!("ai_stream_router: '{field}' must be an array"));
    };
    let mut out = Vec::with_capacity(values.len());
    for v in values {
        let Some(s) = v.as_str() else {
            return Err(format!(
                "ai_stream_router: '{field}' must contain only strings"
            ));
        };
        if s.is_empty() {
            return Err(format!(
                "ai_stream_router: '{field}' must not contain empty strings"
            ));
        }
        out.push(s.to_string());
    }
    Ok(Some(out))
}

/// Read a config string, resolving a `${ENV_VAR}` reference against the process
/// environment.
fn config_or_env_str(config: &Value, field: &str) -> Option<String> {
    let raw = config.get(field).and_then(|v| v.as_str())?;
    if raw.is_empty() {
        return None;
    }
    if let Some(var) = raw
        .strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
    {
        return std::env::var(var).ok().filter(|v| !v.is_empty());
    }
    Some(raw.to_string())
}

// ---------------------------------------------------------------------------
// Model matching (glob)
// ---------------------------------------------------------------------------

/// Characters a `*` wildcard is not allowed to consume — mirrors
/// `ai_federation` so a permissive `model_patterns` glob cannot smuggle
/// URL-structural separators into a routed model name.
const GLOB_WILDCARD_FORBIDDEN_CHARS: &[char] = &['/', '?', '#', '&', '\\', ' ', '\t', '\n', '\r'];

/// Glob match supporting only `*` (matching any run of characters except the
/// forbidden set). The pattern is anchored to both ends of `input`.
fn simple_glob_match(pattern: &str, input: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == input;
    }

    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if let Some(found) = input[pos..].find(part) {
            if i == 0 && found != 0 {
                return false;
            }
            let gap = &input[pos..pos + found];
            if gap.contains(GLOB_WILDCARD_FORBIDDEN_CHARS) {
                return false;
            }
            pos += found + part.len();
        } else {
            return false;
        }
    }

    if !pattern.ends_with('*') && pos != input.len() {
        return false;
    }
    if pattern.ends_with('*') && input[pos..].contains(GLOB_WILDCARD_FORBIDDEN_CHARS) {
        return false;
    }
    true
}

/// `"stream": true` (a real boolean) is the only signal that claims a request.
fn request_wants_streaming(openai_body: &Value) -> bool {
    openai_body["stream"].as_bool() == Some(true)
}

// ---------------------------------------------------------------------------
// Request translation
// ---------------------------------------------------------------------------

/// Inject `stream_options.include_usage = true` into an OpenAI-compatible body
/// so the provider emits a final usage event. Returns the mutated body only when
/// a change was made.
fn inject_include_usage(body: &[u8]) -> Option<Vec<u8>> {
    let mut value: Value = serde_json::from_slice(body).ok()?;
    let obj = value.as_object_mut()?;
    let already = obj
        .get("stream_options")
        .and_then(|so| so.get("include_usage"))
        .and_then(Value::as_bool)
        == Some(true);
    if already {
        return None;
    }
    let entry = obj.entry("stream_options").or_insert_with(|| json!({}));
    if let Some(so) = entry.as_object_mut() {
        so.insert("include_usage".to_string(), Value::Bool(true));
    } else {
        *entry = json!({ "include_usage": true });
    }
    serde_json::to_vec(&value).ok()
}

/// OpenAI message roles that map to the Anthropic top-level `system` string.
fn is_system_role(role: &str) -> bool {
    role == "system" || role == "developer"
}

/// Flatten OpenAI message `content` (string or content-part array) to plain
/// text. MVP Anthropic translation is text-first; non-text parts are dropped.
fn flatten_content_text(content: &Value) -> String {
    if let Some(s) = content.as_str() {
        return s.to_string();
    }
    let Some(parts) = content.as_array() else {
        return String::new();
    };
    let mut out = String::new();
    for part in parts {
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
    out
}

/// Translate an OpenAI Chat Completions streaming request into an Anthropic
/// Messages API streaming request body.
fn translate_to_anthropic(openai_body: &Value, model: &str) -> Vec<u8> {
    let empty: Vec<Value> = Vec::new();
    let messages = openai_body["messages"].as_array().unwrap_or(&empty);

    let system_parts: Vec<String> = messages
        .iter()
        .filter(|m| m["role"].as_str().is_some_and(is_system_role))
        .map(|m| flatten_content_text(&m["content"]))
        .filter(|s| !s.is_empty())
        .collect();

    let translated_messages: Vec<Value> = messages
        .iter()
        .filter(|m| {
            let role = m["role"].as_str().unwrap_or("");
            role == "user" || role == "assistant"
        })
        .map(|m| {
            let role = m["role"].as_str().unwrap_or("user");
            json!({
                "role": role,
                "content": flatten_content_text(&m["content"]),
            })
        })
        .collect();

    let max_tokens = openai_body["max_tokens"]
        .as_u64()
        .or_else(|| openai_body["max_completion_tokens"].as_u64())
        .unwrap_or(4096);

    let mut body = json!({
        "model": model,
        "messages": translated_messages,
        "max_tokens": max_tokens,
        "stream": true,
    });

    if !system_parts.is_empty() {
        body["system"] = Value::String(system_parts.join("\n\n"));
    }
    if let Some(temp) = openai_body.get("temperature") {
        body["temperature"] = temp.clone();
    }
    if let Some(top_p) = openai_body.get("top_p") {
        body["top_p"] = top_p.clone();
    }
    if let Some(stop) = openai_body.get("stop") {
        body["stop_sequences"] = normalize_stop_sequences(stop);
    }
    if let Some(tools) = translate_tools(openai_body.get("tools")) {
        body["tools"] = tools;
    }
    if let Some(choice) = translate_tool_choice(openai_body.get("tool_choice")) {
        body["tool_choice"] = choice;
    }

    serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec())
}

/// Anthropic `stop_sequences` is always an array of strings.
fn normalize_stop_sequences(stop: &Value) -> Value {
    match stop {
        Value::String(s) => json!([s]),
        Value::Array(_) => stop.clone(),
        _ => Value::Array(Vec::new()),
    }
}

/// Translate OpenAI `tools` (`{type:function, function:{name, description,
/// parameters}}`) into Anthropic `tools` (`{name, description, input_schema}`).
fn translate_tools(tools: Option<&Value>) -> Option<Value> {
    let arr = tools?.as_array()?;
    let mut out = Vec::with_capacity(arr.len());
    for tool in arr {
        let func = tool.get("function").unwrap_or(tool);
        let Some(name) = func.get("name").and_then(Value::as_str) else {
            continue;
        };
        let mut entry = json!({
            "name": name,
            "input_schema": func.get("parameters").cloned().unwrap_or_else(|| json!({"type": "object"})),
        });
        if let Some(desc) = func.get("description").and_then(Value::as_str) {
            entry["description"] = Value::String(desc.to_string());
        }
        out.push(entry);
    }
    if out.is_empty() {
        None
    } else {
        Some(Value::Array(out))
    }
}

fn translate_tool_choice(choice: Option<&Value>) -> Option<Value> {
    match choice? {
        Value::String(s) => match s.as_str() {
            "auto" => Some(json!({"type": "auto"})),
            "required" | "any" => Some(json!({"type": "any"})),
            // Anthropic has no "none"; omit so the model is free to answer.
            "none" => None,
            _ => None,
        },
        Value::Object(_) => {
            let name = choice?
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(Value::as_str)?;
            Some(json!({"type": "tool", "name": name}))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// OpenAI error envelope
// ---------------------------------------------------------------------------

fn openai_error_response(
    status_code: u16,
    message: &str,
    error_type: &str,
    param: Option<&str>,
    code: Option<&str>,
) -> PluginResult {
    let body = json!({
        "error": {
            "message": message,
            "type": error_type,
            "param": param,
            "code": code,
        }
    });
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    PluginResult::Reject {
        status_code,
        body: body.to_string(),
        headers,
    }
}

// ---------------------------------------------------------------------------
// Plugin impl
// ---------------------------------------------------------------------------

#[async_trait]
impl Plugin for AiStreamRouter {
    fn name(&self) -> &str {
        "ai_stream_router"
    }

    fn priority(&self) -> u16 {
        super::priority::AI_STREAM_ROUTER
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_ONLY_PROTOCOLS
    }

    fn modifies_request_headers(&self) -> bool {
        // Claimed requests strip client auth and inject provider auth + host.
        self.enabled
    }

    fn modifies_request_body(&self) -> bool {
        // Anthropic translation and optional usage injection rewrite the body.
        self.enabled
    }

    fn requires_request_body_before_before_proxy(&self) -> bool {
        self.enabled
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        if !self.enabled || ctx.method != "POST" {
            return false;
        }
        ctx.headers
            .get("content-type")
            .is_some_and(|ct| is_json_content_type(ct))
    }

    fn requires_response_stream_hooks(&self) -> bool {
        self.response_stream_hooks
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.providers.iter().map(|p| p.host.clone()).collect()
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !self.enabled || ctx.method != "POST" {
            return PluginResult::Continue;
        }
        let content_type = headers
            .get("content-type")
            .map(String::as_str)
            .unwrap_or("");
        if !is_json_content_type(content_type) {
            return PluginResult::Continue;
        }

        // Only a UTF-8 JSON body can carry an OpenAI streaming request. A
        // missing/non-UTF-8 body is not a request we claim — let the
        // non-streaming path (`ai_federation`) apply its own policy.
        let Some(body_str) = ctx.metadata.get("request_body") else {
            return PluginResult::Continue;
        };
        let openai_body: Value = match serde_json::from_str(body_str) {
            Ok(v) => v,
            Err(_) => return PluginResult::Continue,
        };

        // Claim ONLY streaming requests. Non-streaming requests continue to
        // `ai_federation`.
        if !request_wants_streaming(&openai_body) {
            return PluginResult::Continue;
        }

        // Extract the model.
        let model = match openai_body.get("model") {
            Some(Value::String(m)) if !m.is_empty() => m.clone(),
            _ => {
                if self.fail_on_missing_model {
                    return openai_error_response(
                        400,
                        "Missing or invalid 'model' field: expected a non-empty string",
                        "invalid_request_error",
                        Some("model"),
                        Some("missing_model"),
                    );
                }
                ctx.metadata
                    .insert(META_PASSTHROUGH_COORD.to_string(), "true".to_string());
                ctx.metadata
                    .insert(META_STREAMING_SHARED.to_string(), "true".to_string());
                return PluginResult::Continue;
            }
        };

        // Select a provider by model pattern + priority.
        let Some(provider) = self.select_provider(&model) else {
            if self.fail_on_no_matching_provider {
                return openai_error_response(
                    404,
                    &format!(
                        "No ai_stream_router provider is configured for model '{}'",
                        truncate_for_error(&model)
                    ),
                    "invalid_request_error",
                    Some("model"),
                    Some("model_not_found"),
                );
            }
            ctx.metadata
                .insert(META_PASSTHROUGH_COORD.to_string(), "true".to_string());
            ctx.metadata
                .insert(META_STREAMING_SHARED.to_string(), "true".to_string());
            return PluginResult::Continue;
        };

        // Guard against URL injection for providers that embed the model in the
        // backend path.
        if provider.path_has_model_placeholder && !is_valid_url_model_component(&model) {
            return openai_error_response(
                400,
                "Invalid 'model' field: contains characters not permitted in a URL path component",
                "invalid_request_error",
                Some("model"),
                Some("invalid_model"),
            );
        }

        let mut backend_path = if provider.path_has_model_placeholder {
            provider.path.replace("{model}", &model)
        } else {
            provider.path.clone()
        };

        // Merge an endpoint-configured query (Azure-style `api-version=...`)
        // with the client's own query. The dispatch layer appends the
        // (post-strip) client query with `?`, so when the endpoint carries its
        // own query we fold BOTH into the override path joined by `&` and mark
        // every client parameter for strip — otherwise the forwarded URL would
        // contain a second `?`. Endpoints without a query keep the normal
        // client-query forwarding untouched.
        if let Some(endpoint_query) = provider.endpoint_query.as_deref() {
            let endpoint_query = if provider.path_has_model_placeholder {
                endpoint_query.replace("{model}", &model)
            } else {
                endpoint_query.to_string()
            };
            backend_path.push('?');
            backend_path.push_str(&endpoint_query);
            let endpoint_query_names = decoded_query_names(&endpoint_query);
            let raw_client_query = ctx
                .raw_query_string()
                .filter(|q| !q.is_empty())
                .map(str::to_string);
            let client_query = raw_client_query
                .as_deref()
                .map(|q| query_after_strip_markers(ctx, q, &endpoint_query_names))
                .filter(|q| !q.is_empty());
            if let Some(client_query) = client_query {
                backend_path.push('&');
                backend_path.push_str(client_query.as_str());
            }
            if let Some(raw_client_query) = raw_client_query {
                mark_client_query_params_consumed(ctx, &raw_client_query);
            }
        }

        // --- Rewrite the routing decision (no internal HTTP call). ---
        ctx.route_override_backend_scheme = Some(provider.scheme);
        ctx.route_override_backend_host = Some(provider.host.clone());
        ctx.route_override_backend_port = Some(provider.port);
        ctx.route_override_path = Some(backend_path);
        ctx.route_override_path_is_absolute = true;
        ctx.route_override_authority = Some(provider.authority.clone());
        // Default: public providers verify against the system trust store.
        // `inherit_backend_tls: true` carries the current proxy's resolved
        // backend TLS (custom CA / SNI policy / backend mTLS client cert) to
        // internal openai_compatible endpoints, including TLS inherited from an
        // upstream selected before this provider override.
        if provider.scheme == BackendScheme::Https {
            ctx.route_override_resolved_tls = if provider.inherit_backend_tls {
                ctx.matched_proxy
                    .as_ref()
                    .map(|proxy| proxy.resolved_tls.clone())
            } else {
                Some(BackendTlsConfig::default_verify())
            };
        }

        // --- Rewrite headers: strip client credentials, insert provider auth. ---
        strip_client_credentials(headers);
        match &provider.auth {
            ProviderAuth::Bearer { api_key } => {
                headers.insert("authorization".to_string(), format!("Bearer {api_key}"));
            }
            ProviderAuth::Header { name, api_key } => {
                headers.insert(name.clone(), api_key.clone());
            }
        }
        if provider.provider_type == ProviderType::Anthropic {
            headers.insert(
                "anthropic-version".to_string(),
                provider.anthropic_version.clone(),
            );
        }
        headers.insert("host".to_string(), provider.authority.clone());
        headers.insert("content-type".to_string(), "application/json".to_string());
        // A provider streams SSE; make the intent explicit to the upstream.
        headers.insert("accept".to_string(), "text/event-stream".to_string());

        // --- Metadata (observability + downstream-hook coordination). ---
        let normalizes = provider.normalizes_response(self.normalize_response_stream);
        ctx.metadata
            .insert(META_ENABLED.to_string(), "true".to_string());
        ctx.metadata
            .insert(META_CLAIMED.to_string(), "true".to_string());
        ctx.metadata
            .insert(META_CLAIMED_COORD.to_string(), "true".to_string());
        // Shared marker: the request asked for a streaming response. Response
        // plugins (e.g. `ai_response_guard`) use it to stay on the streaming
        // path even when the client did not send `Accept: text/event-stream`;
        // without it the provider SSE would be buffered until completion.
        ctx.metadata
            .insert(META_STREAMING_SHARED.to_string(), "true".to_string());
        // The provider is a third party: the proxy must not append the
        // gateway-asserted `x-consumer-*` identity headers after the
        // credential strip below (see the suppression contract on
        // `RequestContext::backend_consumer_username`).
        ctx.metadata.insert(
            super::SUPPRESS_CONSUMER_IDENTITY_HEADERS_KEY.to_string(),
            "true".to_string(),
        );
        ctx.metadata
            .insert(META_PROVIDER.to_string(), provider.name.clone());
        ctx.metadata.insert(
            META_PROVIDER_TYPE.to_string(),
            provider.provider_type.as_str().to_string(),
        );
        ctx.metadata.insert(META_MODEL.to_string(), model);
        ctx.metadata
            .insert(META_NORMALIZED.to_string(), normalizes.to_string());
        ctx.metadata
            .insert(META_FALLBACK_ATTEMPTS.to_string(), "0".to_string());

        debug!(
            provider = %provider.name,
            provider_type = %provider.provider_type.as_str(),
            normalized = normalizes,
            "ai_stream_router: claimed streaming request and rewrote route to provider"
        );

        PluginResult::Continue
    }

    async fn transform_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        body: &[u8],
        _content_type: Option<&str>,
        _request_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        if !self.enabled || ctx.metadata.get(META_CLAIMED).map(String::as_str) != Some("true") {
            return None;
        }
        let provider_name = ctx.metadata.get(META_PROVIDER)?;
        let provider = self.provider_by_name(provider_name)?;
        let model = ctx.metadata.get(META_MODEL)?.clone();

        match provider.provider_type {
            ProviderType::Anthropic => {
                let openai_body: Value = serde_json::from_slice(body).ok()?;
                Some(translate_to_anthropic(&openai_body, &model))
            }
            ProviderType::OpenAi | ProviderType::OpenAiCompatible => {
                if self.inject_usage_options {
                    inject_include_usage(body)
                } else {
                    None
                }
            }
            // Unreachable: google_gemini fails construction in this MVP.
            ProviderType::GoogleGemini => None,
        }
    }

    fn forces_reqwest_dispatch(&self, ctx: &RequestContext) -> bool {
        // Force the reqwest streaming path only for claimed requests whose SSE
        // will be normalized, so the response-stream inspector is guaranteed to
        // be wired. Requests we pass through unchanged stay on the fast path.
        self.response_stream_hooks
            && ctx.metadata.get(META_NORMALIZED).map(String::as_str) == Some("true")
    }

    fn response_stream_inspector(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        content_type: Option<&str>,
    ) -> Option<Box<dyn ResponseStreamInspector>> {
        if !self.response_stream_hooks {
            return None;
        }
        if ctx.metadata.get(META_NORMALIZED).map(String::as_str) != Some("true") {
            return None;
        }
        // Only normalize a successful event stream; a non-2xx/non-SSE body is an
        // error envelope that should reach the client untouched.
        if !(200..300).contains(&response_status) {
            return None;
        }
        if !content_type.is_some_and(is_event_stream_content_type) {
            return None;
        }
        let model = ctx
            .metadata
            .get(META_MODEL)
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        Some(Box::new(AnthropicSseNormalizer::new(model)))
    }

    async fn transform_response_body_with_context(
        &self,
        ctx: &mut RequestContext,
        body: &[u8],
        content_type: Option<&str>,
        _response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        if !self.response_stream_hooks {
            return None;
        }
        if ctx.metadata.get(META_NORMALIZED).map(String::as_str) != Some("true") {
            return None;
        }
        if !content_type.is_some_and(is_event_stream_content_type) {
            return None;
        }
        let model = ctx
            .metadata
            .get(META_MODEL)
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        normalize_anthropic_sse_buffered(model, body).await
    }
}

/// Strip client-supplied credential headers so they never leak to the provider.
///
/// Unlike `ai_federation` (which builds a fresh provider request), this
/// route-override path forwards the client's own header map, so
/// session-bearing headers (`cookie`, `proxy-authorization`) must be stripped
/// alongside the API-key/auth headers or browser/application session
/// credentials would reach the third-party provider.
fn strip_client_credentials(headers: &mut HashMap<String, String>) {
    const CREDENTIAL_HEADERS: &[&str] = &[
        "authorization",
        "proxy-authorization",
        "cookie",
        "x-api-key",
        "api-key",
        "x-goog-api-key",
        "anthropic-version",
        "anthropic-beta",
        "openai-beta",
        "openai-organization",
        "openai-project",
    ];
    // Header keys in the map are already lowercased by the proxy, but match
    // case-insensitively to be safe against any future change.
    headers.retain(|k, _| {
        let lk = k.to_ascii_lowercase();
        !CREDENTIAL_HEADERS.contains(&lk.as_str())
    });
}

fn decoded_query_names(query: &str) -> HashSet<String> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| pair.split_once('=').map_or(pair, |(name, _)| name))
        .map(|name| percent_decode_str(name).decode_utf8_lossy().into_owned())
        .collect()
}

fn query_after_strip_markers(
    ctx: &RequestContext,
    query: &str,
    endpoint_query_names: &HashSet<String>,
) -> String {
    let strip_names: HashSet<&str> = ctx
        .metadata
        .keys()
        .filter_map(|key| {
            key.strip_prefix(super::utils::token_extract::STRIP_QUERY_PARAM_METADATA_PREFIX)
        })
        .collect();
    if strip_names.is_empty() && endpoint_query_names.is_empty() {
        return query.to_string();
    }

    let mut stripped = String::with_capacity(query.len());
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let raw_name = pair.split_once('=').map_or(pair, |(name, _)| name);
        let decoded_name = percent_decode_str(raw_name).decode_utf8_lossy();
        if strip_names.contains(raw_name)
            || strip_names.contains(decoded_name.as_ref())
            || endpoint_query_names.contains(decoded_name.as_ref())
        {
            continue;
        }
        if !stripped.is_empty() {
            stripped.push('&');
        }
        stripped.push_str(pair);
    }
    stripped
}

fn mark_client_query_params_consumed(ctx: &mut RequestContext, query: &str) {
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let raw_name = pair.split_once('=').map_or(pair, |(name, _)| name);
        ctx.metadata.insert(
            format!(
                "{}{raw_name}",
                super::utils::token_extract::STRIP_QUERY_PARAM_METADATA_PREFIX
            ),
            "true".to_string(),
        );
    }
}

/// Cap a user-controlled model string before echoing it in an error message.
fn truncate_for_error(model: &str) -> String {
    const MAX: usize = 64;
    if model.chars().count() <= MAX {
        return model.to_string();
    }
    let truncated: String = model.chars().take(MAX).collect();
    format!("{truncated}…")
}

/// Validate that a model is safe to substitute into a URL path component.
fn is_valid_url_model_component(model: &str) -> bool {
    if model.is_empty() || model.contains("..") {
        return false;
    }
    model
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-' || b == b':')
}

// ---------------------------------------------------------------------------
// Anthropic SSE → OpenAI chat.completion.chunk SSE normalizer
// ---------------------------------------------------------------------------

/// Upper bound on bytes buffered in `carry` while waiting for one SSE event's
/// blank-line boundary. Real Anthropic events are a few KiB (text/tool-arg
/// deltas are chunked small); a provider that streams an enormous or
/// never-terminated event would otherwise accumulate unbounded memory while
/// producing no downstream bytes (especially with the response-size limit
/// disabled). Overflow fails safe: emit an SSE error event + `[DONE]` and
/// terminate the stream.
const MAX_SSE_EVENT_CARRY_BYTES: usize = 1024 * 1024;

/// Stateful, per-response inspector that transcodes Anthropic Messages API SSE
/// events into OpenAI `chat.completion.chunk` SSE. Robust to chunk splits: raw
/// bytes accumulate in `carry` and only complete SSE events are transcoded.
struct AnthropicSseNormalizer {
    carry: Vec<u8>,
    model: String,
    stream_id: Option<String>,
    created: i64,
    role_emitted: bool,
    done_emitted: bool,
    /// Anthropic content-block index → OpenAI `tool_calls` index.
    tool_indices: HashMap<u64, u32>,
    next_tool_index: u32,
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
}

impl AnthropicSseNormalizer {
    fn new(model: String) -> Self {
        Self {
            carry: Vec::new(),
            model,
            stream_id: None,
            created: Utc::now().timestamp(),
            role_emitted: false,
            done_emitted: false,
            tool_indices: HashMap::new(),
            next_tool_index: 0,
            prompt_tokens: None,
            completion_tokens: None,
        }
    }

    fn id(&mut self) -> String {
        if let Some(id) = &self.stream_id {
            return id.clone();
        }
        let id = format!("chatcmpl-stream-{}", self.created);
        self.stream_id = Some(id.clone());
        id
    }

    /// Envelope a single OpenAI streaming `choices[0].delta` as an SSE line.
    fn chunk_line(&mut self, delta: Value, finish_reason: Option<&str>) -> String {
        let id = self.id();
        let payload = json!({
            "id": id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": [{
                "index": 0,
                "delta": delta,
                "finish_reason": finish_reason,
            }],
        });
        format!("data: {payload}\n\n")
    }

    fn usage_line(&mut self) -> Option<String> {
        let (Some(p), Some(c)) = (self.prompt_tokens, self.completion_tokens) else {
            return None;
        };
        let id = self.id();
        let payload = json!({
            "id": id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": [],
            "usage": {
                "prompt_tokens": p,
                "completion_tokens": c,
                "total_tokens": p + c,
            },
        });
        Some(format!("data: {payload}\n\n"))
    }

    /// Transcode one Anthropic event JSON into zero or more OpenAI SSE lines.
    fn transcode_event(&mut self, event: &Value, out: &mut String) {
        match event.get("type").and_then(Value::as_str) {
            Some("message_start") => {
                let message = &event["message"];
                if let Some(id) = message.get("id").and_then(Value::as_str) {
                    self.stream_id = Some(id.to_string());
                }
                if let Some(m) = message.get("model").and_then(Value::as_str) {
                    self.model = m.to_string();
                }
                if let Some(tokens) = message["usage"]["input_tokens"].as_u64() {
                    self.prompt_tokens = Some(tokens);
                }
                if !self.role_emitted {
                    self.role_emitted = true;
                    out.push_str(&self.chunk_line(json!({ "role": "assistant" }), None));
                }
            }
            Some("content_block_start") => {
                let index = event["index"].as_u64().unwrap_or(0);
                let block = &event["content_block"];
                if block.get("type").and_then(Value::as_str) == Some("tool_use") {
                    let tool_index = self.next_tool_index;
                    self.next_tool_index += 1;
                    self.tool_indices.insert(index, tool_index);
                    let id = block.get("id").and_then(Value::as_str).unwrap_or("");
                    let name = block.get("name").and_then(Value::as_str).unwrap_or("");
                    out.push_str(&self.chunk_line(
                        json!({
                            "tool_calls": [{
                                "index": tool_index,
                                "id": id,
                                "type": "function",
                                "function": { "name": name, "arguments": "" },
                            }]
                        }),
                        None,
                    ));
                }
            }
            Some("content_block_delta") => {
                let index = event["index"].as_u64().unwrap_or(0);
                let delta = &event["delta"];
                match delta.get("type").and_then(Value::as_str) {
                    Some("text_delta") => {
                        if let Some(text) = delta.get("text").and_then(Value::as_str) {
                            self.ensure_role(out);
                            out.push_str(&self.chunk_line(json!({ "content": text }), None));
                        }
                    }
                    Some("input_json_delta") => {
                        if let Some(partial) = delta.get("partial_json").and_then(Value::as_str) {
                            let tool_index = self.tool_indices.get(&index).copied().unwrap_or(0);
                            out.push_str(&self.chunk_line(
                                json!({
                                    "tool_calls": [{
                                        "index": tool_index,
                                        "function": { "arguments": partial },
                                    }]
                                }),
                                None,
                            ));
                        }
                    }
                    // thinking_delta / signature_delta and unknown deltas carry
                    // no OpenAI-visible content in this MVP.
                    _ => {}
                }
            }
            Some("message_delta") => {
                if let Some(tokens) = event["usage"]["output_tokens"].as_u64() {
                    self.completion_tokens = Some(tokens);
                }
                let finish = map_stop_reason(event["delta"]["stop_reason"].as_str());
                out.push_str(&self.chunk_line(json!({}), Some(finish)));
            }
            Some("message_stop") => {
                self.finish(out);
            }
            Some("error") => {
                let message = event["error"]["message"]
                    .as_str()
                    .unwrap_or("upstream provider stream error");
                let err = json!({
                    "error": {
                        "message": message,
                        "type": "upstream_error",
                    }
                });
                out.push_str(&format!("data: {err}\n\n"));
                self.finish(out);
            }
            // ping, content_block_stop, and unknown events produce no output.
            _ => {}
        }
    }

    fn ensure_role(&mut self, out: &mut String) {
        if !self.role_emitted {
            self.role_emitted = true;
            out.push_str(&self.chunk_line(json!({ "role": "assistant" }), None));
        }
    }

    /// Emit the final usage chunk (when available) and the OpenAI `[DONE]`
    /// sentinel exactly once.
    fn finish(&mut self, out: &mut String) {
        if self.done_emitted {
            return;
        }
        self.done_emitted = true;
        if let Some(usage) = self.usage_line() {
            out.push_str(&usage);
        }
        out.push_str("data: [DONE]\n\n");
    }

    /// Drain every complete SSE event currently buffered, transcoding each.
    fn drain(&mut self, out: &mut String) {
        while let Some(end) = next_event_boundary(&self.carry) {
            let raw: Vec<u8> = self.carry.drain(..end).collect();
            if let Some(data) = extract_sse_data(&raw)
                && let Ok(event) = serde_json::from_str::<Value>(&data)
            {
                self.transcode_event(&event, out);
            }
        }
    }
}

#[async_trait]
impl ResponseStreamInspector for AnthropicSseNormalizer {
    async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction {
        if self.done_emitted {
            return ResponseStreamAction::Forward(Bytes::new());
        }
        self.carry.extend_from_slice(chunk);
        let mut out = String::new();
        self.drain(&mut out);
        // Per-event bound: after draining every complete event, whatever is
        // left is one partial event. If it exceeds the cap the provider is
        // streaming a pathological/never-terminated event — fail safe by
        // ending the OpenAI stream with an error event instead of buffering
        // without bound.
        if self.carry.len() > MAX_SSE_EVENT_CARRY_BYTES {
            self.carry.clear();
            self.carry.shrink_to_fit();
            let err = json!({
                "error": {
                    "message": "upstream provider sent an oversized SSE event; stream terminated",
                    "type": "upstream_error",
                }
            });
            out.push_str(&format!("data: {err}\n\n"));
            self.finish(&mut out);
            return ResponseStreamAction::Terminate(Some(Bytes::from(out.into_bytes())));
        }
        ResponseStreamAction::Forward(Bytes::from(out.into_bytes()))
    }

    async fn on_end(&mut self) -> ResponseStreamAction {
        if self.done_emitted {
            return ResponseStreamAction::Forward(Bytes::new());
        }
        let mut out = String::new();
        self.drain(&mut out);
        // Transcode any trailing event that lacked a final blank-line boundary.
        if !self.carry.is_empty() {
            let raw = std::mem::take(&mut self.carry);
            if let Some(data) = extract_sse_data(&raw)
                && let Ok(event) = serde_json::from_str::<Value>(&data)
            {
                self.transcode_event(&event, &mut out);
            }
        }
        // Guarantee the client sees a clean OpenAI stream termination even if the
        // provider ended without a `message_stop`.
        self.finish(&mut out);
        ResponseStreamAction::Forward(Bytes::from(out.into_bytes()))
    }
}

async fn normalize_anthropic_sse_buffered(model: String, body: &[u8]) -> Option<Vec<u8>> {
    let mut normalizer = AnthropicSseNormalizer::new(model);
    let mut out = Vec::new();
    match normalizer.on_chunk(body).await {
        ResponseStreamAction::Forward(bytes) => out.extend_from_slice(&bytes),
        ResponseStreamAction::Terminate(bytes) => {
            if let Some(bytes) = bytes {
                out.extend_from_slice(&bytes);
            }
            return Some(out);
        }
    }
    match normalizer.on_end().await {
        ResponseStreamAction::Forward(bytes) | ResponseStreamAction::Terminate(Some(bytes)) => {
            out.extend_from_slice(&bytes)
        }
        ResponseStreamAction::Terminate(None) => {}
    }
    Some(out)
}

fn map_stop_reason(reason: Option<&str>) -> &'static str {
    match reason {
        Some("max_tokens") => "length",
        Some("tool_use") => "tool_calls",
        // end_turn, stop_sequence, and anything else → "stop".
        _ => "stop",
    }
}

/// Index just past the first complete SSE event boundary (a blank line), or
/// `None` if no complete event is buffered yet. Handles both `\n\n` and
/// `\r\n\r\n` terminators.
fn next_event_boundary(buf: &[u8]) -> Option<usize> {
    let lf = find_subslice(buf, b"\n\n").map(|i| i + 2);
    let crlf = find_subslice(buf, b"\r\n\r\n").map(|i| i + 4);
    match (lf, crlf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Extract and concatenate the `data:` payload lines of one raw SSE event.
/// Returns `None` when the event carries no `data:` line (e.g. a comment or a
/// lone `event:` line).
fn extract_sse_data(raw: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(raw).ok()?;
    let mut data = String::new();
    let mut found = false;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("data:") {
            found = true;
            let rest = rest.strip_prefix(' ').unwrap_or(rest);
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(rest);
        }
    }
    if found { Some(data) } else { None }
}

//! AI Stream Router Plugin
//!
//! Streaming counterpart to [`ai_federation`](super::ai_federation). Gives
//! Ferrum a first-class answer to "can I use Ferrum as my OpenAI-compatible
//! streaming AI gateway?".
//!
//! Unlike `ai_federation` — which uses the buffered "terminate and respond"
//! pattern and rejects `"stream": true` — this plugin claims **only** streaming
//! OpenAI Chat Completions requests and preserves true end-to-end streaming. It
//! runs in `before_proxy` at priority 2984 (before `ai_semantic_cache` at 4057,
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
//!   Messages API streaming request (including assistant `tool_calls` /
//!   matching `role: "tool"` results and legacy assistant `function_call` /
//!   matching `role: "function"` results); Anthropic SSE events are normalized
//!   back to OpenAI `chat.completion.chunk` SSE. OpenAI `tool_choice: "none"`
//!   becomes Anthropic `{"type":"none"}` with the tools list retained;
//!   unsupported tool_choice values and forced tool use with manual extended
//!   thinking (`thinking.type: "enabled"`) are rejected at admission. Adaptive
//!   thinking may combine with OpenAI `required` / named choices. Provider
//!   `tool_use` under a none constraint fails closed instead of becoming OpenAI
//!   `tool_calls`. Normalization requires Anthropic `message_stop` (or an
//!   explicit provider `error`) before emitting a success-shaped terminal
//!   sequence; premature EOF / malformed events fail closed with an
//!   upstream-error SSE frame. Requests that will be normalized strip
//!   `Accept-Encoding`, and residual `Content-Encoding` is decoded (gzip / br)
//!   or rejected before SSE parsing so response headers describe identity
//!   bytes.
//! - `google_gemini`: config is accepted and validated but construction fails
//!   with a clear "not yet implemented" error until the second phase lands.
//!
//! ## Provider fallback is rejected, not stored
//!
//! This plugin does **not** implement provider fallback, and a `fallback`
//! config block is rejected at admission rather than parsed into an inert
//! policy (issue #3328). Post-first-byte provider switching remains prohibited
//! for the obvious reason — once response headers/bytes have streamed to the
//! client the provider cannot be changed — but *pre*-first-byte fallback is
//! also unimplementable at this layer, because the routing decision this plugin
//! makes is committed exactly once and then consumed by the ordinary dispatch
//! path:
//!
//! - `before_proxy` writes the provider's scheme/host/port/path/authority and
//!   `route_override_resolved_tls` into [`RequestContext`]; the proxy bakes
//!   those into a single effective `Arc<Proxy>` (`apply_route_overrides*`)
//!   before any backend attempt.
//! - The provider credential, `Host`, `anthropic-version`, and
//!   `Accept-Encoding` policy are written into one request header map that the
//!   dispatch loop borrows immutably for every attempt.
//! - The provider-specific request body (Anthropic Messages translation vs.
//!   OpenAI passthrough) is produced once by
//!   `transform_request_body_with_context` and verified once by
//!   `on_final_request_body_with_context`; the proxy guards that pipeline with
//!   `request_body_prepared` so it cannot re-run.
//! - The dispatch retry loop replays those exact prepared bytes and headers
//!   against the same effective proxy, rotating only the load-balancer target
//!   within one upstream. It has no per-attempt re-preparation boundary.
//!
//! A second provider needs a different endpoint/authority, different
//! credentials, a different backend TLS resolution, a different translated
//! body, and a different response-normalization decision — none of which are
//! per-attempt today. Nor can the plugin retry internally: [`PluginResult`] can
//! only short-circuit with a fully materialized body, so a plugin-owned
//! fallback loop would have to buffer the entire SSE response and destroy the
//! streaming contract this plugin exists to provide. Accepting a `fallback`
//! block would therefore be worse than rejecting it: an operator could submit
//! valid-looking failover policy and silently receive none. Admission fails
//! closed instead.

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use percent_encoding::percent_decode_str;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use tracing::debug;
use url::{Host, Url};

use super::utils::body_transform::{is_event_stream_content_type, is_json_content_type};
use super::utils::content_encoding::{DecodeLimits, decode_content_encoding};
use super::{
    Plugin, PluginHttpClient, PluginResult, RequestContext, ResponseStreamAction,
    ResponseStreamInspector, ResponseStreamInspectorStage,
};
use crate::config::types::{BackendScheme, BackendTlsConfig};
use crate::util::unknown_keys::reject_unknown_keys;

/// Exact response fields invalidated when Anthropic SSE is normalized.
///
/// Derived from the shared representation-invalidation inventory so trailer
/// policy cannot drift from the header rewrite. The three extra fields are
/// owned directly by [`repair_normalized_representation_headers`].
static AI_STREAM_ROUTER_RESPONSE_POLICY_NAMES: std::sync::LazyLock<Vec<String>> =
    std::sync::LazyLock::new(|| {
        let mut names = Vec::with_capacity(super::TRANSFORM_INVALIDATED_RESPONSE_HEADERS.len() + 3);
        names.extend(
            super::TRANSFORM_INVALIDATED_RESPONSE_HEADERS
                .iter()
                .map(|name| (*name).to_string()),
        );
        names.extend(
            ["content-encoding", "content-length", "vary"]
                .into_iter()
                .map(str::to_string),
        );
        names
    });

/// Open-ended checksum families invalidated by the same normalization.
static AI_STREAM_ROUTER_RESPONSE_POLICY_PREFIXES: std::sync::LazyLock<Vec<String>> =
    std::sync::LazyLock::new(|| {
        super::TRANSFORM_INVALIDATED_RESPONSE_HEADER_PREFIXES
            .iter()
            .map(|prefix| (*prefix).to_string())
            .collect()
    });

// ---------------------------------------------------------------------------
// Strict config key sets (fixed-shape objects; no free-form maps)
// ---------------------------------------------------------------------------

/// Accepted root keys for `ai_stream_router` config objects.
pub const AI_STREAM_ROUTER_CONFIG_KEYS: &[&str] = &[
    "enabled",
    "fail_on_missing_model",
    "fail_on_no_matching_provider",
    "inject_usage_options",
    "normalize_response_stream",
    "providers",
];

/// Accepted keys for each `providers[]` entry.
pub const AI_STREAM_ROUTER_PROVIDER_KEYS: &[&str] = &[
    "name",
    "provider_type",
    "endpoint",
    "api_key",
    "model_patterns",
    "priority",
    "allow_plaintext",
    "anthropic_version",
    "inherit_backend_tls",
];

/// Admission diagnostic for the rejected `fallback` block (issue #3328).
///
/// The plugin never switches providers, so storing a fallback policy could only
/// ever be runtime-inert. See the module docs for why pre-first-byte fallback
/// cannot be expressed at this layer.
pub const AI_STREAM_ROUTER_FALLBACK_REJECTION: &str = "ai_stream_router: unsupported field 'fallback'; provider fallback is not implemented — this plugin commits one provider route, credential set, backend TLS resolution, and translated body before dispatch and never switches providers, so a stored fallback policy would be silently inert. Remove the 'fallback' block.";

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
const META_REQUEST_TRANSLATED: &str = "ai_stream_router.request_translated";
/// Set when the translated Anthropic request carries `tool_choice: {"type":"none"}`.
/// Request-local only: the response normalizer fails closed if the provider
/// nevertheless emits `tool_use` for that generation.
const META_TOOL_CHOICE_NONE: &str = "ai_stream_router.tool_choice_none";
/// Provider `Content-Encoding` that must be decoded before Anthropic SSE
/// normalization. Stamped in `after_proxy` before representation headers are
/// repaired so both streaming and buffered normalizers see the same coding.
const META_PROVIDER_ENCODING: &str = "ai_stream_router.provider_content_encoding";
/// Shared marker (same contract as `ai_prompt_shield` / `ai_semantic_firewall`)
/// telling response plugins the request asked for a streaming response.
const META_STREAMING_SHARED: &str = "ai_request_streaming";

/// Bound decoding of residual provider content codings before SSE normalization.
const NORMALIZE_DECODE_LIMITS: DecodeLimits = DecodeLimits {
    max_decoded_bytes: 8 * 1024 * 1024,
    max_cumulative_bytes: 16 * 1024 * 1024,
    max_codings: 4,
    max_amplification_ratio: 0,
};

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
#[derive(Clone)]
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
    /// Precomputed config-time flag: does any provider need response-stream
    /// normalization (and is normalization enabled)?
    response_stream_hooks: bool,
}

// ---------------------------------------------------------------------------
// Construction / validation
// ---------------------------------------------------------------------------

impl AiStreamRouter {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let config_object = config
            .as_object()
            .ok_or_else(|| "ai_stream_router: config must be an object".to_string())?;

        // Reject ambiguous fields that belong to `ai_federation`'s flat config
        // shape, plus the `fallback` block this plugin cannot honor, BEFORE the
        // generic unknown-key sweep so both get a specific diagnostic.
        reject_ambiguous_fields(config)?;
        reject_unknown_keys(
            config_object,
            "config",
            AI_STREAM_ROUTER_CONFIG_KEYS,
            "ai_stream_router: ",
        )?;

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
            let provider_object = pv
                .as_object()
                .ok_or_else(|| format!("ai_stream_router: provider[{i}] must be an object"))?;
            let provider_path = format!("config.providers[{i}]");
            reject_unknown_keys(
                provider_object,
                &provider_path,
                AI_STREAM_ROUTER_PROVIDER_KEYS,
                "ai_stream_router: ",
            )?;

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
/// silently ignored (or misinterpreted) here, plus the `fallback` block this
/// plugin refuses to store (issue #3328).
///
/// The `fallback` rejection is deliberately a *separate*, more specific
/// diagnostic than the generic unknown-key path: an operator submitting a
/// well-formed failover policy needs to be told the capability does not exist,
/// not that they made a typo.
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
                "ai_stream_router: unsupported field '{field}'; ai_stream_router always claims \"stream\": true requests and does not implement provider fallback"
            ));
        }
    }
    // Any presence at all — object, empty object, `null`, or scalar — is
    // refused. A policy that cannot be honored must never be admitted.
    if config.get("fallback").is_some() {
        return Err(AI_STREAM_ROUTER_FALLBACK_REJECTION.to_string());
    }
    Ok(())
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

#[derive(Clone)]
struct ParsedToolCall {
    id: String,
    name: String,
    arguments: Value,
}

/// Upper bound on a tool/function-call `arguments` JSON string (bytes).
const MAX_TOOL_ARGUMENTS_BYTES: usize = 256 * 1024;
/// Upper bound on a modern tool-call or tool-result ID (bytes).
const MAX_TOOL_CALL_ID_BYTES: usize = 128;

fn valid_tool_call_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_TOOL_CALL_ID_BYTES
}

fn valid_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

#[derive(Clone, Copy)]
enum ToolArgumentsField {
    Modern {
        message_index: usize,
        tool_index: usize,
    },
    Legacy {
        message_index: usize,
    },
}

impl ToolArgumentsField {
    fn error(self, detail: &str) -> String {
        match self {
            Self::Modern {
                message_index,
                tool_index,
            } => format!("messages[{message_index}].tool_calls[{tool_index}] {detail}"),
            Self::Legacy { message_index } => {
                format!("messages[{message_index}].function_call {detail}")
            }
        }
    }
}

fn legacy_tool_use_id(message_index: usize) -> String {
    format!("call_legacy_{message_index}")
}

fn parse_tool_arguments_object(
    arguments: &str,
    field: ToolArgumentsField,
) -> Result<Value, String> {
    if arguments.len() > MAX_TOOL_ARGUMENTS_BYTES {
        return Err(field.error("arguments exceed the maximum allowed size"));
    }
    let parsed: Value = serde_json::from_str(arguments).map_err(|_| {
        // Field-specific only: never echo argument bytes (may hold credentials).
        field.error("arguments are not valid JSON")
    })?;
    if !parsed.is_object() {
        return Err(field.error("arguments must encode a JSON object"));
    }
    Ok(parsed)
}

fn parse_openai_tool_calls(
    message: &Value,
    message_index: usize,
) -> Result<Vec<ParsedToolCall>, String> {
    let Some(tool_calls_value) = message.get("tool_calls") else {
        return Ok(Vec::new());
    };
    if tool_calls_value.is_null() {
        return Ok(Vec::new());
    }
    let tool_calls = tool_calls_value
        .as_array()
        .ok_or_else(|| format!("messages[{message_index}].tool_calls must be an array"))?;
    if tool_calls.is_empty() {
        return Err(format!(
            "messages[{message_index}].tool_calls must not be empty"
        ));
    }

    let mut parsed = Vec::with_capacity(tool_calls.len());
    for (tool_index, call) in tool_calls.iter().enumerate() {
        let call_object = call.as_object().ok_or_else(|| {
            format!("messages[{message_index}].tool_calls[{tool_index}] must be an object")
        })?;
        if call_object.get("type").and_then(Value::as_str) != Some("function") {
            return Err(format!(
                "messages[{message_index}].tool_calls[{tool_index}] must have type 'function'"
            ));
        }
        let id = call_object
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| valid_tool_call_id(value))
            .ok_or_else(|| {
                format!("messages[{message_index}].tool_calls[{tool_index}] missing id")
            })?;
        let function = call_object
            .get("function")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                format!("messages[{message_index}].tool_calls[{tool_index}] missing function")
            })?;
        let name = function
            .get("name")
            .and_then(Value::as_str)
            .filter(|value| valid_tool_name(value))
            .ok_or_else(|| {
                format!(
                    "messages[{message_index}].tool_calls[{tool_index}] has invalid function name"
                )
            })?;
        let arguments = function
            .get("arguments")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!(
                    "messages[{message_index}].tool_calls[{tool_index}] arguments must be a JSON string"
                )
            })?;
        let arguments = parse_tool_arguments_object(
            arguments,
            ToolArgumentsField::Modern {
                message_index,
                tool_index,
            },
        )?;
        parsed.push(ParsedToolCall {
            id: id.to_string(),
            name: name.to_string(),
            arguments,
        });
    }
    Ok(parsed)
}

/// Parse a legacy OpenAI assistant `function_call` into one Anthropic-bound tool use.
///
/// Absent / JSON `null` means no legacy call. A non-null value must be a single
/// `{name, arguments}` object; parallel legacy calls are not representable.
fn parse_openai_function_call(
    message: &Value,
    message_index: usize,
) -> Result<Option<ParsedToolCall>, String> {
    let Some(function_call_value) = message.get("function_call") else {
        return Ok(None);
    };
    if function_call_value.is_null() {
        return Ok(None);
    }
    let function_call = function_call_value
        .as_object()
        .ok_or_else(|| format!("messages[{message_index}].function_call must be an object"))?;
    let name = function_call
        .get("name")
        .and_then(Value::as_str)
        .filter(|value| valid_tool_name(value))
        .ok_or_else(|| {
            format!("messages[{message_index}].function_call has invalid function name")
        })?;
    let arguments = function_call
        .get("arguments")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            format!("messages[{message_index}].function_call.arguments must be a JSON string")
        })?;
    let arguments =
        parse_tool_arguments_object(arguments, ToolArgumentsField::Legacy { message_index })?;
    let id = legacy_tool_use_id(message_index);
    Ok(Some(ParsedToolCall {
        id,
        name: name.to_string(),
        arguments,
    }))
}

fn tool_result_text(content: &Value) -> Result<String, String> {
    if let Some(text) = content.as_str() {
        return Ok(text.to_string());
    }
    if content.is_null() {
        return Ok(String::new());
    }
    let parts = content
        .as_array()
        .ok_or("tool message content must be a string or text-parts array")?;
    let mut text = String::new();
    for (index, part) in parts.iter().enumerate() {
        if part.get("type").and_then(Value::as_str) != Some("text") {
            return Err(format!("tool message content[{index}] must be a text part"));
        }
        text.push_str(
            part.get("text")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("tool message content[{index}] missing text"))?,
        );
    }
    Ok(text)
}

fn anthropic_text_content_blocks(text: &str) -> Vec<Value> {
    if text.is_empty() {
        Vec::new()
    } else {
        vec![json!({ "type": "text", "text": text })]
    }
}

/// Validate OpenAI message history that will be translated to Anthropic.
/// Fail closed on malformed tool calls/results rather than silently dropping them.
///
/// Modern (`tool_calls` / `role: "tool"`) and legacy (`function_call` /
/// `role: "function"`) rounds may coexist when each round is complete. Crossing
/// the result shape while either round is pending is rejected as ambiguous.
fn validate_openai_tool_history(messages: &[Value]) -> Result<(), String> {
    let mut tool_call_ids = HashSet::new();
    let mut pending_tool_results = HashSet::new();
    let mut pending_legacy: Option<(String, String)> = None;
    for (index, message) in messages.iter().enumerate() {
        let message_object = message
            .as_object()
            .ok_or_else(|| format!("messages[{index}] must be an object"))?;
        let role = message_object
            .get("role")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("messages[{index}] missing string role"))?;
        if !matches!(
            role,
            "system" | "developer" | "user" | "assistant" | "tool" | "function"
        ) {
            return Err(format!("messages[{index}] has unsupported role '{role}'"));
        }

        let has_tool_calls = message_object
            .get("tool_calls")
            .is_some_and(|value| !value.is_null());
        let legacy_call = parse_openai_function_call(message, index)?;
        let has_legacy_call = legacy_call.is_some();

        if has_tool_calls && has_legacy_call {
            return Err(format!(
                "messages[{index}] must not combine tool_calls and function_call"
            ));
        }
        if has_tool_calls && role != "assistant" {
            return Err(format!(
                "messages[{index}] tool_calls are only valid on assistant messages"
            ));
        }
        if has_legacy_call && role != "assistant" {
            return Err(format!(
                "messages[{index}].function_call is only valid on assistant messages"
            ));
        }

        if role == "function" && !pending_tool_results.is_empty() {
            return Err(format!(
                "messages[{index}] mixes modern tool_calls and legacy function_call history"
            ));
        }
        if role == "tool" && pending_legacy.is_some() {
            return Err(format!(
                "messages[{index}] mixes modern tool_calls and legacy function_call history"
            ));
        }
        if role != "tool" && !pending_tool_results.is_empty() {
            return Err(format!(
                "messages[{index}] appears before results for every preceding assistant tool call"
            ));
        }
        if role != "function" && pending_legacy.is_some() {
            return Err(format!(
                "messages[{index}] appears before the result for the preceding assistant function_call"
            ));
        }

        match message_object.get("content") {
            Some(Value::String(_)) | Some(Value::Array(_)) => {}
            Some(Value::Null) | None
                if role == "assistant" && (has_tool_calls || has_legacy_call) => {}
            Some(Value::Null) | None if role == "tool" || role == "function" => {}
            _ if matches!(role, "system" | "developer" | "user" | "assistant") => {
                return Err(format!(
                    "messages[{index}] content must be a string or content-parts array"
                ));
            }
            _ => {}
        }

        if role == "assistant" {
            let tool_calls = parse_openai_tool_calls(message, index)?;
            if tool_calls.is_empty()
                && legacy_call.is_none()
                && flatten_content_text(message_object.get("content").unwrap_or(&Value::Null))
                    .is_empty()
            {
                return Err(format!(
                    "messages[{index}] has no Anthropic-representable content"
                ));
            }
            if !tool_calls.is_empty() {
                for call in tool_calls {
                    if !tool_call_ids.insert(call.id.clone()) {
                        return Err(format!("messages[{index}] repeats a tool-call id"));
                    }
                    pending_tool_results.insert(call.id);
                }
            }
            if let Some(call) = legacy_call {
                if !tool_call_ids.insert(call.id.clone()) {
                    return Err(format!("messages[{index}] repeats a tool-call id"));
                }
                pending_legacy = Some((call.id, call.name));
            }
        }

        if role == "tool" {
            let tool_call_id = message_object
                .get("tool_call_id")
                .and_then(Value::as_str)
                .filter(|value| valid_tool_call_id(value))
                .ok_or_else(|| format!("messages[{index}] tool message missing tool_call_id"))?;
            if !pending_tool_results.remove(tool_call_id) {
                return Err(format!(
                    "messages[{index}] tool_call_id has no unmatched preceding assistant tool call"
                ));
            }
            tool_result_text(message_object.get("content").unwrap_or(&Value::Null))
                .map_err(|error| format!("messages[{index}] {error}"))?;
        }

        if role == "function" {
            let name = message_object
                .get("name")
                .and_then(Value::as_str)
                .filter(|value| valid_tool_name(value))
                .ok_or_else(|| format!("messages[{index}] function message has invalid name"))?;
            let Some((_pending_id, pending_name)) = pending_legacy.take() else {
                return Err(format!(
                    "messages[{index}] function result has no unmatched preceding assistant function_call"
                ));
            };
            if name != pending_name {
                return Err(format!(
                    "messages[{index}].name does not match the pending function_call"
                ));
            }
            tool_result_text(message_object.get("content").unwrap_or(&Value::Null))
                .map_err(|error| format!("messages[{index}] {error}"))?;
        }
    }
    if !pending_tool_results.is_empty() {
        return Err("assistant tool calls are missing one or more tool results".to_string());
    }
    if pending_legacy.is_some() {
        return Err("assistant function_call is missing its function result".to_string());
    }
    Ok(())
}

fn validate_anthropic_translation(openai_body: &Value) -> Result<(), String> {
    let messages = openai_body
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| "request missing 'messages' array".to_string())?;
    validate_openai_tool_history(messages)?;
    let tool_choice = resolve_anthropic_tool_choice(openai_body)?;
    resolve_anthropic_thinking(openai_body, tool_choice.as_ref().map(|(kind, _)| *kind))?;
    Ok(())
}

/// OpenAI `tool_choice` kinds that Anthropic translation understands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ToolChoiceKind {
    None,
    Auto,
    /// OpenAI `required` → Anthropic `{"type":"any"}`.
    ForcedAny,
    ForcedNamed,
}

fn openai_declared_tool_names(openai_body: &Value) -> Result<Option<Vec<&str>>, String> {
    let Some(tools) = openai_body.get("tools") else {
        return Ok(None);
    };
    if tools.is_null() {
        return Ok(None);
    }
    let arr = tools
        .as_array()
        .ok_or_else(|| "unsupported or malformed tools".to_string())?;
    if arr.is_empty() {
        return Ok(None);
    }
    let mut names = Vec::with_capacity(arr.len());
    for tool in arr {
        let func = tool.get("function").unwrap_or(tool);
        let name = func
            .get("name")
            .and_then(Value::as_str)
            .filter(|value| valid_tool_name(value))
            .ok_or_else(|| "unsupported or malformed tools".to_string())?;
        names.push(name);
    }
    Ok(Some(names))
}

/// Effective Anthropic `max_tokens` this route forwards (OpenAI `max_tokens`,
/// else `max_completion_tokens`, else the translation default).
fn anthropic_effective_max_tokens(openai_body: &Value) -> u64 {
    openai_body["max_tokens"]
        .as_u64()
        .or_else(|| openai_body["max_completion_tokens"].as_u64())
        .unwrap_or(4096)
}

/// Map supported OpenAI `tool_choice` values to Anthropic's object form.
/// Unsupported, malformed, or ambiguous values fail closed — never silently
/// dropped into the provider default (`auto` when tools are present).
fn resolve_anthropic_tool_choice(
    openai_body: &Value,
) -> Result<Option<(ToolChoiceKind, Value)>, String> {
    let Some(choice) = openai_body.get("tool_choice") else {
        return Ok(None);
    };
    if choice.is_null() {
        return Ok(None);
    }

    let (kind, translated) = match choice {
        Value::String(value) => match value.as_str() {
            "none" => (ToolChoiceKind::None, json!({ "type": "none" })),
            "auto" => (ToolChoiceKind::Auto, json!({ "type": "auto" })),
            // OpenAI Chat Completions string form; Anthropic `any` is the
            // translated object type, not an accepted OpenAI input string.
            "required" => (ToolChoiceKind::ForcedAny, json!({ "type": "any" })),
            _ => {
                return Err("unsupported or malformed tool_choice".to_string());
            }
        },
        Value::Object(object) => {
            // Closed OpenAI shape: {type:"function", function:{name:...}}.
            if object.len() != 2 || object.get("type").and_then(Value::as_str) != Some("function") {
                return Err("unsupported or malformed tool_choice".to_string());
            }
            let function = object
                .get("function")
                .and_then(Value::as_object)
                .ok_or_else(|| "unsupported or malformed tool_choice".to_string())?;
            if function.len() != 1 {
                return Err("unsupported or malformed tool_choice".to_string());
            }
            let name = function
                .get("name")
                .and_then(Value::as_str)
                .filter(|value| valid_tool_name(value))
                .ok_or_else(|| "unsupported or malformed tool_choice".to_string())?;
            (
                ToolChoiceKind::ForcedNamed,
                json!({ "type": "tool", "name": name }),
            )
        }
        _ => return Err("unsupported or malformed tool_choice".to_string()),
    };

    let tools = openai_declared_tool_names(openai_body)?;
    if kind != ToolChoiceKind::None && tools.is_none() {
        return Err("tool_choice requires a non-empty tools array".to_string());
    }
    if kind == ToolChoiceKind::ForcedNamed {
        let name = translated
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| "unsupported or malformed tool_choice".to_string())?;
        if !tools.as_ref().is_some_and(|names| names.contains(&name)) {
            return Err("named tool_choice does not match any declared tool".to_string());
        }
    }

    Ok(Some((kind, translated)))
}

/// Forward closed Anthropic thinking shapes when present. Manual extended
/// thinking (`type: "enabled"`) cannot combine with forced tool use; adaptive
/// thinking may. Budget must satisfy Anthropic's ordinary contract relative to
/// the effective `max_tokens` this route forwards.
fn resolve_anthropic_thinking(
    openai_body: &Value,
    tool_choice_kind: Option<ToolChoiceKind>,
) -> Result<Option<Value>, String> {
    let Some(thinking) = openai_body.get("thinking") else {
        return Ok(None);
    };
    if thinking.is_null() {
        return Ok(None);
    }
    let object = thinking
        .as_object()
        .ok_or_else(|| "unsupported or malformed thinking".to_string())?;
    let thinking_type = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| "unsupported or malformed thinking".to_string())?;

    let forwarded = match thinking_type {
        "enabled" => {
            // Closed shape: exactly `type` and `budget_tokens`.
            if object.len() != 2 || !object.contains_key("budget_tokens") {
                return Err("unsupported or malformed thinking".to_string());
            }
            let budget_value = object
                .get("budget_tokens")
                .ok_or_else(|| "unsupported or malformed thinking".to_string())?;
            if !budget_value.is_u64() {
                return Err("unsupported or malformed thinking".to_string());
            }
            let budget = budget_value
                .as_u64()
                .ok_or_else(|| "unsupported or malformed thinking".to_string())?;
            let max_tokens = anthropic_effective_max_tokens(openai_body);
            // Ordinary Anthropic contract: budget_tokens >= 1024 and strictly
            // less than the forwarded max_tokens (this route does not opt into
            // interleaved manual thinking via anthropic-beta).
            if budget < 1024 || budget >= max_tokens {
                return Err("unsupported or malformed thinking".to_string());
            }
            if matches!(
                tool_choice_kind,
                Some(ToolChoiceKind::ForcedAny | ToolChoiceKind::ForcedNamed)
            ) {
                return Err("forced tool_choice is incompatible with extended thinking".to_string());
            }
            json!({ "type": "enabled", "budget_tokens": budget })
        }
        "adaptive" => {
            if object.len() != 1 {
                return Err("unsupported or malformed thinking".to_string());
            }
            json!({ "type": "adaptive" })
        }
        "disabled" => {
            if object.len() != 1 {
                return Err("unsupported or malformed thinking".to_string());
            }
            json!({ "type": "disabled" })
        }
        _ => return Err("unsupported or malformed thinking".to_string()),
    };

    Ok(Some(forwarded))
}

/// Translate an OpenAI Chat Completions streaming request into an Anthropic
/// Messages API streaming request body. Preserves assistant `tool_calls` and
/// matching `role: "tool"` results, plus legacy assistant `function_call` and
/// matching `role: "function"` results; rejects malformed history instead of
/// dropping it.
fn translate_to_anthropic(openai_body: &Value, model: &str) -> Result<Vec<u8>, String> {
    let messages = openai_body
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| "request missing 'messages' array".to_string())?;
    validate_anthropic_translation(openai_body)?;

    let system_parts: Vec<String> = messages
        .iter()
        .filter(|m| m["role"].as_str().is_some_and(is_system_role))
        .map(|m| flatten_content_text(&m["content"]))
        .filter(|s| !s.is_empty())
        .collect();

    let mut translated_messages = Vec::with_capacity(messages.len());
    let mut pending_legacy_by_name: HashMap<String, String> = HashMap::new();
    let mut message_index = 0;
    while message_index < messages.len() {
        let message = &messages[message_index];
        let role = message["role"].as_str().unwrap_or("");
        if is_system_role(role) {
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
                    format!("messages[{message_index}] tool message missing tool_call_id")
                })?;
                let mut block = json!({
                    "type": "tool_result",
                    "tool_use_id": tool_use_id,
                    "content": tool_result_text(&tool_message["content"])
                        .map_err(|error| format!("messages[{message_index}] {error}"))?,
                });
                if tool_message.get("is_error").and_then(Value::as_bool) == Some(true) {
                    block["is_error"] = Value::Bool(true);
                }
                tool_results.push(block);
                message_index += 1;
            }
            translated_messages.push(json!({
                "role": "user",
                "content": tool_results
            }));
            continue;
        }
        if role == "function" {
            let mut tool_results = Vec::new();
            while message_index < messages.len()
                && messages[message_index]["role"].as_str() == Some("function")
            {
                let function_message = &messages[message_index];
                let name = function_message["name"]
                    .as_str()
                    .filter(|value| valid_tool_name(value))
                    .ok_or_else(|| {
                        format!("messages[{message_index}] function message has invalid name")
                    })?;
                let tool_use_id = pending_legacy_by_name.remove(name).ok_or_else(|| {
                    format!(
                        "messages[{message_index}] function result has no unmatched preceding assistant function_call"
                    )
                })?;
                let mut block = json!({
                    "type": "tool_result",
                    "tool_use_id": tool_use_id,
                    "content": tool_result_text(&function_message["content"])
                        .map_err(|error| format!("messages[{message_index}] {error}"))?,
                });
                if function_message.get("is_error").and_then(Value::as_bool) == Some(true) {
                    block["is_error"] = Value::Bool(true);
                }
                tool_results.push(block);
                message_index += 1;
            }
            translated_messages.push(json!({
                "role": "user",
                "content": tool_results
            }));
            continue;
        }
        if role != "user" && role != "assistant" {
            return Err(format!(
                "messages[{message_index}] has unsupported role '{role}'"
            ));
        }

        let text = flatten_content_text(&message["content"]);
        let tool_calls = if role == "assistant" {
            parse_openai_tool_calls(message, message_index)?
        } else {
            Vec::new()
        };
        let legacy_call = if role == "assistant" {
            parse_openai_function_call(message, message_index)?
        } else {
            None
        };
        let content = if tool_calls.is_empty() && legacy_call.is_none() {
            if text.is_empty() && role == "assistant" {
                return Err(format!(
                    "messages[{message_index}] has no Anthropic-representable content"
                ));
            }
            Value::String(text)
        } else {
            let mut content = anthropic_text_content_blocks(&text);
            for call in tool_calls {
                content.push(json!({
                    "type": "tool_use",
                    "id": call.id,
                    "name": call.name,
                    "input": call.arguments,
                }));
            }
            if let Some(call) = legacy_call {
                pending_legacy_by_name.insert(call.name.clone(), call.id.clone());
                content.push(json!({
                    "type": "tool_use",
                    "id": call.id,
                    "name": call.name,
                    "input": call.arguments,
                }));
            }
            Value::Array(content)
        };
        translated_messages.push(json!({
            "role": role,
            "content": content,
        }));
        message_index += 1;
    }

    if !pending_legacy_by_name.is_empty() {
        return Err("assistant function_call is missing its function result".to_string());
    }

    let max_tokens = anthropic_effective_max_tokens(openai_body);

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
    let tool_choice = resolve_anthropic_tool_choice(openai_body)?;
    if let Some((_, choice)) = &tool_choice {
        body["tool_choice"] = choice.clone();
    }
    if let Some(thinking) =
        resolve_anthropic_thinking(openai_body, tool_choice.as_ref().map(|(kind, _)| *kind))?
    {
        body["thinking"] = thinking;
    }

    serde_json::to_vec(&body)
        .map_err(|error| format!("failed to serialize Anthropic body: {error}"))
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

    fn enforces_finalized_request_policy(&self) -> bool {
        true
    }

    fn modifies_request_headers(&self) -> bool {
        // Claimed requests strip client auth and inject provider auth + host.
        self.enabled
    }

    fn modifies_request_destination(&self) -> bool {
        // Claimed requests replace the backend scheme/host/port, authority,
        // and path with the selected provider destination.
        self.enabled
    }

    fn modifies_request_body(&self) -> bool {
        // Anthropic translation and optional usage injection rewrite the body.
        self.enabled
    }

    fn needs_final_request_body_context(&self) -> bool {
        // Request translation consumes the provider/model decision recorded by
        // `before_proxy`, and the final hook verifies that the translation
        // completed. The H1/H2 dispatch path only supplies that metadata when
        // this capability is advertised.
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

        // Fail closed on Anthropic tool-history / tool_choice / thinking shapes
        // that cannot be represented safely before the route override commits.
        if provider.provider_type == ProviderType::Anthropic
            && let Err(message) = validate_anthropic_translation(&openai_body)
        {
            let (param, code) = if message.contains("thinking") {
                (Some("thinking"), Some("invalid_thinking"))
            } else if message.contains("tool_choice") || message.contains("tools") {
                (Some("tool_choice"), Some("invalid_tool_choice"))
            } else {
                (Some("messages"), Some("invalid_messages"))
            };
            return openai_error_response(
                400,
                &format!("Invalid request for Anthropic translation: {message}"),
                "invalid_request_error",
                param,
                code,
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
        // Normalization parses line-delimited SSE. Strip client content-coding
        // negotiation and explicitly request identity so the provider does not
        // return gzip/br octets that the normalizer would misread as plaintext
        // events. Residual encodings are still handled fail-safe in
        // `after_proxy` / the normalizer.
        if normalizes {
            remove_header_ci(headers, "accept-encoding");
            headers.insert("accept-encoding".to_string(), "identity".to_string());
        }

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
        // No `ai_stream_router.fallback_attempts` key: this plugin never
        // attempts a second provider, so a permanently-zero counter would only
        // advertise a capability that does not exist (issue #3328).

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
                let translated = translate_to_anthropic(&openai_body, &model).ok()?;
                ctx.metadata
                    .insert(META_REQUEST_TRANSLATED.to_string(), "true".to_string());
                if openai_body.get("tool_choice").and_then(Value::as_str) == Some("none") {
                    ctx.metadata
                        .insert(META_TOOL_CHOICE_NONE.to_string(), "true".to_string());
                } else {
                    ctx.metadata.remove(META_TOOL_CHOICE_NONE);
                }
                Some(translated)
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

    async fn on_final_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        _headers: &HashMap<String, String>,
        _body: &[u8],
    ) -> PluginResult {
        if ctx.metadata.get(META_CLAIMED).map(String::as_str) == Some("true")
            && ctx.metadata.get(META_PROVIDER_TYPE).map(String::as_str) == Some("anthropic")
            && ctx
                .metadata
                .get(META_REQUEST_TRANSLATED)
                .map(String::as_str)
                != Some("true")
        {
            return openai_error_response(
                400,
                "The Anthropic request body could not be translated safely",
                "invalid_request_error",
                Some("messages"),
                Some("invalid_messages"),
            );
        }
        PluginResult::Continue
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
        let encoding = ctx.metadata.get(META_PROVIDER_ENCODING).cloned();
        let tools_forbidden =
            ctx.metadata.get(META_TOOL_CHOICE_NONE).map(String::as_str) == Some("true");
        Some(wrap_anthropic_normalizer(
            model,
            encoding.as_deref(),
            tools_forbidden,
        ))
    }

    async fn normalize_response_body_with_context(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        body: &[u8],
        content_type: Option<&str>,
        response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        if !self.response_stream_hooks {
            return None;
        }
        if ctx.metadata.get(META_NORMALIZED).map(String::as_str) != Some("true") {
            return None;
        }
        // Match the streaming normalizer: provider error envelopes reach the
        // client untouched even when a backend labels them as event streams.
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
        let header_encoding = match content_encoding_value(response_headers) {
            Ok(encoding) => encoding,
            Err(message) => return Some(upstream_sse_error_body(&message)),
        };
        let encoding = ctx
            .metadata
            .get(META_PROVIDER_ENCODING)
            .map(String::as_str)
            .or(header_encoding);
        let plaintext = match prepare_sse_bytes_for_normalization(body, encoding) {
            Ok(bytes) => bytes,
            Err(message) => {
                return Some(upstream_sse_error_body(&message));
            }
        };
        let tools_forbidden =
            ctx.metadata.get(META_TOOL_CHOICE_NONE).map(String::as_str) == Some("true");
        normalize_anthropic_sse_buffered(model, &plaintext, tools_forbidden).await
    }

    /// Bind every field normalized Anthropic SSE invalidates.
    ///
    /// When this plugin rewrites provider SSE into OpenAI-shaped identity bytes,
    /// `repair_normalized_representation_headers` removes `content-encoding` and
    /// `content-length`, runs
    /// [`super::invalidate_content_bound_response_headers`] (validators, digests,
    /// signatures, and the open-ended `x-amz-checksum-*` / `x-checksum-*`
    /// families), and scrubs or rewrites `vary`. A trailer-only copy of any of
    /// them is invisible to the per-request mutation witness (absent → absent),
    /// so the exact names and checksum prefixes are derived from the same shared
    /// invalidation inventory. Other application trailers remain intact.
    fn response_trailer_policy(&self) -> super::ResponseTrailerPolicy<'_> {
        if self.enabled {
            super::ResponseTrailerPolicy::NamesAndPrefixes {
                names: &AI_STREAM_ROUTER_RESPONSE_POLICY_NAMES,
                prefixes: &AI_STREAM_ROUTER_RESPONSE_POLICY_PREFIXES,
            }
        } else {
            super::ResponseTrailerPolicy::None
        }
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !self.enabled || ctx.metadata.get(META_NORMALIZED).map(String::as_str) != Some("true") {
            return PluginResult::Continue;
        }
        if !(200..300).contains(&response_status) {
            return PluginResult::Continue;
        }
        let content_type = response_headers.get("content-type").map(String::as_str);
        if !content_type.is_some_and(is_event_stream_content_type) {
            return PluginResult::Continue;
        }

        match classify_provider_content_encoding(response_headers) {
            ProviderContentEncoding::Identity => {
                repair_normalized_representation_headers(response_headers);
                PluginResult::Continue
            }
            ProviderContentEncoding::Supported(coding) => {
                ctx.metadata
                    .insert(META_PROVIDER_ENCODING.to_string(), coding.to_string());
                repair_normalized_representation_headers(response_headers);
                PluginResult::Continue
            }
            ProviderContentEncoding::Unsupported(message) => openai_error_response(
                502,
                &format!("Upstream Anthropic SSE used an unsupported Content-Encoding: {message}"),
                "upstream_error",
                None,
                Some("unsupported_content_encoding"),
            ),
        }
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

fn remove_header_ci(headers: &mut HashMap<String, String>, name: &str) {
    headers.retain(|k, _| !k.eq_ignore_ascii_case(name));
}

fn content_encoding_value(headers: &HashMap<String, String>) -> Result<Option<&str>, String> {
    let mut values = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-encoding"))
        .map(|(_, value)| value.as_str());
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err("multiple case-variant Content-Encoding headers".to_string());
    }
    let value = value.trim();
    Ok((!value.is_empty()).then_some(value))
}

enum ProviderContentEncoding {
    Identity,
    Supported(&'static str),
    Unsupported(String),
}

fn classify_provider_content_encoding(
    headers: &HashMap<String, String>,
) -> ProviderContentEncoding {
    let raw = match content_encoding_value(headers) {
        Ok(Some(raw)) => raw,
        Ok(None) => return ProviderContentEncoding::Identity,
        Err(message) => return ProviderContentEncoding::Unsupported(message),
    };
    let mut codings = Vec::new();
    for part in raw.split(',') {
        let coding = part.trim();
        if coding.is_empty() {
            return ProviderContentEncoding::Unsupported(
                "content-encoding contains an empty coding".to_string(),
            );
        }
        if coding.contains(';') {
            return ProviderContentEncoding::Unsupported(format!(
                "content-encoding coding '{coding}' contains unsupported parameters"
            ));
        }
        let lower = coding.to_ascii_lowercase();
        match lower.as_str() {
            "identity" => {}
            "gzip" | "br" => codings.push(lower),
            other => {
                return ProviderContentEncoding::Unsupported(format!(
                    "unsupported content-encoding '{other}'"
                ));
            }
        }
    }
    if codings.is_empty() {
        ProviderContentEncoding::Identity
    } else if codings.len() == 1 {
        match codings[0].as_str() {
            "gzip" => ProviderContentEncoding::Supported("gzip"),
            "br" => ProviderContentEncoding::Supported("br"),
            other => ProviderContentEncoding::Unsupported(format!(
                "unsupported content-encoding '{other}'"
            )),
        }
    } else {
        // Multi-layer residual encodings are unusual for SSE and are rejected
        // rather than partially decoded into a mislabeled stream.
        ProviderContentEncoding::Unsupported(
            "multi-layer content-encoding is not supported for Anthropic SSE normalization"
                .to_string(),
        )
    }
}

/// Drop or rewrite representation metadata after Anthropic SSE is rewritten to
/// identity OpenAI-shaped bytes. The open-ended checksum-prefix families this
/// removes are declared through the exact-name-plus-prefix trailer policy,
/// derived from the shared invalidation inventory. Otherwise a trailer-only
/// copy of an invalidated field reconciles as absent→absent and lands on the
/// wire after the header phases.
fn repair_normalized_representation_headers(headers: &mut HashMap<String, String>) {
    remove_header_ci(headers, "content-encoding");
    remove_header_ci(headers, "content-length");
    super::invalidate_content_bound_response_headers(headers);
    scrub_accept_encoding_from_vary(headers);
}

fn scrub_accept_encoding_from_vary(headers: &mut HashMap<String, String>) {
    let variants: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("vary"))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    if variants.is_empty() {
        return;
    }
    for (name, _) in &variants {
        headers.remove(name);
    }
    if variants.iter().any(|(_, value)| value.trim() == "*") {
        headers.insert("vary".to_string(), "*".to_string());
        return;
    }
    let mut kept = Vec::new();
    for (_, value) in variants {
        for token in value.split(',') {
            let token = token.trim();
            if token.is_empty()
                || token.eq_ignore_ascii_case("accept-encoding")
                || kept
                    .iter()
                    .any(|kept: &String| kept.eq_ignore_ascii_case(token))
            {
                continue;
            }
            kept.push(token.to_string());
        }
    }
    if !kept.is_empty() {
        headers.insert("vary".to_string(), kept.join(", "));
    }
}

fn prepare_sse_bytes_for_normalization<'a>(
    body: &'a [u8],
    encoding: Option<&str>,
) -> Result<std::borrow::Cow<'a, [u8]>, String> {
    decode_content_encoding(encoding, body, NORMALIZE_DECODE_LIMITS)
}

fn upstream_sse_error_body(message: &str) -> Vec<u8> {
    let err = json!({
        "error": {
            "message": message,
            "type": "upstream_error",
        }
    });
    format!("data: {err}\n\ndata: [DONE]\n\n").into_bytes()
}

fn wrap_anthropic_normalizer(
    model: String,
    encoding: Option<&str>,
    tools_forbidden: bool,
) -> Box<dyn ResponseStreamInspector> {
    let inner = AnthropicSseNormalizer::new(model, tools_forbidden);
    match encoding {
        Some("gzip") => Box::new(ContentDecodingNormalizer::gzip(inner)),
        Some("br") => Box::new(ContentDecodingNormalizer::brotli(inner)),
        Some(other) => Box::new(ImmediateUpstreamErrorNormalizer::new(format!(
            "unsupported content-encoding '{other}' for Anthropic SSE normalization"
        ))),
        None => Box::new(inner),
    }
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

/// Hard per-event SSE frame limit (bytes from event start through its blank-line
/// delimiter). Checked when a boundary is discovered and before any UTF-8
/// conversion, JSON parse, or transcode — including when a complete oversized
/// event arrives in a single chunk. Also caps the unread partial event while
/// waiting for a delimiter. Public so external tests can target the exact bound
/// without inventing a parallel constant.
pub const MAX_SSE_EVENT_BYTES: usize = 1024 * 1024;

/// Cumulative Anthropic SSE plaintext bytes accepted by one normalizer
/// instance (streaming or buffered). Reuses the residual content-coding
/// plaintext ceiling so decode and normalize share one authoritative bound.
pub const MAX_SSE_NORMALIZED_BODY_BYTES: usize = NORMALIZE_DECODE_LIMITS.max_decoded_bytes;

/// Cumulative OpenAI-normalized SSE bytes a single normalizer may emit. Allows
/// modest envelope expansion above the plaintext input ceiling while still
/// failing closed; aligned with the residual-decode cumulative byte budget.
pub const MAX_SSE_NORMALIZED_OUTPUT_BYTES: usize = NORMALIZE_DECODE_LIMITS.max_cumulative_bytes;

/// Space kept below the normalized-output ceiling for one stable fail-closed
/// error frame plus the terminal `[DONE]` sentinel. All non-provider-controlled
/// bound diagnostics are materially smaller than this reserve.
const SSE_NORMALIZED_OUTPUT_TERMINAL_RESERVE_BYTES: usize = 512;

const SSE_NORMALIZED_OUTPUT_LIMIT_MESSAGE: &str =
    "upstream provider SSE stream exceeded the cumulative normalized size limit; stream terminated";

/// Fixed bytes wrapping a bound diagnostic in one terminal emission:
/// `data: {"error":{"message":"…","type":"upstream_error"}}\n\n` (56) plus the
/// `data: [DONE]\n\n` sentinel (14). Bound diagnostics are ASCII literals, so
/// JSON escaping never expands them beyond their own length.
const SSE_BOUND_DIAGNOSTIC_ENVELOPE_BYTES: usize = 70;

// The reserve is what lets a terminal frame replace an over-budget emission
// without itself crossing `MAX_SSE_NORMALIZED_OUTPUT_BYTES`. Pin that invariant
// to the longest `fail_bound` diagnostic at compile time so lengthening a
// message cannot silently break it.
const _: () = assert!(
    SSE_NORMALIZED_OUTPUT_LIMIT_MESSAGE.len() + SSE_BOUND_DIAGNOSTIC_ENVELOPE_BYTES
        <= SSE_NORMALIZED_OUTPUT_TERMINAL_RESERVE_BYTES,
    "terminal reserve must cover the normalized-output bound diagnostic frame"
);

/// Maximum complete SSE events accepted by one normalizer instance. Defends
/// against tiny-event floods that stay under the per-event and body-byte caps.
pub const MAX_SSE_EVENTS: usize = 100_000;

/// Maximum JSON nesting depth accepted in an SSE `data:` payload before
/// `serde_json` parse/transcode. Anthropic protocol frames are shallow; this
/// is well below serde_json's own recursion ceiling and fails with a stable
/// diagnostic rather than a parser-internal error.
pub const MAX_SSE_EVENT_JSON_DEPTH: usize = 32;

/// Compact when the consumed prefix reaches this many bytes (and is at least
/// half the buffer) so total copy work stays linear in input size.
const SSE_BUFFER_COMPACT_THRESHOLD: usize = 8192;

/// How a stream reached its terminal OpenAI sentinel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamTerminal {
    /// Anthropic `message_stop` — successful protocol completion.
    MessageStop,
    /// Explicit Anthropic `error` event (or resource-bound fail-safe).
    ProviderError,
    /// Clean EOF / malformed framing before a successful terminal state.
    UpstreamFailure,
}

/// Outcome of interpreting one complete SSE frame before mutation/transcode.
enum FrameOutcome {
    Ignore,
    Event(Value),
    Fail(&'static str),
}

/// Stateful, per-response inspector that transcodes Anthropic Messages API SSE
/// events into OpenAI `chat.completion.chunk` SSE. Robust to chunk splits: raw
/// bytes accumulate in a cursor-addressed buffer and only complete, in-limit
/// SSE events are transcoded.
///
/// Successful termination requires Anthropic `message_stop` (or an explicit
/// provider `error`). Clean EOF before that state, and malformed complete event
/// data that prevents protocol tracking, surface an upstream error rather than
/// synthesizing a success-only `[DONE]`.
///
/// Resource bounds (per-event bytes, cumulative plaintext, cumulative
/// normalized output, event count, JSON depth) are enforced before expensive
/// parse/transcode work and fail closed with stable diagnostics.
struct AnthropicSseNormalizer {
    /// Incoming SSE bytes. Unread range is `buf[cursor..]`.
    buf: Vec<u8>,
    /// Index of the first unread byte in `buf`.
    cursor: usize,
    /// Absolute index where the next delimiter scan may resume. When a chunk
    /// ends without a boundary this retains only the three-byte overlap needed
    /// for a split `\r\n\r\n`, so one-byte provider chunks cannot repeatedly
    /// rescan the full partial event.
    scan_cursor: usize,
    /// Total plaintext SSE bytes offered to this normalizer.
    bytes_ingested: usize,
    /// Complete SSE frames accepted (including ignored comment/control frames).
    events_seen: usize,
    /// Cumulative OpenAI SSE bytes already forwarded to the client.
    normalized_out_bytes: usize,
    model: String,
    stream_id: Option<String>,
    created: i64,
    message_started: bool,
    role_emitted: bool,
    done_emitted: bool,
    terminal: Option<StreamTerminal>,
    /// When true, any Anthropic `tool_use` fails closed instead of becoming
    /// OpenAI `tool_calls` deltas (caller constrained this generation to none).
    tools_forbidden: bool,
    /// Anthropic content-block index → OpenAI `tool_calls` index.
    tool_indices: HashMap<u64, u32>,
    next_tool_index: u32,
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
}

impl AnthropicSseNormalizer {
    fn new(model: String, tools_forbidden: bool) -> Self {
        Self {
            buf: Vec::new(),
            cursor: 0,
            scan_cursor: 0,
            bytes_ingested: 0,
            events_seen: 0,
            normalized_out_bytes: 0,
            model,
            stream_id: None,
            created: Utc::now().timestamp(),
            message_started: false,
            role_emitted: false,
            done_emitted: false,
            terminal: None,
            tools_forbidden,
            tool_indices: HashMap::new(),
            next_tool_index: 0,
            prompt_tokens: None,
            completion_tokens: None,
        }
    }

    fn unread_len(&self) -> usize {
        self.buf.len().saturating_sub(self.cursor)
    }

    fn clear_buffer(&mut self) {
        self.buf.clear();
        self.cursor = 0;
        self.scan_cursor = 0;
        if self.buf.capacity() > 64 * 1024 {
            self.buf.shrink_to(4096);
        }
    }

    /// Reclaim consumed prefix so total shift work stays linear in input size.
    fn maybe_compact(&mut self) {
        if self.cursor == 0 {
            return;
        }
        if self.cursor >= self.buf.len() {
            self.clear_buffer();
            return;
        }
        if self.cursor >= SSE_BUFFER_COMPACT_THRESHOLD && self.cursor * 2 >= self.buf.len() {
            let consumed = self.cursor;
            self.buf.drain(..consumed);
            self.scan_cursor = self.scan_cursor.saturating_sub(consumed);
            self.cursor = 0;
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

    fn emit_upstream_error(&mut self, message: &str, out: &mut String) {
        let err = json!({
            "error": {
                "message": message,
                "type": "upstream_error",
            }
        });
        out.push_str(&format!("data: {err}\n\n"));
    }

    fn fail_bound(&mut self, message: &'static str, out: &mut String) {
        self.clear_buffer();
        self.emit_upstream_error(message, out);
        self.finish(StreamTerminal::ProviderError, out);
    }

    /// Transcode one Anthropic event JSON into zero or more OpenAI SSE lines.
    /// Returns whether the upstream inspector driver should terminate now.
    fn transcode_event(&mut self, event: &Value, out: &mut String) -> bool {
        match event.get("type").and_then(Value::as_str) {
            Some("message_start") => {
                if self.message_started {
                    self.emit_upstream_error(
                        "upstream provider repeated Anthropic message_start",
                        out,
                    );
                    self.finish(StreamTerminal::UpstreamFailure, out);
                    return true;
                }
                self.message_started = true;
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
                false
            }
            Some("content_block_start") => {
                if !self.require_message_start("content_block_start", out) {
                    return true;
                }
                let index = event["index"].as_u64().unwrap_or(0);
                let block = &event["content_block"];
                if block.get("type").and_then(Value::as_str) == Some("tool_use") {
                    if self.tools_forbidden {
                        self.emit_upstream_error(
                            "upstream provider emitted tool use despite tool_choice none",
                            out,
                        );
                        self.finish(StreamTerminal::UpstreamFailure, out);
                        return true;
                    }
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
                false
            }
            Some("content_block_delta") => {
                if !self.require_message_start("content_block_delta", out) {
                    return true;
                }
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
                        if self.tools_forbidden {
                            self.emit_upstream_error(
                                "upstream provider emitted tool use despite tool_choice none",
                                out,
                            );
                            self.finish(StreamTerminal::UpstreamFailure, out);
                            return true;
                        }
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
                false
            }
            Some("message_delta") => {
                if !self.require_message_start("message_delta", out) {
                    return true;
                }
                if let Some(tokens) = event["usage"]["output_tokens"].as_u64() {
                    self.completion_tokens = Some(tokens);
                }
                let stop_reason = event["delta"]["stop_reason"].as_str();
                if self.tools_forbidden && stop_reason == Some("tool_use") {
                    self.emit_upstream_error(
                        "upstream provider emitted tool use despite tool_choice none",
                        out,
                    );
                    self.finish(StreamTerminal::UpstreamFailure, out);
                    return true;
                }
                let finish = map_stop_reason(stop_reason);
                out.push_str(&self.chunk_line(json!({}), Some(finish)));
                false
            }
            Some("message_stop") => {
                if !self.require_message_start("message_stop", out) {
                    return true;
                }
                self.finish(StreamTerminal::MessageStop, out);
                true
            }
            Some("error") => {
                let message = event["error"]["message"]
                    .as_str()
                    .unwrap_or("upstream provider stream error");
                self.emit_upstream_error(message, out);
                self.finish(StreamTerminal::ProviderError, out);
                true
            }
            // ping, content_block_stop, and unknown events produce no output
            // (forward-compatible). Events with a present `type` that is not a
            // known Anthropic frame are ignored; malformed JSON is handled by
            // the caller as an upstream failure.
            _ => false,
        }
    }

    fn ensure_role(&mut self, out: &mut String) {
        if !self.role_emitted {
            self.role_emitted = true;
            out.push_str(&self.chunk_line(json!({ "role": "assistant" }), None));
        }
    }

    fn require_message_start(&mut self, event_type: &str, out: &mut String) -> bool {
        if self.message_started {
            return true;
        }
        self.emit_upstream_error(
            &format!("upstream provider sent Anthropic {event_type} before message_start"),
            out,
        );
        self.finish(StreamTerminal::UpstreamFailure, out);
        false
    }

    /// Emit the final usage chunk (when successful) and the OpenAI `[DONE]`
    /// sentinel exactly once.
    fn finish(&mut self, terminal: StreamTerminal, out: &mut String) {
        if self.done_emitted {
            return;
        }
        self.done_emitted = true;
        self.terminal = Some(terminal);
        if terminal == StreamTerminal::MessageStop
            && let Some(usage) = self.usage_line()
        {
            out.push_str(&usage);
        }
        out.push_str("data: [DONE]\n\n");
    }

    /// Interpret one complete SSE frame without mutating normalizer state.
    /// Performs UTF-8 / framing / JSON-depth checks and JSON parse; does not
    /// transcode. Caller must enforce the per-event byte cap before invoking.
    fn interpret_sse_frame(raw: &[u8]) -> FrameOutcome {
        match extract_sse_event_result(raw) {
            Ok((event_name, None)) => {
                if event_name.is_some_and(is_known_anthropic_event) {
                    FrameOutcome::Fail(
                        "upstream provider sent a known Anthropic SSE event without valid data framing; stream terminated",
                    )
                } else {
                    FrameOutcome::Ignore
                }
            }
            Ok((event_name, Some(data))) => {
                if json_nesting_depth(&data) > MAX_SSE_EVENT_JSON_DEPTH {
                    return FrameOutcome::Fail(
                        "upstream provider sent an SSE event with excessive JSON nesting; stream terminated",
                    );
                }
                match serde_json::from_str::<Value>(&data) {
                    Ok(event) => {
                        let Some(payload_type) = event.get("type").and_then(Value::as_str) else {
                            return FrameOutcome::Fail(
                                "upstream provider sent an Anthropic SSE JSON event without a string type; stream terminated",
                            );
                        };
                        if let Some(event_name) = event_name
                            && is_known_anthropic_event(event_name)
                            && event_name != payload_type
                        {
                            return FrameOutcome::Fail(
                                "upstream provider sent mismatched Anthropic SSE event and payload types; stream terminated",
                            );
                        }
                        FrameOutcome::Event(event)
                    }
                    Err(_) => FrameOutcome::Fail(
                        "upstream provider sent a malformed SSE JSON event; stream terminated",
                    ),
                }
            }
            Err(_) => FrameOutcome::Fail(
                "upstream provider sent a malformed SSE event; stream terminated",
            ),
        }
    }

    fn apply_frame_outcome(&mut self, outcome: FrameOutcome, out: &mut String) -> bool {
        match outcome {
            FrameOutcome::Ignore => false,
            FrameOutcome::Event(event) => self.transcode_event(&event, out),
            FrameOutcome::Fail(message) => {
                self.emit_upstream_error(message, out);
                self.finish(StreamTerminal::UpstreamFailure, out);
                true
            }
        }
    }

    /// Drain every complete in-limit SSE event currently buffered, transcoding
    /// each from a cursor slice (no front-`drain(..).collect()`). Returns
    /// whether the stream should terminate immediately.
    fn drain_complete(&mut self, out: &mut String) -> bool {
        loop {
            let end = {
                let scan_start = self.scan_cursor.max(self.cursor).min(self.buf.len());
                match next_event_boundary(&self.buf[scan_start..]) {
                    Some(end_rel) => scan_start + end_rel,
                    None => {
                        // `\r\n\r\n` is the longest delimiter. Retain its
                        // three-byte prefix so a boundary split across the next
                        // chunk is still found without rescanning older bytes.
                        self.scan_cursor = self.buf.len().saturating_sub(3).max(self.cursor);
                        break;
                    }
                }
            };
            let end_rel = end.saturating_sub(self.cursor);
            // Enforce the advertised per-event hard limit before any copy,
            // UTF-8 conversion, JSON parse, or transcode of this frame.
            if end_rel > MAX_SSE_EVENT_BYTES {
                self.fail_bound(
                    "upstream provider sent an oversized SSE event; stream terminated",
                    out,
                );
                return true;
            }
            if self.events_seen >= MAX_SSE_EVENTS {
                self.fail_bound(
                    "upstream provider SSE stream exceeded the event count limit; stream terminated",
                    out,
                );
                return true;
            }

            let start = self.cursor;
            let outcome = Self::interpret_sse_frame(&self.buf[start..end]);
            self.cursor = end;
            self.scan_cursor = end;
            self.events_seen = self.events_seen.saturating_add(1);

            let terminate = self.apply_frame_outcome(outcome, out);
            self.maybe_compact();
            if self.normalized_output_exceeded(out, terminate) {
                return true;
            }
            if terminate {
                self.clear_buffer();
                return true;
            }
        }
        false
    }

    fn normalized_output_exceeded(&mut self, out: &mut String, terminal: bool) -> bool {
        let total = self.normalized_out_bytes.saturating_add(out.len());
        let allowed = if terminal {
            MAX_SSE_NORMALIZED_OUTPUT_BYTES
        } else {
            MAX_SSE_NORMALIZED_OUTPUT_BYTES
                .saturating_sub(SSE_NORMALIZED_OUTPUT_TERMINAL_RESERVE_BYTES)
        };
        if total <= allowed {
            return false;
        }

        // A terminal provider event may itself be the bytes that cross the
        // ceiling. Replace the complete current inspector emission, including
        // any provider-controlled error message and an already-appended
        // sentinel, with the fixed bound diagnostic. Prior non-terminal calls
        // always retained enough room for this payload.
        out.clear();
        self.done_emitted = false;
        self.terminal = None;
        self.fail_bound(SSE_NORMALIZED_OUTPUT_LIMIT_MESSAGE, out);
        true
    }

    fn account_ingested(&mut self, chunk_len: usize) -> Result<(), &'static str> {
        let Some(next) = self.bytes_ingested.checked_add(chunk_len) else {
            return Err(
                "upstream provider SSE stream exceeded the cumulative size limit; stream terminated",
            );
        };
        if next > MAX_SSE_NORMALIZED_BODY_BYTES {
            return Err(
                "upstream provider SSE stream exceeded the cumulative size limit; stream terminated",
            );
        }
        self.bytes_ingested = next;
        Ok(())
    }

    /// Ingest `chunk`, enforcing all resource bounds before expensive work.
    /// Returns whether the stream should terminate.
    fn push_chunk(&mut self, mut chunk: &[u8], out: &mut String) -> bool {
        if let Err(message) = self.account_ingested(chunk.len()) {
            self.fail_bound(message, out);
            return true;
        }

        while !chunk.is_empty() {
            let unread = self.unread_len();
            // Grow the current partial event by at most one byte past the
            // hard cap so an oversized complete or never-terminated frame is
            // detected without buffering an unbounded provider chunk.
            // `unread` is always <= `MAX_SSE_EVENT_BYTES` here: each prior
            // iteration either stayed within the cap or failed closed.
            let room = (MAX_SSE_EVENT_BYTES.saturating_add(1)).saturating_sub(unread);
            let take = room.min(chunk.len());
            self.buf.extend_from_slice(&chunk[..take]);
            chunk = &chunk[take..];

            if self.drain_complete(out) {
                return true;
            }
            if self.unread_len() > MAX_SSE_EVENT_BYTES {
                self.fail_bound(
                    "upstream provider sent an oversized SSE event; stream terminated",
                    out,
                );
                return true;
            }
        }
        false
    }

    /// Terminal EOF handling. Always ends the OpenAI stream: every path emits a
    /// terminal frame (or reuses one already emitted), so there is no
    /// "continue reading" outcome to report back.
    fn finish_stream(&mut self, out: &mut String) {
        if self.drain_complete(out) {
            return;
        }
        // Transcode any trailing event that lacked a final blank-line boundary.
        if self.unread_len() > 0 {
            if self.unread_len() > MAX_SSE_EVENT_BYTES {
                self.fail_bound(
                    "upstream provider sent an oversized SSE event; stream terminated",
                    out,
                );
                return;
            }
            if self.events_seen >= MAX_SSE_EVENTS {
                self.fail_bound(
                    "upstream provider SSE stream exceeded the event count limit; stream terminated",
                    out,
                );
                return;
            }
            let start = self.cursor;
            let end = self.buf.len();
            let raw_is_ws = self.buf[start..end].iter().all(u8::is_ascii_whitespace);
            let outcome = Self::interpret_sse_frame(&self.buf[start..end]);
            self.cursor = end;
            self.events_seen = self.events_seen.saturating_add(1);
            self.clear_buffer();

            // Delimiter-less EOF remainder is trailing framing, not a complete
            // event. Interpret Fail outcomes (incomplete JSON, bad UTF-8, etc.)
            // with the stable trailing diagnostic rather than the complete-event
            // malformed-JSON / malformed-SSE labels used by `drain_complete`.
            match outcome {
                FrameOutcome::Fail(_) => {
                    self.emit_upstream_error(
                        "upstream provider ended the Anthropic SSE stream with malformed trailing data",
                        out,
                    );
                    self.finish(StreamTerminal::UpstreamFailure, out);
                    let _ = self.normalized_output_exceeded(out, true);
                    return;
                }
                outcome => {
                    let terminate = self.apply_frame_outcome(outcome, out);
                    if self.normalized_output_exceeded(out, terminate) {
                        return;
                    }
                    if terminate {
                        return;
                    }
                    // Preserve prior EOF framing: a non-terminating trailing frame
                    // that is not pure whitespace is treated as malformed trailing
                    // data.
                    if !raw_is_ws {
                        self.emit_upstream_error(
                            "upstream provider ended the Anthropic SSE stream with malformed trailing data",
                            out,
                        );
                        self.finish(StreamTerminal::UpstreamFailure, out);
                        let _ = self.normalized_output_exceeded(out, true);
                        return;
                    }
                }
            }
        }
        // Clean EOF without `message_stop` is premature truncation — never
        // synthesize a success-only `[DONE]`.
        self.emit_upstream_error(
            "upstream provider closed the Anthropic SSE stream before message_stop",
            out,
        );
        self.finish(StreamTerminal::UpstreamFailure, out);
        let _ = self.normalized_output_exceeded(out, true);
    }

    fn commit_forwarded(&mut self, out: &str) {
        self.normalized_out_bytes = self.normalized_out_bytes.saturating_add(out.len());
    }
}

#[async_trait]
impl ResponseStreamInspector for AnthropicSseNormalizer {
    fn stage(&self) -> ResponseStreamInspectorStage {
        ResponseStreamInspectorStage::Normalize
    }

    async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction {
        if self.done_emitted {
            return ResponseStreamAction::Terminate(None);
        }
        let mut out = String::new();
        if self.push_chunk(chunk, &mut out) {
            return ResponseStreamAction::Terminate(Some(Bytes::from(out.into_bytes())));
        }
        self.commit_forwarded(&out);
        ResponseStreamAction::Forward(Bytes::from(out.into_bytes()))
    }

    async fn on_end(&mut self) -> ResponseStreamAction {
        if self.done_emitted {
            return ResponseStreamAction::Terminate(None);
        }
        let mut out = String::new();
        self.finish_stream(&mut out);
        ResponseStreamAction::Terminate(Some(Bytes::from(out.into_bytes())))
    }
}

/// Decode residual provider content coding, then feed plaintext SSE into the
/// Anthropic→OpenAI normalizer. Because a compressed stream's checksum/trailer
/// is not trustworthy until EOF, this rare fallback buffers the encoded body
/// within a strict cap before decoding. Normal requests strip Accept-Encoding
/// and retain fully progressive identity SSE normalization.
struct ContentDecodingNormalizer {
    encoding: &'static str,
    encoded: Vec<u8>,
    inner: AnthropicSseNormalizer,
}

impl ContentDecodingNormalizer {
    fn gzip(inner: AnthropicSseNormalizer) -> Self {
        Self {
            encoding: "gzip",
            encoded: Vec::new(),
            inner,
        }
    }

    fn brotli(inner: AnthropicSseNormalizer) -> Self {
        Self {
            encoding: "br",
            encoded: Vec::new(),
            inner,
        }
    }

    async fn fail_decode(&mut self, message: String) -> ResponseStreamAction {
        let mut out = String::new();
        self.inner.emit_upstream_error(&message, &mut out);
        self.inner.finish(StreamTerminal::UpstreamFailure, &mut out);
        ResponseStreamAction::Terminate(Some(Bytes::from(out.into_bytes())))
    }
}

#[async_trait]
impl ResponseStreamInspector for ContentDecodingNormalizer {
    fn stage(&self) -> ResponseStreamInspectorStage {
        ResponseStreamInspectorStage::Normalize
    }

    async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction {
        if self.inner.done_emitted {
            return ResponseStreamAction::Terminate(None);
        }
        let Some(next_len) = self.encoded.len().checked_add(chunk.len()) else {
            return self
                .fail_decode("encoded Anthropic SSE size overflowed".to_string())
                .await;
        };
        if next_len > NORMALIZE_DECODE_LIMITS.max_cumulative_bytes {
            return self
                .fail_decode("encoded Anthropic SSE exceeds the streaming size limit".to_string())
                .await;
        }
        self.encoded.extend_from_slice(chunk);
        ResponseStreamAction::Forward(Bytes::new())
    }

    async fn on_end(&mut self) -> ResponseStreamAction {
        if self.inner.done_emitted {
            return ResponseStreamAction::Terminate(None);
        }
        let decoded = match prepare_sse_bytes_for_normalization(&self.encoded, Some(self.encoding))
        {
            Ok(bytes) => bytes.into_owned(),
            Err(message) => return self.fail_decode(message).await,
        };
        let mut out = Vec::new();
        if !decoded.is_empty() {
            match self.inner.on_chunk(&decoded).await {
                ResponseStreamAction::Forward(bytes) => out.extend_from_slice(&bytes),
                ResponseStreamAction::Terminate(bytes) => {
                    if let Some(bytes) = bytes {
                        out.extend_from_slice(&bytes);
                    }
                    return ResponseStreamAction::Terminate(Some(Bytes::from(out)));
                }
            }
        }
        match self.inner.on_end().await {
            ResponseStreamAction::Forward(bytes) => {
                out.extend_from_slice(&bytes);
                ResponseStreamAction::Terminate(Some(Bytes::from(out)))
            }
            ResponseStreamAction::Terminate(Some(bytes)) => {
                out.extend_from_slice(&bytes);
                ResponseStreamAction::Terminate(Some(Bytes::from(out)))
            }
            ResponseStreamAction::Terminate(None) => {
                if out.is_empty() {
                    ResponseStreamAction::Terminate(None)
                } else {
                    ResponseStreamAction::Terminate(Some(Bytes::from(out)))
                }
            }
        }
    }
}

/// Fail closed immediately when residual encoding cannot be decoded.
struct ImmediateUpstreamErrorNormalizer {
    message: String,
    emitted: bool,
}

impl ImmediateUpstreamErrorNormalizer {
    fn new(message: String) -> Self {
        Self {
            message,
            emitted: false,
        }
    }
}

#[async_trait]
impl ResponseStreamInspector for ImmediateUpstreamErrorNormalizer {
    fn stage(&self) -> ResponseStreamInspectorStage {
        ResponseStreamInspectorStage::Normalize
    }

    async fn on_chunk(&mut self, _chunk: &[u8]) -> ResponseStreamAction {
        if self.emitted {
            return ResponseStreamAction::Terminate(None);
        }
        self.emitted = true;
        ResponseStreamAction::Terminate(Some(Bytes::from(upstream_sse_error_body(&self.message))))
    }

    async fn on_end(&mut self) -> ResponseStreamAction {
        if self.emitted {
            return ResponseStreamAction::Terminate(None);
        }
        self.emitted = true;
        ResponseStreamAction::Terminate(Some(Bytes::from(upstream_sse_error_body(&self.message))))
    }
}

async fn normalize_anthropic_sse_buffered(
    model: String,
    body: &[u8],
    tools_forbidden: bool,
) -> Option<Vec<u8>> {
    let mut normalizer = AnthropicSseNormalizer::new(model, tools_forbidden);
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

fn is_known_anthropic_event(event_type: &str) -> bool {
    matches!(
        event_type,
        "message_start"
            | "content_block_start"
            | "content_block_delta"
            | "content_block_stop"
            | "message_delta"
            | "message_stop"
            | "error"
            | "ping"
    )
}

/// Extract and concatenate the `data:` payload lines of one raw SSE event.
///
/// The optional SSE `event:` name is retained so known Anthropic protocol
/// events cannot disguise malformed/missing `data:` framing as a harmless
/// comment or forward-compatible unknown event. Returns `Err` for invalid
/// UTF-8 framing.
fn extract_sse_event_result(raw: &[u8]) -> Result<(Option<&str>, Option<String>), ()> {
    let text = std::str::from_utf8(raw).map_err(|_| ())?;
    let mut data = String::new();
    let mut found = false;
    let mut event_name = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("data:") {
            found = true;
            let rest = rest.strip_prefix(' ').unwrap_or(rest);
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(rest);
        } else if let Some(rest) = line.strip_prefix("event:") {
            let rest = rest.strip_prefix(' ').unwrap_or(rest);
            event_name = (!rest.is_empty()).then_some(rest);
        }
    }
    Ok((event_name, found.then_some(data)))
}

/// Maximum nesting depth of `{` / `[` outside JSON strings. Used as a cheap
/// pre-parse gate so hostile deep payloads fail closed before `serde_json`.
fn json_nesting_depth(s: &str) -> usize {
    let mut depth = 0usize;
    let mut max = 0usize;
    let mut in_string = false;
    let mut escape = false;
    for b in s.bytes() {
        if in_string {
            if escape {
                escape = false;
                continue;
            }
            match b {
                b'\\' => escape = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth = depth.saturating_add(1);
                if depth > max {
                    max = depth;
                }
                if max > MAX_SSE_EVENT_JSON_DEPTH {
                    return max;
                }
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    max
}

#[cfg(test)]
mod sse_buffer_tests {
    use super::*;

    /// Structural proof that the cursor/compaction path does not repeatedly
    /// shift the unread remainder on every event: after many small complete
    /// frames the unread window stays tiny and capacity stays O(partial), not
    /// O(total_input).
    #[test]
    fn cursor_compaction_stays_linear_for_many_small_events() {
        let mut normalizer = AnthropicSseNormalizer::new("claude-test".to_string(), false);
        let event = b"data: {\"type\":\"ping\"}\n\n";
        let mut out = String::new();
        let iterations = 4_096usize;
        for _ in 0..iterations {
            assert!(
                !normalizer.push_chunk(event, &mut out),
                "ping flood under event-count cap must not terminate"
            );
            out.clear();
        }
        assert_eq!(normalizer.events_seen, iterations);
        assert_eq!(normalizer.unread_len(), 0);
        assert_eq!(normalizer.cursor, 0);
        assert_eq!(normalizer.scan_cursor, 0);
        // Compaction reclaims the consumed prefix; capacity must stay far below
        // the quadratic alternative of retaining every prior event.
        let capacity = normalizer.buf.capacity();
        let total_input = iterations * event.len();
        assert!(
            capacity < total_input / 2,
            "capacity {capacity} should stay well below total input {total_input}"
        );
        assert_eq!(normalizer.bytes_ingested, iterations * event.len());
    }
}

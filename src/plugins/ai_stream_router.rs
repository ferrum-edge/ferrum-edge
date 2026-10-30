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
//! ## Coordination with other built-ins
//!
//! `ai_stream_router` runs first and, when it claims a streaming request,
//! records the private typed [`AiStreamRouterClaim`] on the request context and
//! also publishes `ctx.metadata["ai_stream_router_claimed"] = "true"` for
//! observability and third-party/custom-plugin coordination. Every BUILT-IN
//! that must stand down on a claimed provider request — `ai_federation`,
//! `request_mirror`, `serverless_function`, `mcp_gateway`, and
//! `mesh_route_dispatch` — decides from
//! [`RequestContext::has_ai_stream_router_claim`], never from that metadata key
//! (`GHSA-xhp5-hqj8-3mwg`): metadata is a mutable string map, so deleting or
//! rewriting the marker after a real claim would otherwise let those plugins
//! re-route, mirror, federate, or invoke a function over a request whose
//! third-party provider credential, model, destination, and query are already
//! committed. The two plugin families still compose the same way: `stream: true`
//! is handled here, `stream: false` falls through to `ai_federation`.
//!
//! Intentional PASS-THROUGH is a different state — the request is genuinely
//! unclaimed because the operator disabled fail-closed missing/unmatched-model
//! behavior — and still coordinates through
//! `ctx.metadata["ai_stream_router_pass_through"]`.
//!
//! ## MVP scope
//!
//! - `openai` / `openai_compatible` / `azure_openai`: route + header rewrite;
//!   body is passed through untranslated except optional
//!   `stream_options.include_usage` injection. Provider SSE is already
//!   OpenAI-shaped, so it streams through unchanged (zero-overhead — no
//!   inspector). `azure_openai` authenticates with the `api-key` header.
//! - For both translated providers, OpenAI request parameters are mapped
//!   exactly (`response_format` / `n` / penalties / `seed` for Gemini,
//!   `parallel_tool_calls` for Anthropic) or refused with an OpenAI-shaped
//!   `400`, never silently dropped; user-message base64 data-URL images become
//!   native image parts; and a 2xx response whose media type is not a
//!   supported stream framing fails closed.
//! - `anthropic`: OpenAI Chat Completions request is translated to the Anthropic
//!   Messages API streaming request (including assistant `tool_calls` /
//!   matching `role: "tool"` results and legacy assistant `function_call` /
//!   matching `role: "function"` results); Anthropic SSE events are normalized
//!   back to OpenAI `chat.completion.chunk` SSE. OpenAI `tool_choice: "none"`
//!   becomes Anthropic `{"type":"none"}` with the tools list retained;
//!   unsupported tool_choice values, and extended thinking (manual or
//!   adaptive) combined with callable tools or a tool-result continuation, are
//!   rejected at admission: signed thinking blocks cannot round-trip through
//!   the OpenAI representation. Provider
//!   `tool_use` under a none constraint fails closed instead of becoming OpenAI
//!   `tool_calls`. Normalization requires Anthropic `message_stop` (or an
//!   explicit provider `error`) before emitting a success-shaped terminal
//!   sequence; premature EOF / malformed events fail closed with an
//!   upstream-error SSE frame. Requests that will be normalized strip
//!   `Accept-Encoding`, and residual `Content-Encoding` chains are decoded
//!   (`gzip` / `x-gzip` / `br`, including stacked lists) in reverse application
//!   order under shared bounded limits, or rejected fail-closed before SSE
//!   parsing so response headers describe identity bytes.
//! - `google_gemini`: OpenAI Chat Completions request is translated to the
//!   Gemini/`streamGenerateContent` (Vertex-compatible) request body; native
//!   Gemini SSE (`alt=sse`) and Vertex-compatible JSON array / object streams
//!   are normalized to OpenAI `chat.completion.chunk` SSE. Gemini thought
//!   signatures round-trip through the OpenAI tool call's
//!   `extra_content.google.thought_signature`. Message content is
//!   closed-shape at claim (string or array of text-part objects with exactly
//!   `type` and `text`; mixed/extra/unknown fields, non-object members,
//!   non-text/malformed parts, and null system/developer/user content reject
//!   with OpenAI-shaped `400`). Assistant null/empty content is preserved only
//!   with a valid `tool_calls` or legacy `function_call`. Content/role deltas,
//!   multi-candidate indexes, finish/terminal state, usage metadata, safety /
//!   prompt blocks, function calls + args, and provider error envelopes are
//!   mapped under the same bounded fail-closed policy as Anthropic. Every
//!   candidate that emitted client-visible output must reach a terminal
//!   `finishReason` before clean EOF; post-finish candidate data and
//!   unrepresentable content parts fail closed. A claimed normalizing 2xx
//!   response with a missing or unexpected `Content-Type` fails closed rather
//!   than streaming raw provider bytes. The model is URL-scoped via an
//!   optional `{model}` endpoint placeholder.
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
//! ## Final provider boundary (`GHSA-xhp5-hqj8-3mwg`)
//!
//! Claiming in `before_proxy` at 2984 only orders this plugin ahead of the
//! plugins that run before it. The generic `request_transformer` runs at 3000,
//! a `serverless_function` `pre_proxy` backend overlay is merged later still,
//! and both can add, overwrite, or rename any header — including the credential
//! this plugin just installed — or rewrite the already-translated provider body.
//! Two shared lifecycle boundaries close that window, and neither depends on
//! relative priority:
//!
//! - `enforce_final_backend_header_policy` re-strips client/backend credential
//!   and gateway-identity headers and re-installs ONLY the selected provider's
//!   credential over the finalized backend-visible header map. The gateway runs
//!   it after every `before_proxy` pass (including the deferred routing/remaining
//!   passes) and after an egress header overlay, on H1/H2 and H3 alike.
//! - `on_final_request_body_with_context` re-parses the backend-visible body
//!   after every `transform_request_body` hook and fails closed unless the
//!   provider-visible `model` is still exactly the model recorded in the
//!   PRIVATE claim — the value that actually selected this provider — and still
//!   matches that provider's `model_patterns`. The public
//!   `ai_stream_router.model` metadata key is never consulted: a later plugin
//!   that rewrites both the final body's model and that key to the same value
//!   would otherwise satisfy an equality check while bypassing selection. It
//!   also re-checks the committed destination witness, so the credential and the
//!   destination cannot drift apart.
//!
//! Both fail closed. Neither logs header values, credentials, or body bytes,
//! and neither echoes the offending value into the client error envelope.
//!
//! ### What the claim actually commits
//!
//! The credential boundary is not just a header set. A claim commits, and the
//! final boundary re-asserts or re-checks, ALL of:
//!
//! - **Headers** — the owned credential / gateway-identity / provider-protocol
//!   set listed on [`apply_provider_boundary_headers`]: every canonical
//!   credential header name (shared with replay partitioning), the route's own
//!   configured authentication header locations, and provider-protocol
//!   headers. Headers OUTSIDE that set are deliberately untouched, so intended
//!   operator transforms still reach the provider. Ferrum does not attempt to
//!   classify an arbitrary unknown custom header as a credential; an operator
//!   who routes a bespoke secret header to a normal backend must not also
//!   configure that rule on a proxy that routes to a third-party provider.
//! - **Model** — the exact model string that matched `model_patterns` and chose
//!   this provider, this price, and (for `{model}` endpoints) this backend URL.
//!   Final body enforcement compares against THIS copy, and the claim-owned
//!   response normalizers stamp the client-visible generation identity from it.
//!   The `ai_stream_router.model` metadata key is observability only.
//! - **Query** — the exact backend-visible query, frozen at claim time and
//!   replayed from private request state at
//!   `crate::proxy::effective_backend_query_string*`, the single funnel every
//!   dispatcher and retry attempt reads. `request_transformer` query rules run
//!   later (3000) and could otherwise append a normal-backend static secret to
//!   the provider URL.
//! - **Destination** — scheme, host, port, authority, absolute path, AND the
//!   routing identity: `route_override_upstream_id` is cleared at claim time and
//!   must still be clear, so no load balancer can pick the dial target.
//! - **Transport security** — the exact `route_override_resolved_tls` committed
//!   at claim time, compared for equality (verification flag, SNI, CA, mTLS
//!   client materials, and the provider-isolation marker). Without
//!   `inherit_backend_tls` this is [`BackendTlsConfig::isolated_public_verify`]:
//!   public roots only, no gateway-global CA / no-verify / client identity.
//!   `None` means plaintext HTTP and is a distinct committed state.
//! - **DNS** — the claim revokes any inherited `Proxy.dns_override` through the
//!   typed `RouteOverrideDnsPolicy::ClearInherited` route override, because a
//!   same-host pin would otherwise send the provider credential to an operator
//!   address instead of provider DNS.
//! - **Instance ownership** — an opaque per-instance identity recorded in
//!   private request state. Multiple `ai_stream_router` instances are allowed and
//!   two of them may share a provider NAME while differing in endpoint, key,
//!   provider type, patterns, and normalization. Exactly one instance claims;
//!   every claim-dependent request and response hook (request transform, final
//!   header policy, final body revalidation, response header handling, and
//!   response stream inspector / normalizer selection) verifies ownership before
//!   acting. Fail-on-missing-model / fail-on-no-matching-provider still decide an
//!   UNCLAIMED request in normal plugin order; ownership begins only on a
//!   successful claim.
//! - **Request-shape witnesses** — whether this instance's own transform
//!   actually produced the Anthropic representation, and whether the claimed
//!   request forbids tool use for this generation. Both gate fail-closed
//!   decisions, so both are claim state rather than the mirrored
//!   `ai_stream_router.request_translated` / `ai_stream_router.tool_choice_none`
//!   observability keys.
//!
//! None of the claim state is metadata, and none of it is logged, serialized, or
//! exported: it holds a query string, the committed model, and an ownership
//! token. The `ai_stream_router.*` metadata keys remain published for logs and
//! cross-plugin coordination, and a later plugin may write any of them — no
//! enforcement point reads them back. The one metadata value a claim-owned hook
//! still consults is `ai_stream_router.provider_content_encoding`, which is
//! derived from the PROVIDER's own response headers, decides only how this
//! instance decodes its own upstream bytes, and is bounded by that decoder's
//! `NORMALIZE_DECODE_LIMITS`; forging it can fail this instance's
//! normalization but cannot move a credential, a destination, or a generation.
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
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::debug;
use url::{Host, Url};

use super::utils::ai_model_glob::{
    MAX_MODEL_PATTERNS_PER_PROVIDER, is_valid_model_pattern, matches_model_glob,
};
use super::utils::body_transform::{is_event_stream_content_type, is_json_content_type};
use super::utils::content_encoding::{
    DecodeLimits, decode_content_encoding, parse_content_codings,
};
use super::utils::openai_error::openai_error_body;
use super::utils::plugin_secret_env::resolve_plugin_secret_env;
use super::utils::replay_partition::CREDENTIAL_CONTEXT_HEADERS;
use super::utils::sse::{sse_event_end, sse_lines};
use super::{
    Plugin, PluginHttpClient, PluginResult, RequestContext, ResponseStreamAction,
    ResponseStreamInspector, ResponseStreamInspectorStage,
};
use crate::config::types::{BackendScheme, BackendTlsConfig};
use crate::util::unknown_keys::reject_unknown_keys;

/// Exact response fields invalidated when provider SSE is normalized.
///
/// Derived from the shared representation-invalidation inventory so trailer
/// policy cannot drift from the header rewrite. The four extra fields are owned
/// directly by [`repair_normalized_representation_headers`] and
/// [`stamp_normalized_sse_content_type`].
static AI_STREAM_ROUTER_RESPONSE_POLICY_NAMES: std::sync::LazyLock<Vec<String>> =
    std::sync::LazyLock::new(|| {
        let mut names = Vec::with_capacity(super::TRANSFORM_INVALIDATED_RESPONSE_HEADERS.len() + 4);
        names.extend(
            super::TRANSFORM_INVALIDATED_RESPONSE_HEADERS
                .iter()
                .map(|name| (*name).to_string()),
        );
        names.extend(
            ["content-encoding", "content-length", "content-type", "vary"]
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
    "max_normalized_stream_bytes",
    "max_stream_bytes",
    "max_stream_events",
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
    "default_max_tokens",
    "inherit_backend_tls",
];

/// `anthropic-version` header value used when a provider omits the field.
const DEFAULT_ANTHROPIC_VERSION: &str = "2023-06-01";

/// Anthropic `max_tokens` forwarded when the OpenAI request sets neither
/// `max_tokens` nor `max_completion_tokens` and the provider configures no
/// `default_max_tokens`. Anthropic requires the field; OpenAI does not.
const DEFAULT_ANTHROPIC_MAX_TOKENS: u64 = 4096;

/// Upper bound on a configured provider `default_max_tokens`.
const MAX_CONFIGURED_DEFAULT_MAX_TOKENS: u64 = u32::MAX as u64;

/// Admitted range for the `max_stream_bytes` override (cumulative provider
/// plaintext one normalizer accepts).
const MIN_CONFIGURED_STREAM_BYTES: u64 = MAX_SSE_EVENT_BYTES as u64;
const MAX_CONFIGURED_STREAM_BYTES: u64 = 256 * 1024 * 1024;
/// Admitted range for the `max_normalized_stream_bytes` override (cumulative
/// OpenAI-shaped output one normalizer may emit).
const MIN_CONFIGURED_NORMALIZED_STREAM_BYTES: u64 = 1024 * 1024;
const MAX_CONFIGURED_NORMALIZED_STREAM_BYTES: u64 = 512 * 1024 * 1024;
/// Admitted range for the `max_stream_events` override.
const MIN_CONFIGURED_STREAM_EVENTS: u64 = 1_000;
const MAX_CONFIGURED_STREAM_EVENTS: u64 = 10_000_000;

/// UTF-8 byte-order mark. Legal as the very first bytes of an event stream, and
/// stripped before framing is decided (issue #5299).
const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

/// Admission diagnostic for the rejected `fallback` block (issue #3328).
///
/// The plugin never switches providers, so storing a fallback policy could only
/// ever be runtime-inert. See the module docs for why pre-first-byte fallback
/// cannot be expressed at this layer.
pub const AI_STREAM_ROUTER_FALLBACK_REJECTION: &str = "ai_stream_router: unsupported field `fallback`; provider fallback is not implemented — this plugin commits one provider route, credential set, backend TLS resolution, and translated body before dispatch and never switches providers, so a stored fallback policy would be silently inert. Remove the `fallback` block.";

// ---------------------------------------------------------------------------
// Metadata keys
// ---------------------------------------------------------------------------

const META_ENABLED: &str = "ai_stream_router.enabled";
const META_CLAIMED: &str = "ai_stream_router.claimed";
/// OBSERVABILITY / third-party coordination ONLY (`GHSA-xhp5-hqj8-3mwg`).
///
/// Published so logs and external/custom plugins can see that a claim happened.
/// No BUILT-IN reads it back for a routing or egress decision: `ai_federation`,
/// `request_mirror`, `serverless_function`, `mcp_gateway`, and
/// `mesh_route_dispatch` all gate on the private typed claim through
/// `RequestContext::has_ai_stream_router_claim()`, which a later plugin cannot
/// erase or forge. Do not reintroduce a decision on this key.
const META_CLAIMED_COORD: &str = "ai_stream_router_claimed";
/// Coordination key for explicit router pass-through of streaming requests.
const META_PASSTHROUGH_COORD: &str = "ai_stream_router_pass_through";
const META_PROVIDER: &str = "ai_stream_router.provider";
const META_PROVIDER_TYPE: &str = "ai_stream_router.provider_type";
/// OBSERVABILITY ONLY (`GHSA-xhp5-hqj8-3mwg`). The model that selected the
/// provider is authorization state, so it is committed to the private claim
/// (`AiStreamRouterClaim::model`) and read from there by final model
/// enforcement and by every claim-owned response normalizer. This key is
/// published for logs and for other plugins, and a later plugin may overwrite
/// it: nothing reads it back for a policy decision.
const META_MODEL: &str = "ai_stream_router.model";
const META_NORMALIZED: &str = "ai_stream_router.normalized_response_stream";
// NOTE (`GHSA-xhp5-hqj8-3mwg`): the committed model, destination, TLS, DNS
// decision, backend-visible query, translation witness, and owning instance are
// deliberately NOT metadata keys. They live in the private, typed
// `RequestContext::ai_stream_router_claim`, so a later plugin cannot forge them,
// and a query string (which may hold a relocated credential) never reaches a
// transaction log.
/// OBSERVABILITY ONLY. The decisive translation witness is
/// `AiStreamRouterClaim::request_translated`, written by this instance's own
/// transform hook on the same context the final body hook reads.
const META_REQUEST_TRANSLATED: &str = "ai_stream_router.request_translated";
/// OBSERVABILITY ONLY. Set when the claimed Anthropic request carries
/// `tool_choice: {"type":"none"}`. The decisive value is
/// `AiStreamRouterClaim::tool_choice_none`, committed at claim time: the
/// response normalizer fails closed if the provider nevertheless emits
/// `tool_use` for that generation, so it must not be disarmable by a later
/// metadata write.
const META_TOOL_CHOICE_NONE: &str = "ai_stream_router.tool_choice_none";
/// Provider `Content-Encoding` chain that must be decoded before Anthropic SSE
/// normalization. Stamped in `after_proxy` before representation headers are
/// repaired so both streaming and buffered normalizers see the same coding list
/// (canonical application-order members joined with `", "`).
///
/// Deliberately left in metadata and deliberately NOT authorization state
/// (`GHSA-xhp5-hqj8-3mwg`): it is derived from the PROVIDER's own response
/// headers rather than from anything the claim committed, it decides only how
/// this instance's own normalizer decodes its own upstream bytes, and every
/// value it can take is bounded by [`NORMALIZE_DECODE_LIMITS`]. A forged value
/// can only make the claim owner's normalization fail (a fixed-cardinality
/// upstream error body); it cannot move a credential, a destination, or a
/// generation.
const META_PROVIDER_ENCODING: &str = "ai_stream_router.provider_content_encoding";
/// Shared marker (same contract as `ai_prompt_shield` / `ai_semantic_firewall`)
/// telling response plugins the request asked for a streaming response.
const META_STREAMING_SHARED: &str = "ai_request_streaming";

/// Bound decoding of residual provider content coding chains before SSE
/// normalization. Absolute per-layer / aggregate ceilings match the streaming
/// buffer caps; the 1024:1 ratio matches the shared compression pipeline so a
/// tiny gzip/br bomb cannot spend the full absolute budget.
const NORMALIZE_DECODE_LIMITS: DecodeLimits = DecodeLimits {
    max_decoded_bytes: 8 * 1024 * 1024,
    max_cumulative_bytes: 16 * 1024 * 1024,
    max_codings: 4,
    max_amplification_ratio: 1024,
};

/// Compile-time proof that residual-decode ceilings stay finite and ordered:
/// per-layer ≤ aggregate, layer count ≥ 1, and amplification is enabled.
const _: () = {
    assert!(NORMALIZE_DECODE_LIMITS.max_decoded_bytes > 0);
    assert!(NORMALIZE_DECODE_LIMITS.max_cumulative_bytes > 0);
    assert!(NORMALIZE_DECODE_LIMITS.max_codings > 0);
    assert!(NORMALIZE_DECODE_LIMITS.max_amplification_ratio > 0);
    assert!(
        NORMALIZE_DECODE_LIMITS.max_decoded_bytes <= NORMALIZE_DECODE_LIMITS.max_cumulative_bytes
    );
};

// ---------------------------------------------------------------------------
// Provider types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProviderType {
    OpenAi,
    OpenAiCompatible,
    /// Azure OpenAI deployment endpoint. OpenAI-shaped request and SSE, but
    /// key authentication uses the `api-key` header instead of `Authorization:
    /// Bearer`. Entra ID (OAuth2) tokens expire and are not static config, so
    /// they are out of scope here.
    AzureOpenAi,
    Anthropic,
    GoogleGemini,
}

impl ProviderType {
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "openai" => Ok(Self::OpenAi),
            "openai_compatible" => Ok(Self::OpenAiCompatible),
            "azure_openai" => Ok(Self::AzureOpenAi),
            "anthropic" => Ok(Self::Anthropic),
            "google_gemini" => Ok(Self::GoogleGemini),
            other => Err(format!(
                "ai_stream_router: unknown `provider_type` {other:?} (expected `openai`, `openai_compatible`, `azure_openai`, `anthropic`, `google_gemini`)"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
            Self::OpenAiCompatible => "openai_compatible",
            Self::AzureOpenAi => "azure_openai",
            Self::Anthropic => "anthropic",
            Self::GoogleGemini => "google_gemini",
        }
    }

    /// Whether provider-native response SSE / stream framing must be normalized
    /// to OpenAI `chat.completion.chunk` SSE.
    fn needs_response_normalization(self) -> bool {
        matches!(self, Self::Anthropic | Self::GoogleGemini)
    }
}

/// How a provider API key is injected into the forwarded request.
///
/// Both variants carry the COMPLETE, ready-to-insert header value. The final
/// provider-header policy re-runs on every backend-visible header map (each
/// `before_proxy` pass, each deferred routing pass, each finalized-egress
/// overlay, and each retry attempt), so the credential value is built once at
/// construction and only cloned into the outbound map afterwards.
///
/// Deliberately no `Debug`: every field is a live provider credential.
#[derive(Clone)]
enum ProviderAuth {
    /// `Authorization: <header_value>`, where `header_value` is the complete
    /// `Bearer <api_key>` string precomputed at construction.
    Bearer { header_value: String },
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
    /// Anthropic `max_tokens` forwarded when the client sets no output bound
    /// (`default_max_tokens`, else [`DEFAULT_ANTHROPIC_MAX_TOKENS`]).
    anthropic_default_max_tokens: u64,
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
            .any(|pat| matches_model_glob(pat, model))
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
    /// Bounds every response normalizer this instance installs (cumulative
    /// provider plaintext, event count, cumulative normalized output).
    normalize_limits: NormalizeLimits,
    /// Precomputed config-time flag: does any provider need response-stream
    /// normalization (and is normalization enabled)?
    response_stream_hooks: bool,
    /// Opaque per-INSTANCE owner identity (`GHSA-xhp5-hqj8-3mwg`).
    ///
    /// Multiple `ai_stream_router` instances may be effective on one proxy, and
    /// two of them may legitimately carry the same `provider.name` while
    /// pointing at different endpoints with different keys, different
    /// `provider_type`s, and a different normalization decision. Public
    /// metadata identifies only a provider NAME, so it cannot decide which
    /// instance owns a claim. Every claim-dependent hook therefore matches this
    /// value against the winner recorded in private request state instead.
    ///
    /// Never rendered into metadata, logs, configuration, OpenAPI, or a
    /// response: it exists only to make ownership decidable inside the process.
    owner_id: u64,
}

/// Source of [`AiStreamRouter::owner_id`] values. Monotonic and process-local;
/// the value is opaque and never leaves the process.
static NEXT_OWNER_ID: AtomicU64 = AtomicU64::new(1);

/// The private, typed provider claim recorded on [`RequestContext`] by the
/// winning `ai_stream_router` instance (`GHSA-xhp5-hqj8-3mwg`).
///
/// This is the complete witness of what the credential was committed TO,
/// INCLUDING the generation it was committed FOR. The public
/// `ai_stream_router.*` metadata keys stay what they always were —
/// observability and cross-plugin coordination — and are deliberately not
/// load-bearing here: a later plugin can write metadata, but it cannot reach
/// this struct.
///
/// Nothing in it is ever logged, serialized, echoed, or exported. It holds a
/// backend-visible query string, which a transform could have moved a
/// credential into, plus the committed model and the ownership token.
#[derive(Clone)]
pub(crate) struct AiStreamRouterClaim {
    /// Which instance won the claim. Compared against
    /// [`AiStreamRouter::owner_id`] by every claim-dependent hook.
    owner: u64,
    /// Index into the winning instance's own `providers`. An index rather than
    /// a name so a later plugin rewriting `ai_stream_router.provider` metadata
    /// cannot redirect credential injection or revalidation.
    provider_index: usize,
    /// The EXACT model string that selected `provider_index`, frozen at claim
    /// time (`GHSA-xhp5-hqj8-3mwg`).
    ///
    /// Final request-body enforcement compares the provider-visible `model`
    /// against this value and re-checks it against the selected provider's
    /// `model_patterns`; the claim-owned response normalizers stamp the
    /// client-visible generation identity from it. The public
    /// `ai_stream_router.model` metadata key is NOT usable for either: a later
    /// plugin can change the final body's model AND rewrite that key to the
    /// same value, which would satisfy an equality check against metadata while
    /// bypassing the selection that chose the provider, the price, and (for
    /// `{model}` endpoints) the backend URL.
    model: String,
    /// Whether the claimed request forbids tool use for this generation
    /// (`tool_choice: "none"` in the client body, translated to Anthropic
    /// `tool_choice: {"type":"none"}` or Gemini `functionCallingConfig.mode:
    /// "NONE"`). Committed at claim time from the client representation the
    /// claim selected on, so a later metadata write cannot disarm the response
    /// normalizer's fail-closed tool-use guard. Always `false` for providers
    /// whose responses this instance does not translate.
    tool_choice_none: bool,
    /// Set by this instance's own `transform_request_body` hook once the
    /// Anthropic or Gemini representation was produced. Read by
    /// `on_final_request_body_with_context`, which runs on the SAME context
    /// object the transform ran on (the proxy builds one hook context for both
    /// phases), so the witness never has to survive a metadata write-back and
    /// never has to be forgeable metadata.
    request_translated: bool,
    /// Backend-visible destination committed at claim time.
    scheme: BackendScheme,
    host: String,
    port: u16,
    /// Absolute backend path, including any folded endpoint query.
    path: String,
    authority: String,
    /// Exactly the `route_override_resolved_tls` this claim committed. `None`
    /// is unambiguous: the committed destination is plaintext HTTP, which is
    /// also pinned by `scheme`, so a later plugin cannot satisfy the witness by
    /// clearing a committed HTTPS configuration.
    resolved_tls: Option<Arc<BackendTlsConfig>>,
    /// The exact backend-visible query the dispatch layer may append. Empty
    /// when the committed `path` already carries every pair.
    committed_query: String,
    /// Exactly the `route_override_backend_connect_timeout_ms` this claim
    /// committed, so the dispatch policy the credential was approved under is
    /// part of the destination witness. `None` for a claim that inherits the
    /// matched proxy's connect budget (every `ai_stream_router` claim).
    committed_connect_timeout_ms: Option<u64>,
    /// Exactly the `route_override_backend_read_timeout_ms` this claim
    /// committed. Same witness role as
    /// [`Self::committed_connect_timeout_ms`]; `Some(0)` is the explicit
    /// "no gateway-imposed whole-exchange bound" commitment and is distinct
    /// from `None`.
    committed_read_timeout_ms: Option<u64>,
    /// Opaque, clone-safe lifecycle reservation owned by an EXTERNAL claim
    /// owner (`ai_federation`'s streaming path today).
    ///
    /// It carries capacity and provider-circuit admission that must be released
    /// exactly once when the request/stream reaches ANY terminal state,
    /// including cancellation. Cloning the claim (the final-request-body hook
    /// context) shares the same reservation rather than duplicating it, and the
    /// reservation's own `Drop` is the cancellation-safe backstop.
    ///
    /// `None` for every `ai_stream_router` claim: this plugin reserves no
    /// external capacity. Deliberately `dyn Any` so the claim type carries no
    /// knowledge of any particular owner's accounting.
    lifecycle: Option<Arc<dyn std::any::Any + Send + Sync>>,
    /// The client body this claim parsed and VALIDATED in `before_proxy`, kept
    /// only for Anthropic / Gemini translation so the transform hook does not
    /// re-parse and re-validate the same bytes. Consumed (taken) by the
    /// transform, and reused only when the transform's body is byte-identical
    /// to the one parsed here (length plus a keyed fingerprint); any earlier
    /// body rewrite falls back to a fresh parse and full validation.
    client_body_memo: Option<Arc<ClientBodyMemo>>,
    /// Length and keyed fingerprint of the provider body this instance's own
    /// transform produced. When the final backend-visible body is still exactly
    /// those bytes, `on_final_request_body_with_context` already knows its
    /// model (the committed one, written by the translator) and that it holds
    /// no duplicate members (serialized from a `Value`), so it skips the
    /// re-parse. Any later transform changes the bytes and restores the full
    /// revalidation.
    translated_body_fingerprint: Option<(usize, u64)>,
}

/// The parsed, already-validated client body a claim hands to its transform.
pub(crate) struct ClientBodyMemo {
    len: usize,
    fingerprint: u64,
    value: Value,
}

/// Process-local keyed hasher for request-body fingerprints. SipHash with a
/// random per-process key: a plugin that rewrites the body cannot choose bytes
/// that collide with the memoized fingerprint without knowing the key.
static BODY_FINGERPRINT_STATE: std::sync::LazyLock<std::collections::hash_map::RandomState> =
    std::sync::LazyLock::new(std::collections::hash_map::RandomState::new);

fn body_fingerprint(bytes: &[u8]) -> u64 {
    use std::hash::BuildHasher;
    BODY_FINGERPRINT_STATE.hash_one(bytes)
}

fn body_matches_fingerprint(bytes: &[u8], expected: Option<(usize, u64)>) -> bool {
    expected.is_some_and(|(len, fingerprint)| {
        bytes.len() == len && body_fingerprint(bytes) == fingerprint
    })
}

impl AiStreamRouterClaim {
    #[inline]
    pub(crate) fn committed_query(&self) -> &str {
        &self.committed_query
    }

    /// Opaque owning-instance identity. Only equality against the reader's own
    /// id is meaningful; the value is never rendered anywhere.
    #[inline]
    pub(crate) fn owner(&self) -> u64 {
        self.owner
    }

    /// Index into the OWNING plugin instance's own provider list. Meaningless
    /// to any other instance, and only read after an [`owner`](Self::owner)
    /// match.
    #[inline]
    pub(crate) fn provider_index(&self) -> usize {
        self.provider_index
    }

    /// The exact model string that selected the committed provider.
    ///
    /// Never log this: model enforcement is fixed-cardinality and must not echo
    /// a client-controlled value.
    #[inline]
    pub(crate) fn model(&self) -> &str {
        &self.model
    }

    /// The committed backend-visible authority (`Host` / `:authority`).
    ///
    /// Read by an external owner's final backend-header policy so the `Host`
    /// it re-installs is the one the claim committed, never a later transform's
    /// value.
    #[inline]
    pub(crate) fn authority(&self) -> &str {
        &self.authority
    }

    /// Whether the request context still targets exactly what this claim
    /// committed (`GHSA-xhp5-hqj8-3mwg`). Shared with every non-`ai_stream_router`
    /// owner so the destination witness cannot drift between claim owners.
    #[inline]
    pub(crate) fn destination_intact(&self, ctx: &RequestContext) -> bool {
        route_override_still_targets(ctx, self)
    }

    /// The opaque lifecycle reservation an external owner attached at claim
    /// time, if any. Only the owner can make sense of it: it downcasts to its
    /// own private type after an [`owner`](Self::owner) match.
    #[inline]
    pub(crate) fn lifecycle(&self) -> Option<&Arc<dyn std::any::Any + Send + Sync>> {
        self.lifecycle.as_ref()
    }
}

/// The complete set of values another plugin must commit to mint a provider
/// claim of its own (`GHSA-xhp5-hqj8-3mwg`).
///
/// `ai_federation`'s streaming path is the only external owner today. Keeping
/// ONE claim type — rather than a second parallel one — is load-bearing: the
/// stand-down signal every other built-in reads
/// ([`RequestContext::has_ai_stream_router_claim`]) and the committed-query
/// re-assertion funnel ([`RequestContext::committed_provider_query`]) are both
/// defined over this type, so a second type would silently bypass both.
pub(crate) struct ExternalProviderClaimParts {
    pub(crate) owner: u64,
    pub(crate) provider_index: usize,
    pub(crate) model: String,
    pub(crate) scheme: BackendScheme,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) path: String,
    pub(crate) authority: String,
    pub(crate) resolved_tls: Option<Arc<BackendTlsConfig>>,
    pub(crate) committed_query: String,
    /// The exact `route_override_backend_connect_timeout_ms` the owner
    /// committed for this destination.
    pub(crate) committed_connect_timeout_ms: Option<u64>,
    /// The exact `route_override_backend_read_timeout_ms` the owner committed
    /// for this destination.
    pub(crate) committed_read_timeout_ms: Option<u64>,
    /// Opaque, clone-safe lifecycle reservation (capacity + circuit admission)
    /// whose `Drop` releases anything still unresolved exactly once.
    pub(crate) lifecycle: Option<Arc<dyn std::any::Any + Send + Sync>>,
}

/// Mint a provider claim owned by a plugin other than `ai_stream_router`.
///
/// The owner id MUST come from [`next_provider_claim_owner_id`] so ownership is
/// decidable across plugin types: every `ai_stream_router` claim-dependent hook
/// compares `claim.owner` against its own instance id and stands down on a
/// mismatch, which is exactly the behavior an externally owned claim needs.
///
/// `tool_choice_none` and `request_translated` are deliberately fixed to
/// `false`: they gate `ai_stream_router`'s own Anthropic/Gemini translation
/// witnesses, and an external owner that performs no translation must not be
/// able to set either.
pub(crate) fn mint_external_provider_claim(
    parts: ExternalProviderClaimParts,
) -> AiStreamRouterClaim {
    AiStreamRouterClaim {
        owner: parts.owner,
        provider_index: parts.provider_index,
        model: parts.model,
        tool_choice_none: false,
        request_translated: false,
        scheme: parts.scheme,
        host: parts.host,
        port: parts.port,
        path: parts.path,
        authority: parts.authority,
        resolved_tls: parts.resolved_tls,
        committed_query: parts.committed_query,
        committed_connect_timeout_ms: parts.committed_connect_timeout_ms,
        committed_read_timeout_ms: parts.committed_read_timeout_ms,
        lifecycle: parts.lifecycle,
        client_body_memo: None,
        translated_body_fingerprint: None,
    }
}

/// Allocate a process-unique provider-claim owner identity.
///
/// Shared with every claim owner (this plugin's instances and `ai_federation`'s
/// streaming path) so two different plugin types can never mint colliding
/// ownership tokens.
pub(crate) fn next_provider_claim_owner_id() -> u64 {
    NEXT_OWNER_ID.fetch_add(1, Ordering::Relaxed)
}

/// Deliberately opaque: `RequestContext` derives `Debug`, and a derived
/// implementation here would print the committed backend-visible query (which a
/// transform may have relocated a credential into), the committed model, and
/// the ownership token into any diagnostic that formats a request context.
/// Model enforcement is fixed-cardinality and never echoes a model, so the
/// committed model must not reach a log through `Debug` either.
impl std::fmt::Debug for AiStreamRouterClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AiStreamRouterClaim(<redacted>)")
    }
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
            "ai_stream_router: `config`: ",
        )?;

        let enabled = optional_bool(config, "enabled")?.unwrap_or(true);
        let fail_on_missing_model = optional_bool(config, "fail_on_missing_model")?.unwrap_or(true);
        let fail_on_no_matching_provider =
            optional_bool(config, "fail_on_no_matching_provider")?.unwrap_or(true);
        let inject_usage_options = optional_bool(config, "inject_usage_options")?.unwrap_or(true);
        let normalize_response_stream =
            optional_bool(config, "normalize_response_stream")?.unwrap_or(true);
        let normalize_limits = NormalizeLimits {
            max_plaintext_bytes: bounded_usize_option(
                config,
                "max_stream_bytes",
                MIN_CONFIGURED_STREAM_BYTES,
                MAX_CONFIGURED_STREAM_BYTES,
            )?
            .unwrap_or(MAX_SSE_NORMALIZED_BODY_BYTES),
            max_events: bounded_usize_option(
                config,
                "max_stream_events",
                MIN_CONFIGURED_STREAM_EVENTS,
                MAX_CONFIGURED_STREAM_EVENTS,
            )?
            .unwrap_or(MAX_SSE_EVENTS),
            max_output_bytes: bounded_usize_option(
                config,
                "max_normalized_stream_bytes",
                MIN_CONFIGURED_NORMALIZED_STREAM_BYTES,
                MAX_CONFIGURED_NORMALIZED_STREAM_BYTES,
            )?
            .unwrap_or(MAX_SSE_NORMALIZED_OUTPUT_BYTES),
        };

        let providers_val = config
            .get("providers")
            .and_then(|v| v.as_array())
            .ok_or("ai_stream_router: `providers` must be a non-empty array")?;
        if providers_val.is_empty() {
            return Err("ai_stream_router: `providers` array must not be empty".to_string());
        }

        // Honor the gateway IP allowlist policy (CLI/env/conf/default precedence)
        // for config-time SSRF validation of literal-IP endpoints.
        let backend_allow_ips = http_client.backend_allow_ips().clone();

        let mut providers = Vec::with_capacity(providers_val.len());
        let mut seen_names: HashSet<String> = HashSet::with_capacity(providers_val.len());

        for (i, pv) in providers_val.iter().enumerate() {
            let provider_object = pv
                .as_object()
                .ok_or_else(|| format!("ai_stream_router: `providers[{i}]` must be an object"))?;
            let provider_path = format!("config.providers[{i}]");
            reject_unknown_keys(
                provider_object,
                &provider_path,
                AI_STREAM_ROUTER_PROVIDER_KEYS,
                &format!("ai_stream_router: `{provider_path}`: "),
            )?;

            let name = pv["name"]
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or(format!(
                    "ai_stream_router: `providers[{i}]` missing non-empty `name`"
                ))?
                .to_string();
            if !seen_names.insert(name.clone()) {
                return Err(format!(
                    "ai_stream_router: duplicate provider name {name:?}"
                ));
            }

            let provider_type_str = pv["provider_type"].as_str().ok_or(format!(
                "ai_stream_router: provider {name:?} missing `provider_type`"
            ))?;
            let provider_type = ProviderType::from_str(provider_type_str)?;

            let priority_u64 = optional_u64(pv, "priority")?.unwrap_or((i as u64) + 1);
            if priority_u64 == 0 {
                return Err(format!(
                    "ai_stream_router: provider {name:?} `priority` must be a positive integer"
                ));
            }
            let priority = u32::try_from(priority_u64).map_err(|_| {
                format!("ai_stream_router: provider {name:?} `priority` is too large")
            })?;

            let model_patterns = optional_string_vec(pv, "model_patterns")?.unwrap_or_default();
            if model_patterns.is_empty() {
                return Err(format!(
                    "ai_stream_router: provider {name:?} requires a non-empty `model_patterns` array"
                ));
            }
            if model_patterns.len() > MAX_MODEL_PATTERNS_PER_PROVIDER
                || model_patterns
                    .iter()
                    .any(|pattern| !is_valid_model_pattern(pattern))
            {
                return Err(format!(
                    "ai_stream_router: provider {name:?} `model_patterns` must contain at most {MAX_MODEL_PATTERNS_PER_PROVIDER} bounded model globs"
                ));
            }

            let endpoint = pv["endpoint"].as_str().ok_or(format!(
                "ai_stream_router: provider {name:?} missing `endpoint`"
            ))?;
            let allow_plaintext = optional_bool(pv, "allow_plaintext")?.unwrap_or(false);
            let parsed = parse_endpoint(&name, endpoint, allow_plaintext, &backend_allow_ips)?;
            // Gemini carries the model ONLY in the URL. A fixed-model endpoint
            // would generate every admitted model with whatever model the
            // endpoint hard-codes while the claim and every normalized chunk
            // stamp the requested one. Without `{model}`, the provider may
            // therefore admit exactly one exact model name, and it must be the
            // model the endpoint path itself names (`.../models/<model>:...`).
            if provider_type == ProviderType::GoogleGemini && !parsed.has_model_placeholder {
                let fixed_model_matches = match model_patterns.as_slice() {
                    [pattern] => {
                        !pattern.contains('*')
                            && parsed.path.contains(&format!("/models/{pattern}:"))
                    }
                    _ => false,
                };
                if !fixed_model_matches {
                    return Err(format!(
                        "ai_stream_router: provider {name:?} is `google_gemini` with an `endpoint` that has no `{{model}}` placeholder; Gemini routes the model only through the URL, so either add `{{model}}` to the endpoint or set `model_patterns` to the single exact model the endpoint path names (`.../models/<model>:...`)"
                    ));
                }
            }

            let api_key = config_or_env_str(pv, &name, "api_key")?.ok_or(format!(
                "ai_stream_router: provider {name:?} missing `api_key`"
            ))?;
            // Header-value validity is a per-byte property, so proving the key
            // itself is sendable also proves the `Bearer {api_key}` form the
            // OpenAI-compatible providers build from it.
            validate_provider_header_value(&name, "api_key", &api_key)?;
            let auth = build_auth(provider_type, api_key);

            let anthropic_version = optional_str(pv, "anthropic_version")?
                .unwrap_or_else(|| DEFAULT_ANTHROPIC_VERSION.to_string());
            // An explicit empty string is not omission (`null` is): it would
            // send an empty `anthropic-version` header on every request.
            if anthropic_version.is_empty() {
                return Err(format!(
                    "ai_stream_router: provider {name:?} `anthropic_version` must not be empty; omit it (or use null) to send the default {DEFAULT_ANTHROPIC_VERSION:?}"
                ));
            }
            validate_provider_header_value(&name, "anthropic_version", &anthropic_version)?;

            let anthropic_default_max_tokens = match optional_u64(pv, "default_max_tokens")? {
                None => DEFAULT_ANTHROPIC_MAX_TOKENS,
                Some(_) if provider_type != ProviderType::Anthropic => {
                    return Err(format!(
                        "ai_stream_router: provider {name:?} `default_max_tokens` is only supported for `anthropic` providers (Anthropic requires an output bound; other providers apply their own model default)"
                    ));
                }
                Some(value) if (1..=MAX_CONFIGURED_DEFAULT_MAX_TOKENS).contains(&value) => value,
                Some(_) => {
                    return Err(format!(
                        "ai_stream_router: provider {name:?} `default_max_tokens` must be between 1 and {MAX_CONFIGURED_DEFAULT_MAX_TOKENS}"
                    ));
                }
            };

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
                anthropic_default_max_tokens,
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
            normalize_limits,
            response_stream_hooks,
            owner_id: NEXT_OWNER_ID.fetch_add(1, Ordering::Relaxed),
        })
    }

    /// First provider (in priority order) whose patterns match `model`, with its
    /// index for the private claim witness.
    fn select_provider(&self, model: &str) -> Option<(usize, &StreamProvider)> {
        self.providers
            .iter()
            .enumerate()
            .find(|(_, p)| p.matches_model(model))
    }

    /// The claim and provider THIS instance owns for `ctx`, or `None`.
    ///
    /// `None` covers three distinct cases that all mean "do nothing here":
    /// the request was never claimed, another `ai_stream_router` instance won
    /// the claim (it runs the identical enforcement from the same phase), or
    /// this instance is disabled. Every claim-dependent request and response
    /// hook goes through this one gate (`GHSA-xhp5-hqj8-3mwg`), so a second
    /// instance can never re-inject its own credential, re-transform the body,
    /// revalidate against its own model policy, or install a second response
    /// normalizer.
    fn owned_claim<'a>(
        &'a self,
        ctx: &'a RequestContext,
    ) -> Option<(&'a AiStreamRouterClaim, &'a StreamProvider)> {
        if !self.enabled {
            return None;
        }
        let claim = ctx.ai_stream_router_claim.as_deref()?;
        if claim.owner != self.owner_id {
            return None;
        }
        // `provider_index` was recorded by this same instance, so the lookup
        // cannot miss; `get` keeps it total rather than indexing.
        let provider = self.providers.get(claim.provider_index)?;
        Some((claim, provider))
    }

    /// Whether THIS instance owns the claim AND its selected provider's response
    /// SSE must be normalized.
    ///
    /// Every response-side hook gates on this rather than on the public
    /// `ai_stream_router.normalized_response_stream` marker, so a losing
    /// instance cannot install a second normalizer over an already-normalized
    /// stream (`GHSA-xhp5-hqj8-3mwg`).
    fn normalizes_owned_response(&self, ctx: &RequestContext) -> bool {
        self.owned_claim(ctx).is_some_and(|(_, provider)| {
            provider.normalizes_response(self.normalize_response_stream)
        })
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
                "ai_stream_router: unsupported field `{field}`; ai_stream_router always claims `stream: true` requests and does not implement provider fallback"
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
        // Azure OpenAI key authentication.
        ProviderType::AzureOpenAi => ProviderAuth::Header {
            name: "api-key".to_string(),
            api_key,
        },
        // Build the complete `Bearer <key>` header value once, here, so the
        // final-policy hot path never formats a credential per pass.
        ProviderType::OpenAi | ProviderType::OpenAiCompatible => ProviderAuth::Bearer {
            header_value: format!("Bearer {api_key}"),
        },
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

    let parsed = Url::parse(&parse_src).map_err(|_| {
        format!("ai_stream_router: provider {provider_name:?} invalid `endpoint`: invalid URL")
    })?;

    // Embedded userinfo is never sent (only host/port/path/query are routed),
    // so an operator who put Basic-style credentials in the URL would get
    // silent provider 401s; and a fragment is never part of a request target,
    // so it would be dropped without a word. Both are configuration errors.
    // Neither the userinfo nor the fragment is echoed.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(format!(
            "ai_stream_router: provider {provider_name:?} `endpoint` must not embed userinfo credentials; configure the provider credential through `api_key`"
        ));
    }
    if parsed.fragment().is_some() {
        return Err(format!(
            "ai_stream_router: provider {provider_name:?} `endpoint` must not contain a `#` fragment; fragments are never sent to the provider"
        ));
    }

    let scheme = match parsed.scheme() {
        "https" => BackendScheme::Https,
        "http" => {
            if !allow_plaintext {
                return Err(format!(
                    "ai_stream_router: provider {provider_name:?} `endpoint` uses `http://` which is rejected by default; set `allow_plaintext: true` on the provider to override"
                ));
            }
            BackendScheme::Http
        }
        other => {
            return Err(format!(
                "ai_stream_router: provider {provider_name:?} `endpoint` has unsupported scheme {other:?} (expected `https` or `http` with `allow_plaintext`)"
            ));
        }
    };

    let (host, host_is_ipv6) = match parsed.host() {
        Some(Host::Domain(h)) if !h.is_empty() => (h.to_string(), false),
        Some(Host::Ipv4(h)) => (h.to_string(), false),
        Some(Host::Ipv6(h)) => (h.to_string(), true),
        _ => {
            return Err(format!(
                "ai_stream_router: provider {provider_name:?} `endpoint` has no host"
            ));
        }
    };

    if let Ok(ip) = host.parse::<std::net::IpAddr>()
        && !backend_allow_ips.is_allowed(&ip)
    {
        return Err(format!(
            "ai_stream_router: provider {provider_name:?} `endpoint` IP \"{ip}\" denied by backend egress policy"
        ));
    }

    let default_port = if scheme == BackendScheme::Https {
        443
    } else {
        80
    };
    // Port `0` disables a LISTENER; an outbound provider destination has no
    // such meaning. Admitting it produced a route that every matching request
    // failed to dial, long after `validate` reported the config as good
    // (issue #5302).
    if parsed.port() == Some(0) {
        return Err(format!(
            "ai_stream_router: provider {provider_name:?} `endpoint` must not use port 0; port 0 disables a listener and cannot be dialed as a provider destination"
        ));
    }
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
            .ok_or_else(|| format!("ai_stream_router: `{field}` must be a boolean")),
    }
}

/// Read an optional positive integer config field bounded to `[min, max]`.
fn bounded_usize_option(
    config: &Value,
    field: &str,
    min: u64,
    max: u64,
) -> Result<Option<usize>, String> {
    let Some(value) = optional_u64(config, field)? else {
        return Ok(None);
    };
    if !(min..=max).contains(&value) {
        return Err(format!(
            "ai_stream_router: `{field}` must be between {min} and {max}"
        ));
    }
    usize::try_from(value)
        .map(Some)
        .map_err(|_| format!("ai_stream_router: `{field}` is too large for this platform"))
}

fn optional_u64(config: &Value, field: &str) -> Result<Option<u64>, String> {
    match config.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("ai_stream_router: `{field}` must be an unsigned integer")),
    }
}

/// Read an optional string field, rejecting a non-null value of the wrong type.
///
/// `as_str().unwrap_or(default)` silently accepted `anthropic_version: 123` and
/// then sent the unrelated default version header, so the stored configuration
/// and the effective behavior disagreed with no diagnostic anywhere (issue
/// #5301). An explicit `null` still means omission, exactly as it does for
/// [`optional_bool`] and [`optional_u64`].
fn optional_str(config: &Value, field: &str) -> Result<Option<String>, String> {
    match config.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_str()
            .map(|s| Some(s.to_string()))
            .ok_or_else(|| format!("ai_stream_router: `{field}` must be a string")),
    }
}

fn optional_string_vec(config: &Value, field: &str) -> Result<Option<Vec<String>>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(values) = value.as_array() else {
        return Err(format!("ai_stream_router: `{field}` must be an array"));
    };
    let mut out = Vec::with_capacity(values.len());
    for v in values {
        let Some(s) = v.as_str() else {
            return Err(format!(
                "ai_stream_router: `{field}` must contain only strings"
            ));
        };
        if s.is_empty() {
            return Err(format!(
                "ai_stream_router: `{field}` must not contain empty strings"
            ));
        }
        out.push(s.to_string());
    }
    Ok(Some(out))
}

/// Reject a configured provider string that cannot become an HTTP header value.
///
/// [`build_auth`] and [`apply_provider_boundary_headers`] hand these strings
/// straight to the outbound header map, so a value carrying a newline or a
/// control character was only discovered at dispatch: every request routed to
/// that provider failed with a `502` the operator could not diagnose, while
/// `ferrum-edge validate` reported the configuration as good (issue #5300).
/// Screening the FINAL value here — after `${FERRUM_PLUGIN_SECRET_<NAME>}`
/// resolution — turns an operator typo into a configuration error. The value
/// itself is never echoed, because `api_key` is a live credential.
fn validate_provider_header_value(provider: &str, field: &str, value: &str) -> Result<(), String> {
    if reqwest::header::HeaderValue::from_str(value).is_err() {
        return Err(format!(
            "ai_stream_router: provider {provider:?} `{field}` is not a valid HTTP header value"
        ));
    }
    Ok(())
}

/// Read a config string, resolving a whole-value `${FERRUM_PLUGIN_SECRET_<NAME>}`
/// reference against the process environment. A `${...}` reference to any
/// other variable is refused before anything is read, so a config writer
/// cannot direct an unrelated process secret to a provider endpoint it chose.
fn config_or_env_str(
    config: &Value,
    provider: &str,
    field: &str,
) -> Result<Option<String>, String> {
    let Some(raw) = config.get(field).and_then(|v| v.as_str()) else {
        return Ok(None);
    };
    if raw.is_empty() {
        return Ok(None);
    }
    if let Some(var) = raw
        .strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
    {
        let label = format!("ai_stream_router: provider {provider:?} `{field}`");
        return resolve_plugin_secret_env(&label, var).map(Some);
    }
    Ok(Some(raw.to_string()))
}

// ---------------------------------------------------------------------------
// Model matching (glob)
// ---------------------------------------------------------------------------

// Model globs are matched by the shared `utils::ai_model_glob` helper: the
// pattern is anchored to both ends of the model name and a `*` window may not
// consume a URL-structural separator or whitespace. The matcher lives in
// `plugins::utils` rather than here because `ai_federation` carries the same
// contract, and the two private copies drifted into the same defect twice
// (issues #5297 / #5392 here, #5255 there).

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

/// Closed Gemini-representable OpenAI message `content`.
///
/// Only a string or a closed array of text-part objects with exactly `type` and
/// `text` may be translated. Mixed text-plus-image/audio/unknown parts, extra
/// or unknown fields on a text part, non-object array members, malformed text
/// parts, null content, and non-array/non-string shapes fail closed rather than
/// being silently reduced. Callers that intentionally
/// allow assistant null/empty content when a valid `tool_calls` or legacy
/// `function_call` is present must handle that null case before calling this
/// helper.
fn gemini_message_content_text(content: &Value) -> Result<String, String> {
    if let Some(text) = content.as_str() {
        return Ok(text.to_string());
    }
    if content.is_null() {
        return Err("content must be a string or text-parts array".to_string());
    }
    let parts = content
        .as_array()
        .ok_or_else(|| "content must be a string or text-parts array".to_string())?;
    let mut out = String::new();
    for (index, part) in parts.iter().enumerate() {
        let Some(object) = part.as_object() else {
            return Err(format!(
                "content[{index}] is not a Gemini-representable text part"
            ));
        };
        // Closed claim shape: exactly `{ "type": "text", "text": "..." }`.
        if object.len() != 2 || object.get("type").and_then(Value::as_str) != Some("text") {
            return Err(format!(
                "content[{index}] is not a Gemini-representable text part"
            ));
        }
        let text = object
            .get("text")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("content[{index}] text part is malformed"))?;
        if text.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(text);
    }
    Ok(out)
}

/// Closed Anthropic-representable OpenAI message `content`.
///
/// Only a string or a closed array of text-part objects with exactly `type` and
/// `text` may be translated. Mixed text-plus-image/audio/unknown parts, extra
/// or unknown fields on a text part, non-object array members, malformed text
/// parts, null content, and non-array/non-string shapes fail closed rather than
/// being silently reduced. Callers that intentionally allow assistant null/empty
/// content when a valid `tool_calls` or legacy `function_call` is present must
/// handle that null case before calling this helper.
fn anthropic_message_content_text(content: &Value) -> Result<String, String> {
    if let Some(text) = content.as_str() {
        return Ok(text.to_string());
    }
    if content.is_null() {
        return Err("content must be a string or text-parts array".to_string());
    }
    let parts = content
        .as_array()
        .ok_or_else(|| "content must be a string or text-parts array".to_string())?;
    let mut out = String::new();
    for (index, part) in parts.iter().enumerate() {
        let Some(object) = part.as_object() else {
            return Err(format!(
                "content[{index}] is not an Anthropic-representable text part"
            ));
        };
        // Closed claim shape: exactly `{ "type": "text", "text": "..." }`.
        if object.len() != 2 || object.get("type").and_then(Value::as_str) != Some("text") {
            return Err(format!(
                "content[{index}] is not an Anthropic-representable text part"
            ));
        }
        let text = object
            .get("text")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("content[{index}] text part is malformed"))?;
        if text.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(text);
    }
    Ok(out)
}

/// Image media types both translated providers accept inline.
const SUPPORTED_INLINE_IMAGE_MEDIA_TYPES: &[&str] =
    &["image/jpeg", "image/png", "image/gif", "image/webp"];

/// Upper bound on one base64 data-URL image payload (bytes of base64 text).
const MAX_INLINE_IMAGE_BASE64_BYTES: usize = 20 * 1024 * 1024;

/// A base64 data-URL image from an OpenAI `image_url` content part.
struct InlineImage {
    media_type: &'static str,
    data: String,
}

/// One translatable part of an OpenAI USER message `content` array.
enum UserContentPart {
    Text(String),
    Image(InlineImage),
}

/// Whether `data` is structurally valid standard-alphabet base64: decoded by a
/// real decoder, so padding placement, final-quantum length, and trailing bits
/// are all checked (an alphabet-only scan admitted `=` or `AA=A`). Padding may
/// be present or stripped; a URL-safe alphabet is rejected. The caller bounds
/// `data` first, so the transient decode buffer is bounded too.
fn is_base64_payload(data: &str) -> bool {
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
    !data.is_empty()
        && DECODER
            .decode(data.as_bytes())
            .is_ok_and(|decoded| !decoded.is_empty())
}

/// Closed OpenAI `{"type":"image_url","image_url":{"url":...,"detail"?}}`
/// part carrying a base64 `data:` URL of a supported image media type.
///
/// Remote `http(s)` image URLs are not fetched or forwarded: they fail closed
/// with a fixed diagnostic. Neither the URL nor any payload byte is echoed.
fn parse_inline_image_part(
    object: &serde_json::Map<String, Value>,
    index: usize,
    provider_label: &str,
) -> Result<InlineImage, String> {
    let malformed = || format!("content[{index}] image_url part is malformed");
    if object.len() != 2 {
        return Err(malformed());
    }
    let image_url = object
        .get("image_url")
        .and_then(Value::as_object)
        .ok_or_else(malformed)?;
    if image_url.keys().any(|key| key != "url" && key != "detail") {
        return Err(malformed());
    }
    match image_url.get("detail") {
        None | Some(Value::Null) => {}
        Some(Value::String(detail)) if matches!(detail.as_str(), "auto" | "low" | "high") => {}
        Some(_) => return Err(malformed()),
    }
    let url = image_url
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(malformed)?;
    let has_prefix = |prefix: &str| {
        url.get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    };
    let Some(rest) = url.get(5..).filter(|_| has_prefix("data:")) else {
        if has_prefix("http://") || has_prefix("https://") {
            return Err(format!(
                "content[{index}] remote image URLs are not supported for {provider_label} translation; send the image as a base64 data URL"
            ));
        }
        return Err(format!(
            "content[{index}] image_url must be a base64 data URL"
        ));
    };
    if url.len() > MAX_INLINE_IMAGE_BASE64_BYTES + 64 {
        return Err(format!(
            "content[{index}] image exceeds the maximum inline image size"
        ));
    }
    let (meta, payload) = rest.split_once(',').ok_or_else(malformed)?;
    let (mime, encoding) = meta.split_once(';').ok_or_else(malformed)?;
    if !encoding.eq_ignore_ascii_case("base64") {
        return Err(format!(
            "content[{index}] image_url must be a base64 data URL"
        ));
    }
    let media_type = SUPPORTED_INLINE_IMAGE_MEDIA_TYPES
        .iter()
        .copied()
        .find(|supported| supported.eq_ignore_ascii_case(mime))
        .ok_or_else(|| {
            format!(
                "content[{index}] image media type is not supported (expected image/jpeg, image/png, image/gif, or image/webp)"
            )
        })?;
    if payload.len() > MAX_INLINE_IMAGE_BASE64_BYTES {
        return Err(format!(
            "content[{index}] image exceeds the maximum inline image size"
        ));
    }
    if !is_base64_payload(payload) {
        return Err(format!("content[{index}] image data is not valid base64"));
    }
    Ok(InlineImage {
        media_type,
        data: payload.to_string(),
    })
}

/// Closed OpenAI USER message content: a string, or an array of closed text
/// parts (`type` + `text`) and closed base64 data-URL `image_url` parts.
/// Everything else (audio, files, remote image URLs, extra fields, non-object
/// members, null) fails closed.
fn user_message_content_parts(
    content: &Value,
    provider_label: &str,
) -> Result<Vec<UserContentPart>, String> {
    if let Some(text) = content.as_str() {
        return Ok(vec![UserContentPart::Text(text.to_string())]);
    }
    let parts = content
        .as_array()
        .ok_or_else(|| "content must be a string or content-parts array".to_string())?;
    let mut out = Vec::with_capacity(parts.len());
    for (index, part) in parts.iter().enumerate() {
        let Some(object) = part.as_object() else {
            return Err(format!(
                "content[{index}] is not a {provider_label}-representable text or image part (image parts must be base64 data URLs)"
            ));
        };
        match object.get("type").and_then(Value::as_str) {
            Some("text") if object.len() == 2 => {
                let text = object
                    .get("text")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("content[{index}] text part is malformed"))?;
                out.push(UserContentPart::Text(text.to_string()));
            }
            Some("image_url") => {
                out.push(UserContentPart::Image(parse_inline_image_part(
                    object,
                    index,
                    provider_label,
                )?));
            }
            _ => {
                return Err(format!(
                    "content[{index}] is not a {provider_label}-representable text or image part (image parts must be base64 data URLs)"
                ));
            }
        }
    }
    Ok(out)
}

fn has_inline_image(parts: &[UserContentPart]) -> bool {
    parts
        .iter()
        .any(|part| matches!(part, UserContentPart::Image(_)))
}

/// Anthropic `content` for an OpenAI user message. Text-only content keeps the
/// historical joined-string translation; content with images becomes ordered
/// Anthropic `text` / base64 `image` blocks.
fn anthropic_user_content(content: &Value) -> Result<Value, String> {
    let parts = user_message_content_parts(content, "Anthropic")?;
    if !has_inline_image(&parts) {
        return anthropic_message_content_text(content).map(Value::String);
    }
    let mut blocks = Vec::with_capacity(parts.len());
    for part in parts {
        match part {
            UserContentPart::Text(text) if text.is_empty() => {}
            UserContentPart::Text(text) => blocks.push(json!({ "type": "text", "text": text })),
            UserContentPart::Image(image) => blocks.push(json!({
                "type": "image",
                "source": {
                    "type": "base64",
                    "media_type": image.media_type,
                    "data": image.data,
                }
            })),
        }
    }
    Ok(Value::Array(blocks))
}

/// Gemini `parts` for an OpenAI user message. Text-only content keeps the
/// historical single joined text part; content with images becomes ordered
/// Gemini `text` / `inlineData` parts.
fn gemini_user_parts(content: &Value) -> Result<Vec<Value>, String> {
    let parts = user_message_content_parts(content, "Gemini")?;
    if !has_inline_image(&parts) {
        let text = gemini_message_content_text(content)?;
        return Ok(if text.is_empty() {
            Vec::new()
        } else {
            vec![json!({ "text": text })]
        });
    }
    let mut out = Vec::with_capacity(parts.len());
    for part in parts {
        match part {
            UserContentPart::Text(text) if text.is_empty() => {}
            UserContentPart::Text(text) => out.push(json!({ "text": text })),
            UserContentPart::Image(image) => out.push(json!({
                "inlineData": {
                    "mimeType": image.media_type,
                    "data": image.data,
                }
            })),
        }
    }
    Ok(out)
}

#[derive(Clone)]
struct ParsedToolCall {
    id: String,
    name: String,
    arguments: Value,
}

/// Upper bound on one Gemini thought signature (base64 text bytes).
const MAX_THOUGHT_SIGNATURE_BYTES: usize = 64 * 1024;

/// A Gemini thought signature: opaque, non-empty, bounded base64 text.
fn valid_thought_signature(signature: &str) -> bool {
    !signature.is_empty()
        && signature.len() <= MAX_THOUGHT_SIGNATURE_BYTES
        && signature.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_')
        })
}

/// The Gemini thought signature an OpenAI client round-tripped on an assistant
/// tool call, in Google's OpenAI-compatibility shape
/// `tool_calls[i].extra_content.google.thought_signature`.
///
/// Absent/`null` at any level means no signature. A present value of the wrong
/// shape, or a malformed signature, fails closed rather than being dropped:
/// Gemini 3 rejects a function-call continuation whose signature is missing.
fn openai_tool_call_thought_signature(
    message: &Value,
    message_index: usize,
    tool_index: usize,
) -> Result<Option<String>, String> {
    let malformed = || {
        format!(
            "messages[{message_index}].tool_calls[{tool_index}].extra_content.google.thought_signature is malformed"
        )
    };
    let Some(extra) = message
        .get("tool_calls")
        .and_then(|calls| calls.get(tool_index))
        .and_then(|call| call.get("extra_content"))
        .filter(|extra| !extra.is_null())
    else {
        return Ok(None);
    };
    let extra = extra.as_object().ok_or_else(malformed)?;
    let Some(google) = extra.get("google").filter(|google| !google.is_null()) else {
        return Ok(None);
    };
    let google = google.as_object().ok_or_else(malformed)?;
    let Some(signature) = google
        .get("thought_signature")
        .filter(|signature| !signature.is_null())
    else {
        return Ok(None);
    };
    signature
        .as_str()
        .filter(|signature| valid_thought_signature(signature))
        .map(|signature| Some(signature.to_string()))
        .ok_or_else(malformed)
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
            if tool_calls.is_empty() && legacy_call.is_none() {
                let content = message_object.get("content").unwrap_or(&Value::Null);
                let text = if content.is_null() {
                    String::new()
                } else {
                    anthropic_message_content_text(content)
                        .map_err(|error| format!("messages[{index}] {error}"))?
                };
                if text.is_empty() {
                    return Err(format!(
                        "messages[{index}] has no Anthropic-representable content"
                    ));
                }
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

fn validate_anthropic_translation(
    openai_body: &Value,
    default_max_tokens: u64,
) -> Result<(), String> {
    let messages = openai_body
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| "request missing 'messages' array".to_string())?;
    validate_openai_tool_history(messages)?;
    for (message_index, message) in messages.iter().enumerate() {
        let role = message["role"].as_str().unwrap_or("");
        if is_system_role(role) {
            anthropic_message_content_text(&message["content"])
                .map_err(|error| format!("messages[{message_index}] {error}"))?;
            continue;
        }
        if matches!(role, "tool" | "function") {
            continue;
        }
        if role == "user" {
            if message["content"].is_null() {
                return Err(format!(
                    "messages[{message_index}] content must be a string or text-parts array"
                ));
            }
            anthropic_user_content(&message["content"])
                .map_err(|error| format!("messages[{message_index}] {error}"))?;
            continue;
        }
        if role != "assistant" {
            continue;
        }
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
        let has_tool_representation = !tool_calls.is_empty() || legacy_call.is_some();
        let text = if message["content"].is_null() {
            if role == "assistant" && has_tool_representation {
                String::new()
            } else {
                return Err(format!(
                    "messages[{message_index}] content must be a string or text-parts array"
                ));
            }
        } else {
            anthropic_message_content_text(&message["content"])
                .map_err(|error| format!("messages[{message_index}] {error}"))?
        };
        if role == "assistant" && text.is_empty() && !has_tool_representation {
            return Err(format!(
                "messages[{message_index}] has no Anthropic-representable content"
            ));
        }
    }
    let tool_choice = resolve_anthropic_tool_choice(openai_body)?;
    let tool_choice_kind = tool_choice.as_ref().map(|(kind, _)| *kind);
    let thinking = resolve_anthropic_thinking(openai_body, tool_choice_kind, default_max_tokens)?;
    if matches!(
        thinking
            .as_ref()
            .and_then(|thinking| thinking.get("type"))
            .and_then(Value::as_str),
        Some("enabled" | "adaptive")
    ) {
        // Extended thinking (manual or adaptive) with tool use requires the
        // provider's signed thinking blocks emitted in a tool-use turn to be
        // replayed, complete and unmodified, when that turn's `tool_result`s
        // come back. The OpenAI Chat Completions representation has no carrier
        // for those blocks: manual mode would be rejected by the provider, and
        // adaptive mode would silently lose the reasoning state the turn was
        // built on. Refuse the combination up front with a clear diagnostic
        // instead of letting the agent loop degrade or fail on its second turn.
        let tools_callable = openai_declared_tool_names(openai_body)?.is_some()
            && tool_choice_kind != Some(ToolChoiceKind::None);
        let continues_tool_turn = messages
            .iter()
            .rev()
            .find(|message| message["role"].as_str() == Some("assistant"))
            .is_some_and(|message| {
                message
                    .get("tool_calls")
                    .is_some_and(|value| !value.is_null())
                    || message
                        .get("function_call")
                        .is_some_and(|value| !value.is_null())
            });
        if tools_callable || continues_tool_turn {
            return Err(
                "extended thinking (thinking.type \"enabled\" or \"adaptive\") cannot be combined with callable tools or a tool-result continuation: signed thinking blocks cannot be round-tripped through the OpenAI representation; use tool_choice \"none\" or disable thinking for tool turns".to_string(),
            );
        }
    }
    resolve_anthropic_effort(openai_body)?;
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

/// The client's OpenAI output bound (`max_tokens`, else
/// `max_completion_tokens`). A present non-null value of either field must be a
/// positive integer; a string, float, negative, or zero is rejected rather than
/// silently treated as omission.
fn openai_max_output_tokens(openai_body: &Value) -> Result<Option<u64>, String> {
    let mut resolved = None;
    for field in ["max_tokens", "max_completion_tokens"] {
        match openai_body.get(field) {
            None | Some(Value::Null) => {}
            Some(value) => {
                let tokens = value
                    .as_u64()
                    .filter(|tokens| *tokens > 0)
                    .ok_or_else(|| format!("{field} must be a positive integer"))?;
                resolved = resolved.or(Some(tokens));
            }
        }
    }
    Ok(resolved)
}

/// Effective Anthropic `max_tokens` this route forwards (OpenAI `max_tokens`,
/// else `max_completion_tokens`, else the provider's `default_max_tokens`).
fn anthropic_effective_max_tokens(
    openai_body: &Value,
    default_max_tokens: u64,
) -> Result<u64, String> {
    Ok(openai_max_output_tokens(openai_body)?.unwrap_or(default_max_tokens))
}

/// A request-parameter refusal with the OpenAI `param` it concerns.
struct ParamRejection {
    param: &'static str,
    code: &'static str,
    message: String,
}

impl ParamRejection {
    fn unsupported(param: &'static str, message: impl Into<String>) -> Self {
        Self {
            param,
            code: "unsupported_parameter",
            message: message.into(),
        }
    }

    fn invalid(param: &'static str, message: impl Into<String>) -> Self {
        Self {
            param,
            code: "invalid_parameter",
            message: message.into(),
        }
    }
}

fn present<'a>(openai_body: &'a Value, field: &str) -> Option<&'a Value> {
    openai_body.get(field).filter(|value| !value.is_null())
}

/// Shared closed-shape checks for OpenAI parameters neither translated provider
/// can represent in a streamed generation (`logit_bias`, `logprobs`,
/// `top_logprobs`) plus the output bound and `parallel_tool_calls` typing.
fn validate_common_request_params(
    openai_body: &Value,
    provider_label: &str,
) -> Result<(), ParamRejection> {
    openai_max_output_tokens(openai_body)
        .map_err(|message| ParamRejection::invalid("max_tokens", message))?;
    if let Some(bias) = present(openai_body, "logit_bias") {
        let Some(bias) = bias.as_object() else {
            return Err(ParamRejection::invalid(
                "logit_bias",
                "logit_bias must be an object",
            ));
        };
        if !bias.is_empty() {
            return Err(ParamRejection::unsupported(
                "logit_bias",
                format!("logit_bias has no {provider_label} equivalent"),
            ));
        }
    }
    match present(openai_body, "logprobs") {
        None | Some(Value::Bool(false)) => {}
        Some(Value::Bool(true)) => {
            return Err(ParamRejection::unsupported(
                "logprobs",
                format!("logprobs are not supported for {provider_label} stream normalization"),
            ));
        }
        Some(_) => {
            return Err(ParamRejection::invalid(
                "logprobs",
                "logprobs must be a boolean",
            ));
        }
    }
    if present(openai_body, "top_logprobs").is_some() {
        return Err(ParamRejection::unsupported(
            "top_logprobs",
            format!("top_logprobs are not supported for {provider_label} stream normalization"),
        ));
    }
    if present(openai_body, "parallel_tool_calls").is_some_and(|value| !value.is_boolean()) {
        return Err(ParamRejection::invalid(
            "parallel_tool_calls",
            "parallel_tool_calls must be a boolean",
        ));
    }
    Ok(())
}

/// `n`, as a positive integer, when present.
fn openai_choice_count(openai_body: &Value) -> Result<Option<u64>, ParamRejection> {
    match present(openai_body, "n") {
        None => Ok(None),
        Some(value) => value
            .as_u64()
            .filter(|count| *count > 0)
            .map(Some)
            .ok_or_else(|| ParamRejection::invalid("n", "n must be a positive integer")),
    }
}

/// `response_format` as a closed shape: `None` for absent / `{"type":"text"}`,
/// otherwise the JSON-object or JSON-schema request.
enum ResponseFormat<'a> {
    JsonObject,
    JsonSchema { schema: &'a Value, strict: bool },
}

/// JSON Schema keywords Gemini `responseJsonSchema` documents as enforced.
/// Deliberately conservative: an unlisted keyword (`minLength`, `pattern`,
/// `uniqueItems`, `oneOf`, `const`, ...) is treated as unenforced, so a strict
/// schema using it is refused rather than silently weakened.
const GEMINI_STRICT_SCHEMA_KEYWORDS: &[&str] = &[
    "type",
    "title",
    "description",
    "enum",
    "format",
    "anyOf",
    "$ref",
    "$defs",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "prefixItems",
    "minItems",
    "maxItems",
    "minimum",
    "maximum",
];

/// String `format` values Gemini documents as enforced.
const GEMINI_STRICT_SCHEMA_FORMATS: &[&str] = &["date-time", "date", "time"];

/// Non-`$` keywords that may sit beside `$ref`: annotations that change no
/// constraint. `$`-prefixed siblings (`$defs`) are reference/definition
/// metadata Gemini permits beside `$ref`; every keyword still has to pass
/// [`GEMINI_STRICT_SCHEMA_KEYWORDS`], and `$defs` entries are screened too.
const GEMINI_REF_SIBLING_ANNOTATIONS: &[&str] = &["title", "description"];

/// Nesting bound for the strict-schema screen; deeper schemas are refused
/// rather than walked, so hostile nesting cannot grow the stack.
const MAX_STRICT_SCHEMA_DEPTH: usize = 32;

/// Check one strict JSON Schema node (and every nested subschema) against the
/// Gemini-enforced subset. Diagnostics are fixed and never echo schema keys or
/// values.
fn screen_gemini_strict_schema(schema: &Value, depth: usize) -> Result<(), &'static str> {
    if depth > MAX_STRICT_SCHEMA_DEPTH {
        return Err("strict response_format json_schema nests too deeply for Gemini translation");
    }
    let object = match schema {
        // Boolean subschemas (`true` / `false`) carry no keywords.
        Value::Bool(_) => return Ok(()),
        Value::Object(object) => object,
        _ => return Err("strict response_format json_schema contains a non-object subschema"),
    };
    if object.contains_key("$ref")
        && object.keys().any(|keyword| {
            !keyword.starts_with('$') && !GEMINI_REF_SIBLING_ANNOTATIONS.contains(&keyword.as_str())
        })
    {
        return Err(
            "strict response_format json_schema combines `$ref` with sibling constraints, which Gemini does not apply",
        );
    }
    for (keyword, value) in object {
        if !GEMINI_STRICT_SCHEMA_KEYWORDS.contains(&keyword.as_str()) {
            return Err(
                "strict response_format json_schema uses a keyword Gemini does not enforce",
            );
        }
        match keyword.as_str() {
            "format" => {
                if !value
                    .as_str()
                    .is_some_and(|format| GEMINI_STRICT_SCHEMA_FORMATS.contains(&format))
                {
                    return Err(
                        "strict response_format json_schema uses a `format` Gemini does not enforce (supported: date-time, date, time)",
                    );
                }
            }
            "$ref" => {
                // Only document-local references resolve inside the schema the
                // provider receives.
                if !value
                    .as_str()
                    .is_some_and(|reference| reference.starts_with('#'))
                {
                    return Err(
                        "strict response_format json_schema `$ref` must be a local `#...` reference",
                    );
                }
            }
            "properties" | "$defs" => {
                let members = value.as_object().ok_or(
                    "strict response_format json_schema `properties` / `$defs` must be an object",
                )?;
                for member in members.values() {
                    screen_gemini_strict_schema(member, depth + 1)?;
                }
            }
            "anyOf" | "prefixItems" => {
                let members = value.as_array().ok_or(
                    "strict response_format json_schema `anyOf` / `prefixItems` must be an array",
                )?;
                for member in members {
                    screen_gemini_strict_schema(member, depth + 1)?;
                }
            }
            "items" | "additionalProperties" => {
                screen_gemini_strict_schema(value, depth + 1)?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn openai_response_format(
    openai_body: &Value,
) -> Result<Option<ResponseFormat<'_>>, ParamRejection> {
    let invalid = || {
        ParamRejection::invalid(
            "response_format",
            "response_format must be {\"type\":\"text\"}, {\"type\":\"json_object\"}, or {\"type\":\"json_schema\",\"json_schema\":{\"name\":...,\"schema\":{...}}}",
        )
    };
    let Some(format) = present(openai_body, "response_format") else {
        return Ok(None);
    };
    let format = format.as_object().ok_or_else(invalid)?;
    match format.get("type").and_then(Value::as_str) {
        Some("text") if format.len() == 1 => Ok(None),
        Some("json_object") if format.len() == 1 => Ok(Some(ResponseFormat::JsonObject)),
        Some("json_schema") if format.len() == 2 => {
            let spec = format
                .get("json_schema")
                .and_then(Value::as_object)
                .ok_or_else(invalid)?;
            if spec
                .keys()
                .any(|key| !matches!(key.as_str(), "name" | "schema" | "strict" | "description"))
            {
                return Err(invalid());
            }
            if !spec.get("name").is_some_and(Value::is_string) {
                return Err(invalid());
            }
            let strict = match spec.get("strict") {
                None | Some(Value::Null) => false,
                Some(Value::Bool(strict)) => *strict,
                Some(_) => return Err(invalid()),
            };
            if spec
                .get("description")
                .is_some_and(|description| !description.is_string() && !description.is_null())
            {
                return Err(invalid());
            }
            let schema = spec
                .get("schema")
                .filter(|schema| schema.is_object())
                .ok_or_else(invalid)?;
            Ok(Some(ResponseFormat::JsonSchema { schema, strict }))
        }
        _ => Err(invalid()),
    }
}

/// OpenAI request parameters the Anthropic translator either maps exactly or
/// must refuse. Fields with no Anthropic equivalent are rejected with an
/// OpenAI-shaped `400` instead of being silently dropped.
fn validate_anthropic_request_params(openai_body: &Value) -> Result<(), ParamRejection> {
    validate_common_request_params(openai_body, "Anthropic")?;
    if openai_choice_count(openai_body)?.is_some_and(|count| count > 1) {
        return Err(ParamRejection::unsupported(
            "n",
            "n > 1 is not supported for Anthropic translation",
        ));
    }
    for penalty in ["presence_penalty", "frequency_penalty"] {
        if let Some(value) = present(openai_body, penalty) {
            let Some(number) = value.as_f64() else {
                return Err(ParamRejection::invalid(
                    penalty,
                    format!("{penalty} must be a number"),
                ));
            };
            if number != 0.0 {
                return Err(ParamRejection::unsupported(
                    penalty,
                    format!("{penalty} has no Anthropic equivalent"),
                ));
            }
        }
    }
    if present(openai_body, "seed").is_some() {
        return Err(ParamRejection::unsupported(
            "seed",
            "seed has no Anthropic equivalent",
        ));
    }
    if openai_response_format(openai_body)?.is_some() {
        return Err(ParamRejection::unsupported(
            "response_format",
            "JSON response_format is not supported for Anthropic translation; use an openai_compatible provider or describe the output format in the prompt",
        ));
    }
    Ok(())
}

/// OpenAI request parameters the Gemini translator maps exactly or must
/// refuse.
fn validate_gemini_request_params(openai_body: &Value) -> Result<(), ParamRejection> {
    validate_common_request_params(openai_body, "Gemini")?;
    openai_choice_count(openai_body)?;
    for penalty in ["presence_penalty", "frequency_penalty"] {
        if present(openai_body, penalty).is_some_and(|value| !value.is_number()) {
            return Err(ParamRejection::invalid(
                penalty,
                format!("{penalty} must be a number"),
            ));
        }
    }
    if present(openai_body, "seed").is_some_and(|seed| seed.as_i64().is_none()) {
        return Err(ParamRejection::invalid("seed", "seed must be an integer"));
    }
    // A STRICT schema is a contract the client relies on: every constraint in
    // it must be one Gemini enforces, or the request is refused rather than
    // answered with output that may violate it. Non-strict schemas are
    // best-effort in OpenAI's own contract and are forwarded as-is.
    if let Some(ResponseFormat::JsonSchema {
        schema,
        strict: true,
    }) = openai_response_format(openai_body)?
    {
        screen_gemini_strict_schema(schema, 0)
            .map_err(|message| ParamRejection::unsupported("response_format", message))?;
    }
    // Gemini has no switch that limits a turn to one function call, so a
    // client that disabled parallel calls for callable tools cannot have that
    // contract honored.
    if present(openai_body, "parallel_tool_calls") == Some(&Value::Bool(false))
        && gemini_declared_function_names(openai_body)
            .ok()
            .flatten()
            .is_some()
        && openai_body.get("tool_choice").and_then(Value::as_str) != Some("none")
    {
        return Err(ParamRejection::unsupported(
            "parallel_tool_calls",
            "parallel_tool_calls: false has no Gemini equivalent",
        ));
    }
    Ok(())
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
/// thinking (`type: "enabled"`) cannot combine with forced tool use (the
/// broader tools/continuation refusal for both manual and adaptive thinking
/// lives in [`validate_anthropic_translation`]). Budget must satisfy
/// Anthropic's ordinary contract relative to the effective `max_tokens` this
/// route forwards.
fn resolve_anthropic_thinking(
    openai_body: &Value,
    tool_choice_kind: Option<ToolChoiceKind>,
    default_max_tokens: u64,
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
            let max_tokens = anthropic_effective_max_tokens(openai_body, default_max_tokens)
                .map_err(|_| "unsupported or malformed thinking".to_string())?;
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
            // `display` is the only optional key. Current models default to
            // `omitted`, so a caller that streams reasoning must be able to ask
            // for `summarized`.
            let display = match object.get("display") {
                None => None,
                Some(Value::String(display))
                    if matches!(display.as_str(), "summarized" | "omitted") =>
                {
                    Some(display.as_str())
                }
                Some(_) => return Err("unsupported or malformed thinking".to_string()),
            };
            if object.len() != 1 + usize::from(display.is_some()) {
                return Err("unsupported or malformed thinking".to_string());
            }
            match display {
                Some(display) => json!({ "type": "adaptive", "display": display }),
                None => json!({ "type": "adaptive" }),
            }
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

/// Map OpenAI `reasoning_effort` onto Anthropic `output_config.effort`. Only
/// levels with an exact Anthropic counterpart are admitted; OpenAI `none` and
/// `minimal` have none and are rejected rather than silently rounded.
fn resolve_anthropic_effort(openai_body: &Value) -> Result<Option<&'static str>, String> {
    let Some(effort) = openai_body.get("reasoning_effort") else {
        return Ok(None);
    };
    if effort.is_null() {
        return Ok(None);
    }
    match effort.as_str() {
        Some("low") => Ok(Some("low")),
        Some("medium") => Ok(Some("medium")),
        Some("high") => Ok(Some("high")),
        Some("xhigh") => Ok(Some("xhigh")),
        Some("max") => Ok(Some("max")),
        _ => Err("unsupported reasoning_effort".to_string()),
    }
}

/// Translate an OpenAI Chat Completions streaming request into an Anthropic
/// Messages API streaming request body. Preserves assistant `tool_calls` and
/// matching `role: "tool"` results, plus legacy assistant `function_call` and
/// matching `role: "function"` results; rejects malformed history instead of
/// dropping it.
///
/// `prevalidated` is true only when `openai_body` is the exact value the claim
/// already ran [`validate_anthropic_request_params`] and
/// [`validate_anthropic_translation`] over (same bytes, see
/// [`ClientBodyMemo`]); any other input is validated here first.
fn translate_to_anthropic(
    openai_body: &Value,
    model: &str,
    default_max_tokens: u64,
    prevalidated: bool,
) -> Result<Vec<u8>, String> {
    let messages = openai_body
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| "request missing 'messages' array".to_string())?;
    if !prevalidated {
        validate_anthropic_request_params(openai_body).map_err(|rejection| rejection.message)?;
        validate_anthropic_translation(openai_body, default_max_tokens)?;
    }

    let mut system_parts = Vec::new();
    for (message_index, message) in messages.iter().enumerate() {
        if !message["role"].as_str().is_some_and(is_system_role) {
            continue;
        }
        let text = anthropic_message_content_text(&message["content"])
            .map_err(|error| format!("messages[{message_index}] {error}"))?;
        if !text.is_empty() {
            system_parts.push(text);
        }
    }

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
        if role == "user" {
            if message["content"].is_null() {
                return Err(format!(
                    "messages[{message_index}] content must be a string or text-parts array"
                ));
            }
            let content = anthropic_user_content(&message["content"])
                .map_err(|error| format!("messages[{message_index}] {error}"))?;
            translated_messages.push(json!({
                "role": "user",
                "content": content,
            }));
            message_index += 1;
            continue;
        }

        let tool_calls = parse_openai_tool_calls(message, message_index)?;
        let legacy_call = parse_openai_function_call(message, message_index)?;
        let has_tool_representation = !tool_calls.is_empty() || legacy_call.is_some();
        let text = if message["content"].is_null() {
            if has_tool_representation {
                String::new()
            } else {
                return Err(format!(
                    "messages[{message_index}] content must be a string or text-parts array"
                ));
            }
        } else {
            anthropic_message_content_text(&message["content"])
                .map_err(|error| format!("messages[{message_index}] {error}"))?
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

    let max_tokens = anthropic_effective_max_tokens(openai_body, default_max_tokens)?;

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
    // OpenAI `parallel_tool_calls: false` is Anthropic
    // `tool_choice.disable_parallel_tool_use: true`. It only means something
    // when tools are callable: Anthropic's `none` choice takes no options, and
    // a choice without tools would be rejected by the provider.
    if openai_body.get("parallel_tool_calls") == Some(&Value::Bool(false))
        && body.get("tools").is_some()
        && !matches!(&tool_choice, Some((ToolChoiceKind::None, _)))
    {
        let mut choice = tool_choice
            .as_ref()
            .map(|(_, choice)| choice.clone())
            .unwrap_or_else(|| json!({ "type": "auto" }));
        choice["disable_parallel_tool_use"] = Value::Bool(true);
        body["tool_choice"] = choice;
    }
    if let Some(thinking) = resolve_anthropic_thinking(
        openai_body,
        tool_choice.as_ref().map(|(kind, _)| *kind),
        default_max_tokens,
    )? {
        body["thinking"] = thinking;
    }
    if let Some(effort) = resolve_anthropic_effort(openai_body)? {
        body["output_config"] = json!({ "effort": effort });
    }

    serde_json::to_vec(&body)
        .map_err(|error| format!("failed to serialize Anthropic body: {error}"))
}

/// Validate OpenAI shapes that Gemini translation must represent safely.
fn validate_gemini_translation(openai_body: &Value) -> Result<(), String> {
    let messages = openai_body
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| "request missing 'messages' array".to_string())?;
    let mut pending_legacy_by_name: HashMap<String, String> = HashMap::new();
    // Mirrors `translate_to_gemini`'s `tool_names_by_id`: a `tool` message can
    // only be represented as a `functionResponse` when a PRECEDING assistant
    // message declared the id. Admission must reject an orphaned id here, or the
    // translator rejects it later and the client gets the generic
    // "could not be translated safely" 400 instead of this precise diagnostic.
    let mut declared_tool_call_ids: HashSet<String> = HashSet::new();
    let mut message_index = 0;
    while message_index < messages.len() {
        let message = &messages[message_index];
        let role = message["role"].as_str().unwrap_or("");
        if is_system_role(role) {
            gemini_message_content_text(&message["content"])
                .map_err(|error| format!("messages[{message_index}] {error}"))?;
            message_index += 1;
            continue;
        }
        if role == "tool" {
            while message_index < messages.len()
                && messages[message_index]["role"].as_str() == Some("tool")
            {
                let tool_message = &messages[message_index];
                let tool_call_id = tool_message["tool_call_id"].as_str().ok_or_else(|| {
                    format!("messages[{message_index}] tool message missing tool_call_id")
                })?;
                if !declared_tool_call_ids.contains(tool_call_id) {
                    return Err(format!(
                        "messages[{message_index}] tool_call_id has no matching assistant tool call"
                    ));
                }
                tool_result_text(&tool_message["content"])
                    .map_err(|error| format!("messages[{message_index}] {error}"))?;
                message_index += 1;
            }
            continue;
        }
        if role == "function" {
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
                if pending_legacy_by_name.remove(name).is_none() {
                    return Err(format!(
                        "messages[{message_index}] function result has no unmatched preceding assistant function_call"
                    ));
                }
                tool_result_text(&function_message["content"])
                    .map_err(|error| format!("messages[{message_index}] {error}"))?;
                message_index += 1;
            }
            continue;
        }
        if role != "user" && role != "assistant" {
            return Err(format!(
                "messages[{message_index}] has unsupported role '{role}'"
            ));
        }
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
        if !tool_calls.is_empty() && legacy_call.is_some() {
            return Err(format!(
                "messages[{message_index}] mixes modern tool_calls with legacy function_call"
            ));
        }
        for call in &tool_calls {
            declared_tool_call_ids.insert(call.id.clone());
        }
        let had_legacy = legacy_call.is_some();
        if let Some(call) = legacy_call {
            pending_legacy_by_name.insert(call.name.clone(), call.id.clone());
        }
        for tool_index in 0..tool_calls.len() {
            openai_tool_call_thought_signature(message, message_index, tool_index)?;
        }
        let has_tool_representation = !tool_calls.is_empty() || had_legacy;
        if role == "user" {
            if message["content"].is_null() {
                return Err(format!(
                    "messages[{message_index}] content must be a string or text-parts array"
                ));
            }
            let parts = gemini_user_parts(&message["content"])
                .map_err(|error| format!("messages[{message_index}] {error}"))?;
            if parts.is_empty() {
                return Err(format!(
                    "messages[{message_index}] has no Gemini-representable content"
                ));
            }
            message_index += 1;
            continue;
        }
        // Null is fail-closed for system/developer/user. Assistant null/empty is
        // intentional only when a valid modern or legacy tool representation exists.
        let text = if message["content"].is_null() {
            if role == "assistant" && has_tool_representation {
                String::new()
            } else {
                return Err(format!(
                    "messages[{message_index}] content must be a string or text-parts array"
                ));
            }
        } else {
            gemini_message_content_text(&message["content"])
                .map_err(|error| format!("messages[{message_index}] {error}"))?
        };
        if role == "assistant" && text.is_empty() && !has_tool_representation {
            return Err(format!(
                "messages[{message_index}] has no Gemini-representable content"
            ));
        }
        if role == "user" && text.is_empty() {
            return Err(format!(
                "messages[{message_index}] has no Gemini-representable content"
            ));
        }
        message_index += 1;
    }
    if !pending_legacy_by_name.is_empty() {
        return Err("assistant function_call is missing its function result".to_string());
    }
    // Closed tools + tool_choice validation: never silently drop unsupported
    // declarations or weaken non-`none` choices without a tools array.
    let _ = gemini_declared_function_names(openai_body)?;
    let _ = resolve_gemini_tool_choice(openai_body)?;
    Ok(())
}

/// Closed Gemini-representable OpenAI `tools` declarations. Every entry must be
/// `{type:"function", function:{name:...}}` with a valid name; unsupported or
/// unrepresentable entries fail closed rather than being skipped.
fn gemini_declared_function_names(openai_body: &Value) -> Result<Option<Vec<&str>>, String> {
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
        if tool.get("type").and_then(Value::as_str) != Some("function") {
            return Err("unsupported or malformed tools".to_string());
        }
        let function = tool
            .get("function")
            .and_then(Value::as_object)
            .ok_or_else(|| "unsupported or malformed tools".to_string())?;
        let name = function
            .get("name")
            .and_then(Value::as_str)
            .filter(|value| valid_tool_name(value))
            .ok_or_else(|| "unsupported or malformed tools".to_string())?;
        names.push(name);
    }
    Ok(Some(names))
}

fn resolve_gemini_tool_choice(openai_body: &Value) -> Result<Option<Value>, String> {
    let Some(choice) = openai_body.get("tool_choice") else {
        return Ok(None);
    };
    if choice.is_null() {
        return Ok(None);
    }

    let (kind, translated) = match choice {
        Value::String(value) => match value.as_str() {
            "none" => (ToolChoiceKind::None, json!({ "mode": "NONE" })),
            "auto" => (ToolChoiceKind::Auto, json!({ "mode": "AUTO" })),
            "required" => (ToolChoiceKind::ForcedAny, json!({ "mode": "ANY" })),
            _ => return Err("unsupported or malformed tool_choice".to_string()),
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
                json!({
                    "mode": "ANY",
                    "allowedFunctionNames": [name],
                }),
            )
        }
        _ => return Err("unsupported or malformed tool_choice".to_string()),
    };

    let tools = gemini_declared_function_names(openai_body)?;
    if kind != ToolChoiceKind::None && tools.is_none() {
        return Err("tool_choice requires a non-empty tools array".to_string());
    }
    if kind == ToolChoiceKind::ForcedNamed {
        let name = translated
            .get("allowedFunctionNames")
            .and_then(Value::as_array)
            .and_then(|names| names.first())
            .and_then(Value::as_str)
            .ok_or_else(|| "unsupported or malformed tool_choice".to_string())?;
        if !tools.as_ref().is_some_and(|names| names.contains(&name)) {
            return Err("named tool_choice does not match any declared tool".to_string());
        }
    }

    Ok(Some(translated))
}

/// Map OpenAI Chat Completions into a Gemini/Vertex `generateContent` body.
/// The model is URL-scoped (`…/models/{model}:streamGenerateContent`), so it is
/// intentionally omitted from the JSON body.
///
/// `prevalidated` has the same meaning as for [`translate_to_anthropic`].
fn translate_to_gemini(openai_body: &Value, prevalidated: bool) -> Result<Vec<u8>, String> {
    let messages = openai_body
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| "request missing 'messages' array".to_string())?;
    if !prevalidated {
        validate_gemini_request_params(openai_body).map_err(|rejection| rejection.message)?;
        validate_gemini_translation(openai_body)?;
    }

    let mut system_parts = Vec::new();
    for (message_index, message) in messages.iter().enumerate() {
        if !message["role"].as_str().is_some_and(is_system_role) {
            continue;
        }
        let text = gemini_message_content_text(&message["content"])
            .map_err(|error| format!("messages[{message_index}] {error}"))?;
        if !text.is_empty() {
            system_parts.push(json!({ "text": text }));
        }
    }

    let mut tool_names_by_id: HashMap<String, String> = HashMap::new();
    let mut pending_legacy_by_name: HashMap<String, String> = HashMap::new();
    let mut contents = Vec::with_capacity(messages.len());
    let mut message_index = 0;
    while message_index < messages.len() {
        let message = &messages[message_index];
        let role = message["role"].as_str().unwrap_or("");
        if is_system_role(role) {
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
                    format!("messages[{message_index}] tool message missing tool_call_id")
                })?;
                let tool_name = tool_names_by_id.get(tool_call_id).ok_or_else(|| {
                    format!(
                        "messages[{message_index}] tool_call_id has no matching assistant tool call"
                    )
                })?;
                let text = tool_result_text(&tool_message["content"])
                    .map_err(|error| format!("messages[{message_index}] {error}"))?;
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
        if role == "function" {
            let mut parts = Vec::new();
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
                let _tool_use_id = pending_legacy_by_name.remove(name).ok_or_else(|| {
                    format!(
                        "messages[{message_index}] function result has no unmatched preceding assistant function_call"
                    )
                })?;
                let text = tool_result_text(&function_message["content"])
                    .map_err(|error| format!("messages[{message_index}] {error}"))?;
                let response = match serde_json::from_str::<Value>(&text) {
                    Ok(Value::Object(object)) => Value::Object(object),
                    Ok(value) => json!({ "output": value }),
                    Err(_) => json!({ "output": text }),
                };
                parts.push(json!({
                    "functionResponse": {
                        "name": name,
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
        if role == "user" {
            if message["content"].is_null() {
                return Err(format!(
                    "messages[{message_index}] content must be a string or text-parts array"
                ));
            }
            let parts = gemini_user_parts(&message["content"])
                .map_err(|error| format!("messages[{message_index}] {error}"))?;
            if parts.is_empty() {
                return Err(format!(
                    "messages[{message_index}] has no Gemini-representable content"
                ));
            }
            contents.push(json!({ "role": "user", "parts": parts }));
            message_index += 1;
            continue;
        }
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
        let has_tool_representation = !tool_calls.is_empty() || legacy_call.is_some();
        let text = if message["content"].is_null() {
            if role == "assistant" && has_tool_representation {
                String::new()
            } else {
                return Err(format!(
                    "messages[{message_index}] content must be a string or text-parts array"
                ));
            }
        } else {
            gemini_message_content_text(&message["content"])
                .map_err(|error| format!("messages[{message_index}] {error}"))?
        };
        let mut parts = Vec::new();
        if !text.is_empty() {
            parts.push(json!({ "text": text }));
        }
        for (tool_index, call) in tool_calls.into_iter().enumerate() {
            let thought_signature =
                openai_tool_call_thought_signature(message, message_index, tool_index)?;
            tool_names_by_id.insert(call.id.clone(), call.name.clone());
            let mut part = json!({
                "functionCall": {
                    "name": call.name,
                    "args": call.arguments,
                }
            });
            // Gemini 3 requires the signature it issued on a function-call part
            // to come back on that same part when the call's result is sent.
            if let Some(signature) = thought_signature {
                part["thoughtSignature"] = Value::String(signature);
            }
            parts.push(part);
        }
        if let Some(call) = legacy_call {
            pending_legacy_by_name.insert(call.name.clone(), call.id.clone());
            parts.push(json!({
                "functionCall": {
                    "name": call.name,
                    "args": call.arguments,
                }
            }));
        }
        if parts.is_empty() {
            return Err(format!(
                "messages[{message_index}] has no Gemini-representable content"
            ));
        }
        contents.push(json!({ "role": native_role, "parts": parts }));
        message_index += 1;
    }

    if !pending_legacy_by_name.is_empty() {
        return Err("assistant function_call is missing its function result".to_string());
    }

    let mut body = json!({ "contents": contents });
    if !system_parts.is_empty() {
        body["systemInstruction"] = json!({ "parts": system_parts });
    }

    let mut gen_config = serde_json::Map::new();
    if let Some(max_tokens) = openai_max_output_tokens(openai_body)? {
        gen_config.insert("maxOutputTokens".to_string(), json!(max_tokens));
    }
    if let Some(count) = openai_choice_count(openai_body).map_err(|rejection| rejection.message)? {
        gen_config.insert("candidateCount".to_string(), json!(count));
    }
    for (openai_field, gemini_field) in [
        ("presence_penalty", "presencePenalty"),
        ("frequency_penalty", "frequencyPenalty"),
        ("seed", "seed"),
    ] {
        if let Some(value) = present(openai_body, openai_field) {
            gen_config.insert(gemini_field.to_string(), value.clone());
        }
    }
    match openai_response_format(openai_body).map_err(|rejection| rejection.message)? {
        None => {}
        Some(ResponseFormat::JsonObject) => {
            gen_config.insert(
                "responseMimeType".to_string(),
                Value::String("application/json".to_string()),
            );
        }
        Some(ResponseFormat::JsonSchema { schema, .. }) => {
            gen_config.insert(
                "responseMimeType".to_string(),
                Value::String("application/json".to_string()),
            );
            gen_config.insert("responseJsonSchema".to_string(), schema.clone());
        }
    }
    if let Some(temp) = openai_body.get("temperature") {
        gen_config.insert("temperature".to_string(), temp.clone());
    }
    if let Some(top_p) = openai_body.get("top_p") {
        gen_config.insert("topP".to_string(), top_p.clone());
    }
    if let Some(stop) = openai_body.get("stop") {
        gen_config.insert("stopSequences".to_string(), normalize_stop_sequences(stop));
    }
    if !gen_config.is_empty() {
        body["generationConfig"] = Value::Object(gen_config);
    }

    if let Some(tools) = openai_body.get("tools")
        && !tools.is_null()
    {
        let tools = tools
            .as_array()
            .ok_or_else(|| "unsupported or malformed tools".to_string())?;
        if !tools.is_empty() {
            let mut declarations = Vec::with_capacity(tools.len());
            for tool in tools {
                if tool.get("type").and_then(Value::as_str) != Some("function") {
                    return Err("unsupported or malformed tools".to_string());
                }
                let function = tool
                    .get("function")
                    .and_then(Value::as_object)
                    .ok_or_else(|| "unsupported or malformed tools".to_string())?;
                let name = function
                    .get("name")
                    .and_then(Value::as_str)
                    .filter(|n| valid_tool_name(n))
                    .ok_or_else(|| "unsupported or malformed tools".to_string())?;
                let mut declaration = serde_json::Map::new();
                declaration.insert("name".to_string(), Value::String(name.to_string()));
                if let Some(description) = function.get("description").and_then(Value::as_str) {
                    declaration.insert(
                        "description".to_string(),
                        Value::String(description.to_string()),
                    );
                }
                if let Some(parameters) = function.get("parameters") {
                    declaration.insert("parameters".to_string(), parameters.clone());
                }
                declarations.push(Value::Object(declaration));
            }
            body["tools"] = json!([{ "functionDeclarations": declarations }]);
        }
    }
    if let Some(choice) = resolve_gemini_tool_choice(openai_body)? {
        body["toolConfig"] = json!({ "functionCallingConfig": choice });
    }

    serde_json::to_vec(&body).map_err(|error| format!("failed to serialize Gemini body: {error}"))
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
    let body = openai_error_body(message, error_type, param, code);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    PluginResult::Reject {
        status_code,
        body: body.to_string(),
        headers,
    }
}

/// Whether the live route override is still byte-for-byte the destination the
/// claim committed (`GHSA-xhp5-hqj8-3mwg`).
///
/// A visible host/port match is NOT sufficient. Three things decide where the
/// provider credential actually goes, and all three are compared here:
///
/// * the visible destination (scheme / host / port / authority / absolute path),
/// * the routing identity — `route_override_upstream_id` must still be clear,
///   because an upstream override hands target selection to a load balancer
///   that can dial an address this claim never approved,
/// * the resolved backend TLS — exact equality over verification, SNI, CA, and
///   the mTLS client identity, so a later plugin cannot keep the same visible
///   host while disabling verification, retargeting SNI, or attaching Ferrum's
///   own client certificate to a third-party connection. `None` (plaintext) is a
///   distinct committed state, not "unset".
///
/// The committed dispatch budgets are compared for the same reason: a claim that
/// pinned a provider's own connect / whole-exchange timeouts must not be
/// dispatched under a different budget than the one it was approved with, and an
/// inherited (`None`) commitment must stay inherited.
///
/// The claim is a private typed struct, not serialized metadata, so none of
/// these values can be forged by a plugin that can only write metadata.
fn route_override_still_targets(ctx: &RequestContext, claim: &AiStreamRouterClaim) -> bool {
    ctx.route_override_upstream_id.is_none()
        && ctx.route_override_backend_scheme == Some(claim.scheme)
        && ctx.route_override_backend_port == Some(claim.port)
        && ctx.route_override_path_is_absolute
        && ctx.route_override_dns_policy == super::RouteOverrideDnsPolicy::ClearInherited
        && ctx.route_override_backend_host.as_deref() == Some(claim.host.as_str())
        && ctx.route_override_authority.as_deref() == Some(claim.authority.as_str())
        && ctx.route_override_path.as_deref() == Some(claim.path.as_str())
        && ctx.route_override_resolved_tls == claim.resolved_tls
        && ctx.route_override_backend_connect_timeout_ms == claim.committed_connect_timeout_ms
        && ctx.route_override_backend_read_timeout_ms == claim.committed_read_timeout_ms
}

/// Fail-closed envelope for a broken provider-boundary invariant. Fixed
/// cardinality: never echoes a model, header, or body value.
fn provider_policy_violation(message: &str) -> PluginResult {
    openai_error_response(
        500,
        message,
        "api_error",
        None,
        Some("provider_policy_violation"),
    )
}

/// Fail-closed envelope for a final provider-visible model that no longer
/// satisfies the policy that selected the provider.
fn model_policy_violation(message: &str) -> PluginResult {
    openai_error_response(
        400,
        message,
        "invalid_request_error",
        Some("model"),
        Some("model_policy_violation"),
    )
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

    fn lifecycle_hooks(&self) -> crate::plugins::PluginHooks {
        crate::plugins::PluginHooks::BEFORE_PROXY | crate::plugins::PluginHooks::AFTER_PROXY
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
        // Once any router instance has claimed the request, its final model and
        // destination policy must run with RequestContext even if a later
        // header transformer temporarily relabels the body as non-JSON. The
        // final backend-header policy restores the provider's JSON contract,
        // so allowing the mutable Content-Type to suppress buffering/context
        // here would skip the claim owner's final revalidation.
        ctx.has_ai_stream_router_claim()
            || ctx
                .headers
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
        // First claim wins (`GHSA-xhp5-hqj8-3mwg`). Multiple same-type instances
        // are allowed, and two of them can match the same request. A second
        // claim would reapply a different credential, repoint the destination
        // under the first instance's already-installed key, translate the body
        // twice, and install a second response normalizer. Yielding silently
        // (rather than rejecting) also keeps `fail_on_missing_model` /
        // `fail_on_no_matching_provider` meaningful: those decide an UNCLAIMED
        // request in normal plugin order, and ownership only begins once some
        // instance has actually claimed.
        if ctx.ai_stream_router_claim.is_some() {
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
        let Some((provider_index, provider)) = self.select_provider(&model) else {
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

        // Fail closed on OpenAI request parameters the selected provider can
        // neither map exactly nor honor (instead of silently dropping them),
        // before the route override commits.
        let param_rejection = match provider.provider_type {
            ProviderType::Anthropic => validate_anthropic_request_params(&openai_body).err(),
            ProviderType::GoogleGemini => validate_gemini_request_params(&openai_body).err(),
            ProviderType::OpenAi | ProviderType::OpenAiCompatible | ProviderType::AzureOpenAi => {
                None
            }
        };
        if let Some(rejection) = param_rejection {
            let provider_label = if provider.provider_type == ProviderType::Anthropic {
                "Anthropic"
            } else {
                "Gemini"
            };
            return openai_error_response(
                400,
                &format!(
                    "Invalid request for {provider_label} translation: {}",
                    rejection.message
                ),
                "invalid_request_error",
                Some(rejection.param),
                Some(rejection.code),
            );
        }

        // Fail closed on Anthropic / Gemini tool-history / tool_choice shapes
        // that cannot be represented safely before the route override commits.
        if provider.provider_type == ProviderType::Anthropic
            && let Err(message) =
                validate_anthropic_translation(&openai_body, provider.anthropic_default_max_tokens)
        {
            let (param, code) = if message.contains("thinking") {
                (Some("thinking"), Some("invalid_thinking"))
            } else if message.contains("reasoning_effort") {
                (Some("reasoning_effort"), Some("invalid_reasoning_effort"))
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
        if provider.provider_type == ProviderType::GoogleGemini
            && let Err(message) = validate_gemini_translation(&openai_body)
        {
            let (param, code) = if message.contains("tool_choice") || message.contains("tools") {
                (Some("tool_choice"), Some("invalid_tool_choice"))
            } else {
                (Some("messages"), Some("invalid_messages"))
            };
            return openai_error_response(
                400,
                &format!("Invalid request for Gemini translation: {message}"),
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
        // The exact backend-visible query the dispatch layer may append to the
        // committed target, frozen HERE and re-asserted at every later capture
        // point (`GHSA-xhp5-hqj8-3mwg`). `request_transformer` runs at 3000 —
        // after this claim — and its query rules could otherwise append a
        // normal-backend static secret to the third-party provider URL.
        //
        // Two cases, both preserving the pre-existing semantics:
        //  * an endpoint query is folded into the absolute override path below,
        //    and every client pair is marked consumed, so the separately
        //    appended query is committed EMPTY;
        //  * otherwise the already-safe client query continues — the canonical
        //    backend-visible query as of this moment, which is the raw wire
        //    query (or an earlier plugin's published outbound query) after the
        //    authentication-owned strip markers.
        let mut committed_query = if provider.endpoint_query.is_some() {
            String::new()
        } else {
            crate::proxy::effective_backend_query_string(ctx).into_owned()
        };

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

        // Gemini/Vertex streamGenerateContent is normalized from SSE or a
        // Vertex-compatible JSON object stream. Prefer `alt=sse` so native
        // Gemini uses the documented SSE framing; operators may already have
        // it on the endpoint.
        if provider.provider_type == ProviderType::GoogleGemini
            && provider.normalizes_response(self.normalize_response_stream)
        {
            ensure_gemini_alt_sse(&mut backend_path, &mut committed_query);
        }

        // --- Rewrite the routing decision (no internal HTTP call). ---
        ctx.route_override_backend_scheme = Some(provider.scheme);
        ctx.route_override_backend_host = Some(provider.host.clone());
        ctx.route_override_backend_port = Some(provider.port);
        ctx.route_override_path = Some(backend_path.clone());
        ctx.route_override_path_is_absolute = true;
        ctx.route_override_authority = Some(provider.authority.clone());
        // This claim commits a DIRECT provider endpoint, never an upstream /
        // load-balancer identity. Clear any upstream override an earlier plugin
        // set: leaving one in place would let a load balancer choose the actual
        // dial target while this plugin's provider credential is installed, and
        // the final boundary requires it to still be clear
        // (`GHSA-xhp5-hqj8-3mwg`).
        ctx.route_override_upstream_id = None;
        // The provider host must resolve through provider DNS. A `dns_override`
        // on the selected proxy pins a fixed address, and the generic
        // "host text changed" rule does not clear it when the configured proxy
        // host happens to equal the provider host — exactly the case where the
        // destination identity changed but the text did not.
        ctx.route_override_dns_policy = super::RouteOverrideDnsPolicy::ClearInherited;
        // Default: public providers verify against the system trust store.
        // `inherit_backend_tls: true` carries the current proxy's resolved
        // backend TLS (custom CA / SNI policy / backend mTLS client cert) to
        // internal openai_compatible endpoints, including TLS inherited from an
        // upstream selected before this provider override.
        if provider.scheme == BackendScheme::Https {
            ctx.route_override_resolved_tls = if provider.inherit_backend_tls {
                ctx.matched_proxy
                    .as_ref()
                    .map(|proxy| Arc::new(proxy.resolved_tls.clone()))
            } else {
                // Not `default_verify()`: its unset CA / client fields are
                // filled from gateway-global settings by the backend TLS
                // builder (a private `FERRUM_TLS_CA_BUNDLE_PATH`,
                // `FERRUM_TLS_NO_VERIFY`, and the global backend client
                // certificate). A third-party provider gets public roots only,
                // verification that no global opt-out can disable, and no
                // gateway client identity.
                Some(Arc::new(BackendTlsConfig::isolated_public_verify()))
            };
        } else {
            // Plaintext HTTP provider: no committed TLS configuration at all.
            // Pinned explicitly so the witness below cannot be satisfied by a
            // later plugin ADDING one (which would change SNI/verification for
            // a destination this claim never negotiated TLS with).
            ctx.route_override_resolved_tls = None;
        }

        // --- Rewrite headers: strip client credentials, insert provider auth. ---
        // This is the FIRST application of the owned header set. It is not the
        // decisive one: `enforce_final_backend_header_policy` re-applies exactly
        // the same policy over the finalized backend-visible map after every
        // later generic header transform (`GHSA-xhp5-hqj8-3mwg`).
        let normalizes = provider.normalizes_response(self.normalize_response_stream);
        apply_provider_boundary_headers(ctx, provider, normalizes, headers);

        // --- Private claim: the complete witness of what was committed. ---
        // Everything the credential boundary depends on lives here, in typed
        // request-private state, and nowhere in public metadata: the owning
        // instance, the provider it selected, the MODEL that selected it, the
        // destination identity, the resolved backend TLS, and the
        // backend-visible query (`GHSA-xhp5-hqj8-3mwg`).
        // `on_final_request_body_with_context` requires every one of them to be
        // unchanged before the request is dispatched.
        let committed_tls = ctx.route_override_resolved_tls.clone();
        // Committed from the CLIENT representation this claim selected on, not
        // from the later translated body: the response normalizer's fail-closed
        // tool-use guard must be armed by what the request actually asked for
        // and must not be disarmable afterwards. Only meaningful for the
        // provider type whose SSE this instance translates.
        let tool_choice_none = matches!(
            provider.provider_type,
            ProviderType::Anthropic | ProviderType::GoogleGemini
        ) && openai_body.get("tool_choice").and_then(Value::as_str)
            == Some("none");
        // Hand the parsed, validated client body to this claim's own transform
        // so it is not parsed and validated a second time. The fingerprint is
        // taken over the exact bytes parsed above; the transform reuses the
        // value only when its body is still those bytes.
        let client_body_memo = if matches!(
            provider.provider_type,
            ProviderType::Anthropic | ProviderType::GoogleGemini
        ) {
            ctx.metadata.get("request_body").map(|raw| {
                Arc::new(ClientBodyMemo {
                    len: raw.len(),
                    fingerprint: body_fingerprint(raw.as_bytes()),
                    value: openai_body,
                })
            })
        } else {
            None
        };
        ctx.ai_stream_router_claim = Some(Box::new(AiStreamRouterClaim {
            owner: self.owner_id,
            provider_index,
            model: model.clone(),
            tool_choice_none,
            // The transform hook has not run yet; it sets this on the same
            // context the final body hook reads.
            request_translated: false,
            scheme: provider.scheme,
            host: provider.host.clone(),
            port: provider.port,
            path: backend_path,
            authority: provider.authority.clone(),
            resolved_tls: committed_tls,
            committed_query,
            // This plugin never overrides the matched proxy's dispatch budgets,
            // so the witness pins "inherited" and a later plugin cannot install
            // one without breaking the destination check.
            committed_connect_timeout_ms: ctx.route_override_backend_connect_timeout_ms,
            committed_read_timeout_ms: ctx.route_override_backend_read_timeout_ms,
            // No external capacity is reserved for an `ai_stream_router` claim.
            lifecycle: None,
            client_body_memo,
            translated_body_fingerprint: None,
        }));

        // --- Metadata (observability + downstream-hook coordination ONLY). ---
        // Nothing below is read back for an authorization or policy decision:
        // a later plugin can write any of these keys, so every enforcement
        // point reads the private claim instead (`GHSA-xhp5-hqj8-3mwg`).
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
        // gateway-asserted `x-consumer-*` identity headers after the credential
        // strip above (see the suppression contract on
        // `RequestContext::backend_consumer_username`). The final header policy
        // additionally strips any that a later generic rule reintroduced.
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
        // Observability only: the decisive copy is `claim.model` above.
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
        // Only the instance that won the claim transforms the body. A second
        // instance running this hook would translate an already-translated
        // representation, or re-inject usage options into another provider's
        // body (`GHSA-xhp5-hqj8-3mwg`). The model comes from the private claim,
        // never from `ai_stream_router.model`: this hook runs at 2984 but a
        // later plugin's metadata write must not be able to decide which
        // generation the provider request is translated for.
        let (provider_type, model, default_max_tokens) = {
            let (claim, provider) = self.owned_claim(ctx)?;
            (
                provider.provider_type,
                claim.model.clone(),
                provider.anthropic_default_max_tokens,
            )
        };

        match provider_type {
            ProviderType::Anthropic | ProviderType::GoogleGemini => {
                // Reuse the claim's parsed, validated client body only when this
                // transform sees exactly the bytes the claim parsed; otherwise
                // parse and validate afresh.
                let memo = ctx
                    .ai_stream_router_claim
                    .as_deref_mut()
                    .and_then(|claim| claim.client_body_memo.take())
                    .filter(|memo| {
                        body_matches_fingerprint(body, Some((memo.len, memo.fingerprint)))
                    });
                let reparsed;
                let (openai_body, prevalidated) = match memo.as_deref() {
                    Some(memo) => (&memo.value, true),
                    None => {
                        reparsed = serde_json::from_slice::<Value>(body).ok()?;
                        (&reparsed, false)
                    }
                };
                let translated = if provider_type == ProviderType::Anthropic {
                    translate_to_anthropic(openai_body, &model, default_max_tokens, prevalidated)
                        .ok()?
                } else {
                    translate_to_gemini(openai_body, prevalidated).ok()?
                };
                let tool_choice_none =
                    openai_body.get("tool_choice").and_then(Value::as_str) == Some("none");
                // The decisive witness: private claim state on the very context
                // `on_final_request_body_with_context` reads.
                if let Some(claim) = ctx.ai_stream_router_claim.as_deref_mut() {
                    claim.request_translated = true;
                    claim.translated_body_fingerprint =
                        Some((translated.len(), body_fingerprint(&translated)));
                }
                ctx.metadata
                    .insert(META_REQUEST_TRANSLATED.to_string(), "true".to_string());
                if tool_choice_none {
                    ctx.metadata
                        .insert(META_TOOL_CHOICE_NONE.to_string(), "true".to_string());
                } else {
                    ctx.metadata.remove(META_TOOL_CHOICE_NONE);
                }
                Some(translated)
            }
            ProviderType::OpenAi | ProviderType::OpenAiCompatible | ProviderType::AzureOpenAi => {
                if self.inject_usage_options {
                    inject_include_usage(body)
                } else {
                    None
                }
            }
        }
    }

    fn enforces_final_backend_header_policy(&self) -> bool {
        self.enabled
    }

    /// Re-assert the provider credential boundary over the FINAL backend-visible
    /// header map (`GHSA-xhp5-hqj8-3mwg`).
    ///
    /// `before_proxy` already applied this policy, but a later generic header
    /// rule (`request_transformer` at 3000), a deferred routing-header hook, or
    /// a `pre_proxy` function's backend overlay can add/overwrite/rename the
    /// credential afterwards. The gateway calls this at every point where the
    /// outbound header map is complete, so the last word is always this policy
    /// rather than whichever plugin happened to run last.
    ///
    /// Ownership is decided by the private claim, never by the public
    /// `ai_stream_router.provider` metadata key: two instances may carry the
    /// same provider NAME with different endpoints and different keys, so a
    /// name match would let the losing instance install the wrong credential.
    fn enforce_final_backend_header_policy(
        &self,
        ctx: &RequestContext,
        headers: &mut HashMap<String, String>,
    ) {
        let Some((_, provider)) = self.owned_claim(ctx) else {
            return;
        };
        let normalizes = provider.normalizes_response(self.normalize_response_stream);
        apply_provider_boundary_headers(ctx, provider, normalizes, headers);
    }

    /// Revalidate the FINAL provider-visible body and route against the policy
    /// that selected the provider (`GHSA-xhp5-hqj8-3mwg`).
    ///
    /// Runs after every `transform_request_body` hook, so `body` is exactly what
    /// the provider would receive. Every failure is fail-closed and carries a
    /// fixed-cardinality message: the offending model, header, or body bytes are
    /// never echoed back or logged, because a later transform could have placed
    /// a secret there.
    async fn on_final_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        _headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Ownership and the destination witness both come from the private
        // claim. Read them in one scope so the shared duplicate-key memo below
        // can still take the context mutably.
        let (
            provider_index,
            provider_is_anthropic,
            provider_is_gemini,
            destination_intact,
            committed_model,
            request_translated,
            translated_body_fingerprint,
        ) = {
            // Not this instance's claim — either the request was never claimed,
            // or a second effective `ai_stream_router` owns it and runs the
            // identical revalidation from this same phase.
            let Some((claim, provider)) = self.owned_claim(ctx) else {
                return PluginResult::Continue;
            };
            (
                claim.provider_index,
                provider.provider_type == ProviderType::Anthropic,
                provider.provider_type == ProviderType::GoogleGemini,
                route_override_still_targets(ctx, claim),
                claim.model.clone(),
                claim.request_translated,
                claim.translated_body_fingerprint,
            )
        };

        if provider_is_anthropic && !request_translated {
            return openai_error_response(
                400,
                "The Anthropic request body could not be translated safely",
                "invalid_request_error",
                Some("messages"),
                Some("invalid_messages"),
            );
        }
        if provider_is_gemini && !request_translated {
            return openai_error_response(
                400,
                "The Gemini request body could not be translated safely",
                "invalid_request_error",
                Some("messages"),
                Some("invalid_messages"),
            );
        }

        // The credential installed at the boundary is only safe if it is still
        // going to the destination that claimed it — same visible endpoint, no
        // upstream/load-balancer identity, byte-identical backend TLS, and the
        // provider-DNS decision intact. The backend-visible QUERY needs no check
        // here: it is not read from the context at dispatch but re-asserted from
        // the claim at the single capture funnel
        // (`crate::proxy::effective_backend_query_string*`), which every
        // dispatcher and every retry attempt goes through.
        if !destination_intact {
            return provider_policy_violation(
                "The routed AI provider destination changed after provider selection",
            );
        }

        // Still exactly the bytes this instance's own translator produced: the
        // translator wrote the committed model (Anthropic) or a URL-scoped body
        // with `contents` (Gemini), and serialized it from a `Value`, so it has
        // no duplicate members. Only the policy re-check remains; any later
        // body transform changes the bytes and takes the full path below.
        if (provider_is_anthropic || provider_is_gemini)
            && body_matches_fingerprint(body, translated_body_fingerprint)
        {
            return match self.providers.get(provider_index) {
                Some(provider) if provider.matches_model(&committed_model) => {
                    PluginResult::Continue
                }
                Some(_) => model_policy_violation(
                    "The final AI provider request model does not match the routed model policy",
                ),
                None => provider_policy_violation(
                    "The routed AI provider could not be revalidated before dispatch",
                ),
            };
        }

        // A duplicate `model` member makes the provider-visible generation
        // parser-dependent: `serde_json` keeps the last occurrence while a
        // first-wins provider parser would read the other one, so an equality
        // check against either value proves nothing. Screen with the shared
        // bounded scanner (memoized per request body) before parsing.
        if ctx.json_scan_memo.ambiguity(body).is_some() {
            return model_policy_violation(
                "The final AI provider request body has ambiguous duplicate JSON members",
            );
        }

        // `committed_model` is the private claim's copy, taken above. The public
        // `ai_stream_router.model` key is deliberately NOT consulted here
        // (`GHSA-xhp5-hqj8-3mwg`): a later plugin can rewrite the final body's
        // model AND that key to the same new value, which would satisfy an
        // equality check against metadata while bypassing the selection that
        // chose this provider.
        //
        // Recorded by this same instance at claim time, so the lookup cannot
        // miss; fail closed rather than indexing.
        let Some(provider) = self.providers.get(provider_index) else {
            return provider_policy_violation(
                "The routed AI provider could not be revalidated before dispatch",
            );
        };

        // The router committed a JSON provider contract; anything else at this
        // point means a later transform reshaped the backend-visible body.
        let Ok(final_body) = serde_json::from_slice::<Value>(body) else {
            return model_policy_violation(
                "The final AI provider request body is not valid JSON after request transforms",
            );
        };

        if provider_is_gemini {
            // Gemini/Vertex generateContent bodies are URL-scoped for the model
            // (`…/models/{model}:streamGenerateContent`). Destination integrity
            // already pins the path that embeds `committed_model`; here require
            // a Gemini-shaped body and that the committed model still matches
            // this provider's patterns.
            match final_body.get("contents") {
                Some(Value::Array(_)) => {}
                _ => {
                    return model_policy_violation(
                        "The final Gemini provider request body has no usable 'contents' field",
                    );
                }
            }
            if !provider.matches_model(&committed_model) {
                return model_policy_violation(
                    "The final AI provider request model does not match the routed model policy",
                );
            }
            return PluginResult::Continue;
        }

        let final_model = match final_body.get("model") {
            Some(Value::String(model)) if !model.is_empty() => model.as_str(),
            _ => {
                return model_policy_violation(
                    "The final AI provider request body has no usable 'model' field",
                );
            }
        };
        // Equality pins the exact generation that was priced, allowed, and (for
        // `{model}` endpoints) baked into the backend URL; the pattern re-check
        // proves the surviving value is still inside this provider's configured
        // policy rather than merely unchanged.
        if final_model != committed_model || !provider.matches_model(final_model) {
            return model_policy_violation(
                "The final AI provider request model does not match the routed model policy",
            );
        }

        PluginResult::Continue
    }

    fn forces_reqwest_dispatch(&self, ctx: &RequestContext) -> bool {
        // Force the reqwest streaming path only for requests THIS instance
        // claimed and whose SSE it will normalize, so the response-stream
        // inspector is guaranteed to be wired. Requests we pass through
        // unchanged stay on the fast path.
        self.response_stream_hooks && self.normalizes_owned_response(ctx)
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
        // Ownership, not the public `normalized_response_stream` marker: two
        // instances can disagree on `normalize_response_stream` and on provider
        // type, and only the winner's decision may install a normalizer
        // (`GHSA-xhp5-hqj8-3mwg`). Double normalization would re-parse already
        // OpenAI-shaped SSE as if it were provider-native.
        //
        // The same lookup yields the generation identity this normalizer stamps
        // into every client-visible chunk and the fail-closed `tool_use` guard,
        // both from the private claim rather than from the forgeable
        // `ai_stream_router.model` / `ai_stream_router.tool_choice_none` keys.
        let (model, tools_forbidden, provider_type) = {
            let (claim, provider) = self.owned_claim(ctx)?;
            if !provider.normalizes_response(self.normalize_response_stream) {
                return None;
            }
            (
                claim.model.clone(),
                claim.tool_choice_none,
                provider.provider_type,
            )
        };
        // Only normalize a successful event stream; a non-2xx body is an
        // error envelope that should reach the client untouched.
        if !(200..300).contains(&response_status) {
            return None;
        }
        match classify_provider_stream_media(provider_type, content_type) {
            ProviderStreamMediaDecision::Normalize => {}
            ProviderStreamMediaDecision::PassThrough => return None,
            decision => {
                let message = provider_stream_media_fail_closed_message(decision)
                    .unwrap_or(
                        "upstream provider returned a successful response unsuitable for stream normalization",
                    );
                return Some(Box::new(ImmediateUpstreamErrorNormalizer::new(
                    message.to_string(),
                )));
            }
        }
        let encoding = ctx.metadata.get(META_PROVIDER_ENCODING).cloned();
        Some(wrap_provider_normalizer(
            provider_type,
            model,
            encoding,
            tools_forbidden,
            self.normalize_limits,
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
        // Same private-claim read as the streaming inspector: ownership plus the
        // committed generation identity and tool-use guard
        // (`GHSA-xhp5-hqj8-3mwg`). Scoped so the claim borrow ends before the
        // buffered normalization await.
        let (model, tools_forbidden, provider_type) = {
            let (claim, provider) = self.owned_claim(ctx)?;
            if !provider.normalizes_response(self.normalize_response_stream) {
                return None;
            }
            (
                claim.model.clone(),
                claim.tool_choice_none,
                provider.provider_type,
            )
        };
        // Match the streaming normalizer: provider error envelopes reach the
        // client untouched even when a backend labels them as event streams.
        if !(200..300).contains(&response_status) {
            return None;
        }
        match classify_provider_stream_media(provider_type, content_type) {
            ProviderStreamMediaDecision::Normalize => {}
            ProviderStreamMediaDecision::PassThrough => return None,
            decision => {
                let message = provider_stream_media_fail_closed_message(decision)
                    .unwrap_or(
                        "upstream provider returned a successful response unsuitable for stream normalization",
                    );
                let ceiling = ctx.retained_response_body_ceiling();
                return Some(bounded_upstream_sse_error_body(message, ceiling));
            }
        }
        // Every replacement this normalizer produces is materialised inside a
        // sink bounded by this response's retained ceiling — the same size as
        // the window the phase reserved before invoking it
        // (GHSA-pwcm-6rh8-f2gh). Claim-owned model/tools_forbidden above stay
        // authoritative (`GHSA-xhp5-hqj8-3mwg`); do not re-read them from
        // mutable metadata.
        let ceiling = ctx.retained_response_body_ceiling();
        // Classify residual encoding with the same fixed-cardinality reasons
        // `after_proxy` uses. Never feed raw header/metadata strings into the
        // client-facing decode error envelope.
        let encoding = match ctx.metadata.get(META_PROVIDER_ENCODING) {
            Some(meta) => {
                let mut probe = HashMap::with_capacity(1);
                probe.insert("content-encoding".to_string(), meta.clone());
                match classify_provider_content_encoding(&probe) {
                    ProviderContentEncoding::Supported(coding) => Some(coding),
                    ProviderContentEncoding::Identity => None,
                    ProviderContentEncoding::Unsupported(reason) => {
                        return Some(bounded_upstream_sse_error_body(reason.as_str(), ceiling));
                    }
                }
            }
            None => match classify_provider_content_encoding(response_headers) {
                ProviderContentEncoding::Supported(coding) => Some(coding),
                ProviderContentEncoding::Identity => None,
                ProviderContentEncoding::Unsupported(reason) => {
                    return Some(bounded_upstream_sse_error_body(reason.as_str(), ceiling));
                }
            },
        };
        let plaintext = match prepare_sse_bytes_for_normalization(body, encoding.as_deref()) {
            Ok(bytes) => bytes,
            Err(message) => {
                return Some(bounded_upstream_sse_error_body(
                    safe_residual_decode_diagnostic(&message),
                    ceiling,
                ));
            }
        };
        // Always a replacement once media classification chose normalization:
        // `None` would leave the RAW provider body (provider-native framing,
        // and possibly a tool call the claim forbids) in place under the
        // already-repaired OpenAI representation headers.
        Some(
            normalize_provider_stream_buffered(
                provider_type,
                model,
                &plaintext,
                tools_forbidden,
                ceiling,
                self.normalize_limits,
            )
            .await,
        )
    }

    /// Bind every field normalized provider SSE invalidates.
    ///
    /// When this plugin rewrites provider SSE into OpenAI-shaped identity bytes,
    /// `repair_normalized_representation_headers` removes `content-encoding` and
    /// `content-length`, runs
    /// [`super::invalidate_content_bound_response_headers`] (validators, digests,
    /// signatures, and the open-ended `x-amz-checksum-*` / `x-checksum-*`
    /// families), and scrubs or rewrites `vary`; for a non-SSE provider framing
    /// such as the Gemini JSON-array fallback,
    /// [`stamp_normalized_sse_content_type`] additionally relabels
    /// `content-type`. A trailer-only copy of any of
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
        if !self.normalizes_owned_response(ctx) {
            return PluginResult::Continue;
        }
        if !(200..300).contains(&response_status) {
            return PluginResult::Continue;
        }
        let content_type = response_headers.get("content-type").map(String::as_str);
        let provider_type = match self.owned_claim(ctx) {
            Some((_, provider)) => provider.provider_type,
            None => return PluginResult::Continue,
        };
        match classify_provider_stream_media(provider_type, content_type) {
            ProviderStreamMediaDecision::Normalize => {}
            ProviderStreamMediaDecision::PassThrough => return PluginResult::Continue,
            decision => {
                let message = provider_stream_media_fail_closed_message(decision).unwrap_or(
                    "Upstream provider returned a successful response unsuitable for stream normalization",
                );
                return openai_error_response(
                    502,
                    message,
                    "upstream_error",
                    None,
                    Some("unsupported_content_type"),
                );
            }
        }

        match classify_provider_content_encoding(response_headers) {
            ProviderContentEncoding::Identity => {
                repair_normalized_representation_headers(response_headers);
                stamp_normalized_sse_content_type(response_headers);
                PluginResult::Continue
            }
            ProviderContentEncoding::Supported(coding) => {
                ctx.metadata
                    .insert(META_PROVIDER_ENCODING.to_string(), coding);
                repair_normalized_representation_headers(response_headers);
                stamp_normalized_sse_content_type(response_headers);
                PluginResult::Continue
            }
            ProviderContentEncoding::Unsupported(reason) => openai_error_response(
                502,
                reason.as_str(),
                "upstream_error",
                None,
                Some("unsupported_content_encoding"),
            ),
        }
    }
}

/// Provider-protocol request headers a client must not be able to set toward a
/// third-party provider (they select provider API behavior or bill a provider
/// organization). The selected provider's own values are re-installed.
const PROVIDER_PROTOCOL_HEADERS: &[&str] = &[
    "anthropic-version",
    "anthropic-beta",
    "openai-beta",
    "openai-organization",
    "openai-project",
];

/// Header-name equality that ignores ASCII case and treats `_` as `-`.
///
/// `_` is a legal header-name byte, and CGI-style stacks and several provider
/// front ends fold `x_api_key` onto `x-api-key`, so an underscore spelling of a
/// credential name is the same credential.
fn header_name_matches_folded(name: &str, candidate: &str) -> bool {
    name.len() == candidate.len()
        && name.bytes().zip(candidate.bytes()).all(|(left, right)| {
            let fold = |byte: u8| {
                if byte == b'_' {
                    b'-'
                } else {
                    byte.to_ascii_lowercase()
                }
            };
            fold(left) == fold(right)
        })
}

/// Strip client-supplied credential headers so they never leak to the provider.
///
/// Unlike `ai_federation` (which builds a fresh provider request), this
/// route-override path forwards the client's own header map, so every header
/// Ferrum classifies as a credential — the canonical
/// [`CREDENTIAL_CONTEXT_HEADERS`] set shared with replay partitioning
/// (`authorization`, `proxy-authorization`, `cookie`, `x-api-key`, `api-key`,
/// `apikey`, `x-goog-api-key`, `x-access-token`, `x-auth-token`,
/// `x-amz-security-token`, `x-forwarded-authorization`) — plus the
/// provider-protocol headers are removed, in any case and with `_` spelled as
/// `-`. A hand-maintained subset here previously let `x-auth-token` or an AWS
/// session token reach the third party.
pub(crate) fn strip_client_credentials(headers: &mut HashMap<String, String>) {
    // This runs on every final-policy pass (once per `before_proxy` pass, per
    // deferred routing pass, per egress overlay, and per retry attempt), so
    // compare in place rather than allocating a folded copy of every name.
    headers.retain(|name, _| {
        !CREDENTIAL_CONTEXT_HEADERS
            .iter()
            .chain(PROVIDER_PROTOCOL_HEADERS)
            .any(|candidate| header_name_matches_folded(name, candidate))
    });
}

/// Strip the route's own custom credential locations — the JWT/JWKS, OAuth,
/// and API-key header names this proxy's authentication plugins read
/// (`RequestContext::request_headers_requiring_redaction`). A credential a
/// client presented to Ferrum is never a provider credential.
fn strip_route_credential_locations(ctx: &RequestContext, headers: &mut HashMap<String, String>) {
    let locations = ctx.request_headers_requiring_redaction();
    if locations.is_empty() {
        return;
    }
    headers.retain(|name, _| {
        !locations
            .iter()
            .any(|location| header_name_matches_folded(name, location))
    });
}

/// Gateway-asserted consumer/geo identity must never cross a third-party
/// provider boundary. `before_proxy` sets
/// `SUPPRESS_CONSUMER_IDENTITY_HEADERS_KEY` so proxy core stops
/// appending them; this strip additionally removes any value a later generic
/// header rule reintroduced (`GHSA-xhp5-hqj8-3mwg`). It covers the whole
/// gateway-owned `x-consumer-*` namespace, not only the two identity fields.
pub(crate) fn strip_gateway_identity_assertions(headers: &mut HashMap<String, String>) {
    headers.retain(|name, _| !crate::proxy::headers::is_gateway_assertion_header(name));
}

/// The complete set of request headers this plugin owns at the provider
/// boundary.
///
/// Applied twice by design: once when `before_proxy` claims the request, and
/// again over the FINAL backend-visible header map
/// (`enforce_final_backend_header_policy`) after every later generic header
/// transform. It is idempotent, allocation-light, and never logs a value.
///
/// The owned set is closed: every canonical credential / session header and
/// provider-protocol header ([`strip_client_credentials`], case- and
/// `_`/`-`-insensitive), this route's own custom credential locations
/// ([`strip_route_credential_locations`]), the gateway's own consumer / geo
/// assertions ([`strip_gateway_identity_assertions`]), and the provider
/// protocol headers installed below (`host`, `content-type`, `accept`, the
/// provider credential header, `anthropic-version`, and `accept-encoding` when
/// normalizing).
///
/// Headers outside that set are left untouched, so intended non-credential
/// operator transforms still reach the provider. This is a deliberate limit, not
/// an omission: Ferrum cannot decide that an arbitrary unknown custom header
/// carries a secret, so a bespoke normal-backend credential header that is
/// neither a canonical credential name nor a configured authentication location
/// WILL still be forwarded. Do not configure such a rule on a proxy that routes
/// to a third-party provider.
fn apply_provider_boundary_headers(
    ctx: &RequestContext,
    provider: &StreamProvider,
    normalizes_response: bool,
    headers: &mut HashMap<String, String>,
) {
    strip_client_credentials(headers);
    strip_route_credential_locations(ctx, headers);
    strip_gateway_identity_assertions(headers);
    match &provider.auth {
        ProviderAuth::Bearer { header_value } => {
            // `strip_client_credentials` already removed every case variant of
            // `authorization`, so this insert is the canonical one.
            headers.insert("authorization".to_string(), header_value.clone());
        }
        ProviderAuth::Header { name, api_key } => {
            // The credential header name is provider-specific and may collide
            // with a case variant a later rule added; strip every case variant
            // before installing the canonical one.
            remove_header_ci(headers, name);
            headers.insert(name.clone(), api_key.clone());
        }
    }
    if provider.provider_type == ProviderType::Anthropic {
        headers.insert(
            "anthropic-version".to_string(),
            provider.anthropic_version.clone(),
        );
    }
    remove_header_ci(headers, "host");
    headers.insert("host".to_string(), provider.authority.clone());
    remove_header_ci(headers, "content-type");
    headers.insert("content-type".to_string(), "application/json".to_string());
    // A provider streams SSE; make the intent explicit to the upstream.
    remove_header_ci(headers, "accept");
    headers.insert("accept".to_string(), "text/event-stream".to_string());
    // Normalization parses line-delimited SSE. Strip client content-coding
    // negotiation and explicitly request identity so the provider does not
    // return gzip/br octets that the normalizer would misread as plaintext
    // events. Residual encodings are still handled fail-safe in `after_proxy` /
    // the normalizer.
    if normalizes_response {
        remove_header_ci(headers, "accept-encoding");
        headers.insert("accept-encoding".to_string(), "identity".to_string());
    }
}

pub(crate) fn remove_header_ci(headers: &mut HashMap<String, String>, name: &str) {
    headers.retain(|k, _| !k.eq_ignore_ascii_case(name));
}

fn content_encoding_value(headers: &HashMap<String, String>) -> Result<Option<&str>, ()> {
    let mut values = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-encoding"))
        .map(|(_, value)| value.as_str());
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        // Ambiguous duplicate field-lines — fixed category, no header echo.
        return Err(());
    }
    let value = value.trim();
    Ok((!value.is_empty()).then_some(value))
}

/// Fixed-cardinality residual `Content-Encoding` rejection reasons.
///
/// Client-facing 502 bodies, SSE upstream-error frames, and forged-metadata
/// normalization must never interpolate raw header/metadata members (including
/// credential-like or unbounded attacker tokens).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProviderEncodingRejectReason {
    AmbiguousDuplicateFieldLines,
    MalformedList,
    UnsupportedCoding,
    MixedIdentity,
    TooManyLayers,
}

impl ProviderEncodingRejectReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AmbiguousDuplicateFieldLines => "ambiguous Content-Encoding field-lines",
            Self::MalformedList => "malformed Content-Encoding list",
            Self::UnsupportedCoding => "unsupported Content-Encoding coding",
            Self::MixedIdentity => {
                "identity Content-Encoding cannot be combined with other codings"
            }
            Self::TooManyLayers => "Content-Encoding exceeds supported coding layer count",
        }
    }
}

enum ProviderContentEncoding {
    Identity,
    /// Canonical `#content-coding` list in application order (e.g. `gzip`,
    /// `gzip, br`). Decode undoes layers in reverse.
    Supported(String),
    Unsupported(ProviderEncodingRejectReason),
}

fn classify_provider_content_encoding(
    headers: &HashMap<String, String>,
) -> ProviderContentEncoding {
    let raw = match content_encoding_value(headers) {
        Ok(Some(raw)) => raw,
        Ok(None) => return ProviderContentEncoding::Identity,
        Err(()) => {
            return ProviderContentEncoding::Unsupported(
                ProviderEncodingRejectReason::AmbiguousDuplicateFieldLines,
            );
        }
    };
    let codings = match parse_content_codings(raw) {
        Ok(codings) => codings,
        // Parser diagnostics are already fixed-cardinality; map to field-
        // specific reasons without forwarding the string (defense in depth).
        Err(message) => {
            return ProviderContentEncoding::Unsupported(reject_reason_from_parse_error(&message));
        }
    };
    if codings.len() > NORMALIZE_DECODE_LIMITS.max_codings {
        return ProviderContentEncoding::Unsupported(ProviderEncodingRejectReason::TooManyLayers);
    }
    if codings.iter().all(|coding| coding == "identity") {
        return ProviderContentEncoding::Identity;
    }
    if codings.iter().any(|coding| coding == "identity") {
        return ProviderContentEncoding::Unsupported(ProviderEncodingRejectReason::MixedIdentity);
    }
    // Supported tokens only: parse_content_codings already rejected anything
    // outside gzip / x-gzip / br / identity.
    ProviderContentEncoding::Supported(codings.join(", "))
}

fn reject_reason_from_parse_error(message: &str) -> ProviderEncodingRejectReason {
    if message.contains("unsupported content-encoding") {
        ProviderEncodingRejectReason::UnsupportedCoding
    } else {
        ProviderEncodingRejectReason::MalformedList
    }
}

/// Map residual decode failures to fixed client diagnostics.
///
/// Decode helpers may still carry absolute size numbers from compile-time
/// limits; never forward arbitrary `io::Error` text or upstream body bytes.
fn safe_residual_decode_diagnostic(message: &str) -> &'static str {
    if message.contains("amplification exceeds") {
        "upstream Content-Encoding amplification limit exceeded"
    } else if message.contains("decoded content exceeds")
        || message.contains("decoded content-encoding work exceeds")
        || message.contains("streaming size limit")
        || message.contains("size overflowed")
        || message.contains("work overflowed")
    {
        "upstream Content-Encoding size limit exceeded"
    } else if message.contains("truncated") {
        "upstream Content-Encoding is truncated"
    } else if message.contains("trailing") || message.contains("concatenated") {
        "upstream Content-Encoding contains trailing or concatenated data"
    } else if message.contains("identity") && message.contains("combined") {
        ProviderEncodingRejectReason::MixedIdentity.as_str()
    } else if message.contains("more than") && message.contains("coding layers") {
        ProviderEncodingRejectReason::TooManyLayers.as_str()
    } else if message.contains("unsupported content-encoding")
        || message.contains("unsupported Content-Encoding")
    {
        ProviderEncodingRejectReason::UnsupportedCoding.as_str()
    } else if message.contains("empty coding")
        || message.contains("no coding members")
        || message.contains("not a valid HTTP token")
        || message.contains("unsupported parameters")
    {
        ProviderEncodingRejectReason::MalformedList.as_str()
    } else {
        "upstream Content-Encoding decode failed"
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

/// Media type every normalizer emits, whatever the provider labelled its own
/// framing as.
const NORMALIZED_SSE_CONTENT_TYPE: &str = "text/event-stream";

/// Relabel a normalized response whose provider media type is not SSE.
///
/// The Gemini adapter also normalizes the Vertex JSON-array fallback (a
/// provider that ignores the injected `alt=sse` answers `application/json`), and
/// what leaves the gateway on that path is OpenAI `chat.completion.chunk` SSE
/// terminated by `data: [DONE]`. Leaving the provider's `application/json`
/// label on those bytes would make OpenAI SDKs, intermediaries, and the
/// gateway's own `is_streaming_content_type` dispatch on a media type the body
/// no longer has. Responses already labelled `text/event-stream` (every
/// Anthropic normalization, and Gemini's SSE framing) are left untouched so
/// their `charset` and other parameters survive.
fn stamp_normalized_sse_content_type(headers: &mut HashMap<String, String>) {
    let already_sse = headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-type") && is_event_stream_content_type(value)
    });
    if already_sse {
        return;
    }
    remove_header_ci(headers, "content-type");
    headers.insert(
        "content-type".to_string(),
        NORMALIZED_SSE_CONTENT_TYPE.to_string(),
    );
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

/// [`upstream_sse_error_body`] under the response's retained ceiling.
///
/// The envelope shape is fixed. Callers pass fixed-cardinality diagnostics
/// (never raw header/metadata members or upstream body bytes), and the whole
/// body is SERIALIZED THROUGH the bounded sink rather than built as a complete
/// `Vec` that a bounded copy would only measure afterwards: the JSON string is
/// written by `serde_json` straight into the sink, which stops at the ceiling
/// (GHSA-pwcm-6rh8-f2gh). If a pathologically small ceiling cannot hold even
/// the envelope, the replacement is EMPTY: leaving the response alone would
/// deliver the raw provider body, so it is never the fail-closed answer.
///
/// The bytes are identical to `upstream_sse_error_body`'s: `serde_json`'s
/// compact object rendering emits `message` before `type` under both insertion
/// and lexicographic member ordering, and `to_writer` applies the same string
/// escaping `Value`'s `Display` does.
fn bounded_upstream_sse_error_body(message: &str, ceiling: usize) -> Vec<u8> {
    try_bounded_upstream_sse_error_body(message, ceiling).unwrap_or_default()
}

fn try_bounded_upstream_sse_error_body(message: &str, ceiling: usize) -> Option<Vec<u8>> {
    use crate::proxy::response_buffer_budget::BoundedResponseBodySink;
    let mut sink = BoundedResponseBodySink::with_ceiling(ceiling);
    if !sink.push(br#"data: {"error":{"message":"#) {
        return None;
    }
    // Only the string value goes through `serde_json`, so the escaping is the
    // canonical one without an intermediate `Value` copy of `message`.
    if serde_json::to_writer(&mut sink, message).is_err() {
        return None;
    }
    if !sink.push(br#","type":"upstream_error"}}"#) || !sink.push(b"\n\ndata: [DONE]\n\n") {
        return None;
    }
    sink.finish()
}

/// Bytes fed to the buffered normalizer per driver call.
///
/// This is a WORKING-SET choice, not the memory bound: the bound is
/// [`NormalizedSseOut`], which every normalized byte is written through from the
/// first byte under this response's retained ceiling (GHSA-pwcm-6rh8-f2gh).
/// Slicing the input keeps one call's parse/transcode working set small and
/// makes the buffered path drive the normalizer exactly as a provider that
/// chunked its stream this way would, so the shared streaming inspector
/// contract — cumulative event, byte, and output accounting — is unchanged.
const BUFFERED_NORMALIZE_CHUNK_BYTES: usize = 16 * 1024;

fn wrap_provider_normalizer(
    provider_type: ProviderType,
    model: String,
    encoding: Option<String>,
    tools_forbidden: bool,
    limits: NormalizeLimits,
) -> Box<dyn ResponseStreamInspector> {
    let engine = match provider_type {
        ProviderType::Anthropic => {
            NormalizeEngine::Anthropic(AnthropicSseNormalizer::new(model, tools_forbidden, limits))
        }
        ProviderType::GoogleGemini => {
            NormalizeEngine::Gemini(GeminiStreamNormalizer::new(model, tools_forbidden, limits))
        }
        ProviderType::OpenAi | ProviderType::OpenAiCompatible | ProviderType::AzureOpenAi => {
            // Unreachable: only normalizing providers install an inspector.
            return Box::new(ImmediateUpstreamErrorNormalizer::new(
                "internal error: non-normalizing provider requested a stream normalizer"
                    .to_string(),
            ));
        }
    };
    let Some(encoding) = encoding else {
        return match engine {
            NormalizeEngine::Anthropic(inner) => Box::new(inner),
            NormalizeEngine::Gemini(inner) => Box::new(inner),
        };
    };
    // Re-validate the metadata stamp (or a forged value) with the same
    // classifier `after_proxy` used. Unsupported / ambiguous chains fail closed
    // immediately — never buffer opaque provider frames under a bad coding.
    let mut probe = HashMap::with_capacity(1);
    probe.insert("content-encoding".to_string(), encoding);
    match classify_provider_content_encoding(&probe) {
        ProviderContentEncoding::Supported(coding) => {
            Box::new(ContentDecodingNormalizer::new(coding, engine))
        }
        ProviderContentEncoding::Identity => match engine {
            NormalizeEngine::Anthropic(inner) => Box::new(inner),
            NormalizeEngine::Gemini(inner) => Box::new(inner),
        },
        ProviderContentEncoding::Unsupported(reason) => Box::new(
            ImmediateUpstreamErrorNormalizer::new(reason.as_str().to_string()),
        ),
    }
}

/// How a claimed normalizing provider response's `Content-Type` is handled.
///
/// Neither translated provider may stream raw 2xx provider bytes past the
/// adapter under the OpenAI contract the client asked for: a missing or
/// unexpected media type fails closed through after_proxy / inspector /
/// buffered normalization. Anthropic streaming is always `text/event-stream`
/// (the translation forces `stream: true`); Gemini additionally admits the
/// Vertex-compatible JSON stream framing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProviderStreamMediaDecision {
    Normalize,
    PassThrough,
    FailClosedMissingContentType,
    FailClosedUnexpectedContentType,
}

fn classify_provider_stream_media(
    provider_type: ProviderType,
    content_type: Option<&str>,
) -> ProviderStreamMediaDecision {
    match provider_type {
        ProviderType::Anthropic => match content_type {
            Some(ct) if is_event_stream_content_type(ct) => ProviderStreamMediaDecision::Normalize,
            None => ProviderStreamMediaDecision::FailClosedMissingContentType,
            Some(_) => ProviderStreamMediaDecision::FailClosedUnexpectedContentType,
        },
        ProviderType::GoogleGemini => match content_type {
            Some(ct) if is_event_stream_content_type(ct) || is_json_content_type(ct) => {
                ProviderStreamMediaDecision::Normalize
            }
            None => ProviderStreamMediaDecision::FailClosedMissingContentType,
            Some(_) => ProviderStreamMediaDecision::FailClosedUnexpectedContentType,
        },
        ProviderType::OpenAi | ProviderType::OpenAiCompatible | ProviderType::AzureOpenAi => {
            ProviderStreamMediaDecision::PassThrough
        }
    }
}

/// Fixed-cardinality Content-Type diagnostics. Never echoes the provider header.
fn provider_stream_media_fail_closed_message(
    decision: ProviderStreamMediaDecision,
) -> Option<&'static str> {
    match decision {
        ProviderStreamMediaDecision::FailClosedMissingContentType => Some(
            "Upstream provider returned a successful response without a Content-Type suitable for provider stream normalization",
        ),
        ProviderStreamMediaDecision::FailClosedUnexpectedContentType => Some(
            "Upstream provider returned a successful response with an unexpected Content-Type for provider stream normalization",
        ),
        ProviderStreamMediaDecision::Normalize | ProviderStreamMediaDecision::PassThrough => None,
    }
}

/// Ensure Gemini streaming requests negotiate `alt=sse` when normalizing.
///
/// Native Gemini `streamGenerateContent` defaults to a JSON array stream; with
/// `alt=sse` it uses documented SSE framing. Vertex-compatible JSON object
/// streams remain accepted by the normalizer when a provider omits the flag.
fn ensure_gemini_alt_sse(backend_path: &mut String, committed_query: &mut String) {
    if query_has_alt_sse(backend_path) || query_has_alt_sse(committed_query) {
        return;
    }
    if let Some(qmark) = backend_path.find('?') {
        if backend_path[qmark + 1..].is_empty() {
            backend_path.push_str("alt=sse");
        } else {
            backend_path.push_str("&alt=sse");
        }
        return;
    }
    if committed_query.is_empty() {
        *committed_query = "alt=sse".to_string();
    } else {
        committed_query.push_str("&alt=sse");
    }
}

fn query_has_alt_sse(query_or_path: &str) -> bool {
    let query = query_or_path
        .split_once('?')
        .map(|(_, q)| q)
        .unwrap_or(query_or_path);
    query.split('&').any(|pair| {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        name.eq_ignore_ascii_case("alt") && value.eq_ignore_ascii_case("sse")
    })
}

/// Decoded names of an endpoint-owned query, under `&`-only splitting and,
/// for a pair with a raw `;`, each `;` sub-pair name too (RFC and form
/// decodings; issue #6579), so a provider that splits on `;` cannot have an
/// endpoint parameter overridden through either reading. `%3B` stays content.
fn decoded_query_names(query: &str) -> HashSet<String> {
    let mut names = HashSet::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let name = pair.split_once('=').map_or(pair, |(name, _)| name);
        names.extend(super::utils::query::query_name_decodings(name));
        names.extend(super::utils::query::semicolon_sub_pair_names(pair));
    }
    names
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
        // A `;` sub-pair is a parameter of its own to a provider that also
        // splits on `;` (issue #6579): it must neither carry a stripped
        // credential through nor override an endpoint-owned parameter.
        if strip_names.contains(raw_name)
            || strip_names.contains(decoded_name.as_ref())
            || super::utils::query::query_name_decodings(raw_name)
                .iter()
                .any(|name| strip_names.contains(name.as_str()))
            || super::utils::query::query_name_decodings(raw_name)
                .iter()
                .any(|name| endpoint_query_names.contains(name))
            || super::utils::query::semicolon_sub_pair_names_any(pair, &strip_names)
            || super::utils::query::semicolon_sub_pair_names(pair)
                .iter()
                .any(|name| endpoint_query_names.contains(name))
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

/// Per-instance normalizer stream bounds. The defaults are the published
/// constants; the `max_stream_bytes`, `max_stream_events`, and
/// `max_normalized_stream_bytes` config fields override them within admitted
/// ranges. The per-event byte cap and JSON depth stay fixed, and a residual
/// provider `Content-Encoding` is still decoded under the fixed
/// [`NORMALIZE_DECODE_LIMITS`].
#[derive(Clone, Copy, Debug)]
struct NormalizeLimits {
    /// Cumulative provider plaintext one normalizer accepts.
    max_plaintext_bytes: usize,
    /// Complete provider events one normalizer accepts.
    max_events: usize,
    /// Cumulative OpenAI-shaped output one normalizer may emit.
    max_output_bytes: usize,
}

#[cfg(test)]
impl NormalizeLimits {
    const DEFAULT: Self = Self {
        max_plaintext_bytes: MAX_SSE_NORMALIZED_BODY_BYTES,
        max_events: MAX_SSE_EVENTS,
        max_output_bytes: MAX_SSE_NORMALIZED_OUTPUT_BYTES,
    };
}

/// Maximum JSON nesting depth accepted in an SSE `data:` payload before
/// `serde_json` parse/transcode. Anthropic protocol frames are shallow; this
/// is well below serde_json's own recursion ceiling and fails with a stable
/// diagnostic rather than a parser-internal error.
pub const MAX_SSE_EVENT_JSON_DEPTH: usize = 32;

/// Compact when the consumed prefix reaches this many bytes (and is at least
/// half the buffer) so total copy work stays linear in input size.
const SSE_BUFFER_COMPACT_THRESHOLD: usize = 8192;

/// The normalizer's output seam: every normalized byte is written through it,
/// under a ceiling, from the first byte.
///
/// The streaming inspector contract hands one emission back per driver call, so
/// the obvious implementation accumulates that call's output in a `String` and
/// returns it — which on the BUFFERED path is a complete would-be replacement
/// materialised outside any bounded sink (GHSA-pwcm-6rh8-f2gh). Slicing the
/// input smaller does not fix it: the transcoded expansion of one slice is
/// bounded by a CONSTANT, not by this response's retained ceiling, so a small
/// route-effective ceiling could still be exceeded by a transient nobody
/// measured.
///
/// So the accumulator itself is the bound. The buffered path constructs ONE of
/// these at the response's retained ceiling and drives every call into it, so
/// the producer's whole transient is the output it is building — one ceiling,
/// not two — and an over-ceiling normalization is refused while it is being
/// written. The streaming path constructs an unbounded one per call, which is
/// byte-for-byte what it did before: nothing is retained there.
///
/// `begin_call` / `reset_call` exist for one internal seam: the cumulative
/// normalized-output bound may replace the CURRENT call's emission with a fixed
/// diagnostic. That rollback must not discard emissions from earlier calls, so
/// it truncates to the call's start mark rather than clearing the buffer.
pub(crate) struct NormalizedSseOut {
    sink: crate::proxy::response_buffer_budget::BoundedResponseBodySink,
    /// Length at the start of the current driver call.
    call_start: usize,
    /// A write was refused. Sticky across the rest of the call, and cleared only
    /// by a `reset_call` that abandons the emission the refusal belongs to.
    refused: bool,
}

impl NormalizedSseOut {
    /// A per-call accumulator for the STREAMING path, which retains nothing.
    fn unbounded() -> Self {
        Self::with_ceiling(usize::MAX)
    }

    fn with_ceiling(ceiling: usize) -> Self {
        Self {
            sink: crate::proxy::response_buffer_budget::BoundedResponseBodySink::with_ceiling(
                ceiling,
            ),
            call_start: 0,
            refused: false,
        }
    }

    /// Mark the start of one driver (`on_chunk` / `on_end`) emission.
    fn begin_call(&mut self) {
        self.call_start = self.sink.len();
    }

    /// Abandon everything this call emitted, keeping earlier calls intact.
    fn reset_call(&mut self) {
        self.sink.truncate(self.call_start);
        self.refused = self.sink.overflowed();
    }

    fn push_str(&mut self, text: &str) {
        if !self.sink.push(text.as_bytes()) {
            self.refused = true;
        }
    }

    /// Emit one `data: <json>\n\n` SSE line without building it as a `String`
    /// first. `serde_json` writes the compact form straight through the sink,
    /// which is byte-identical to `Value`'s own `Display`.
    fn write_sse_data_line(&mut self, payload: &Value) {
        self.push_str("data: ");
        if serde_json::to_writer(&mut self.sink, payload).is_err() {
            self.refused = true;
        }
        self.push_str("\n\n");
    }

    /// Bytes emitted so far in THIS call — what the cumulative-output bound
    /// measures.
    fn len(&self) -> usize {
        self.sink.len().saturating_sub(self.call_start)
    }

    /// Whether any write was refused by the ceiling. The buffered driver treats
    /// this as fail-closed; the unbounded streaming accumulator cannot set it.
    fn refused(&self) -> bool {
        self.refused
    }

    /// The bytes this call emitted, for the streaming inspector's per-call
    /// `Bytes`. An unbounded accumulator never refuses, so the `None` arm is a
    /// checked impossibility rather than an expected outcome.
    fn take_call_bytes(self) -> Vec<u8> {
        self.sink.finish().unwrap_or_default()
    }

    /// The complete accumulated replacement, or `None` when a write was refused.
    fn finish(self) -> Option<Vec<u8>> {
        if self.refused {
            return None;
        }
        self.sink.finish()
    }
}

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
    limits: NormalizeLimits,
    model: String,
    stream_id: Option<String>,
    synthetic_id: String,
    created: i64,
    message_started: bool,
    role_emitted: bool,
    done_emitted: bool,
    terminal: Option<StreamTerminal>,
    /// When true, any Anthropic `tool_use` fails closed instead of becoming
    /// OpenAI `tool_calls` deltas (caller constrained this generation to none).
    tools_forbidden: bool,
    /// Active tool blocks: Some(index) is a client call; None is provider-executed.
    tool_indices: HashMap<u64, Option<u32>>,
    finish_reason: Option<&'static str>,
    next_tool_index: u32,
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
    /// Raw Anthropic usage categories merged across `message_start` and
    /// `message_delta`, so a delta restating only some categories cannot erase
    /// the cache counters an earlier event reported.
    usage_categories: super::utils::ai_providers::UsageCategories,
}

impl AnthropicSseNormalizer {
    fn new(model: String, tools_forbidden: bool, limits: NormalizeLimits) -> Self {
        Self {
            buf: Vec::new(),
            cursor: 0,
            scan_cursor: 0,
            bytes_ingested: 0,
            events_seen: 0,
            normalized_out_bytes: 0,
            limits,
            model,
            stream_id: None,
            synthetic_id: format!("chatcmpl-stream-{}", uuid::Uuid::new_v4().simple()),
            created: Utc::now().timestamp(),
            message_started: false,
            role_emitted: false,
            done_emitted: false,
            terminal: None,
            tools_forbidden,
            tool_indices: HashMap::new(),
            finish_reason: None,
            next_tool_index: 0,
            prompt_tokens: None,
            completion_tokens: None,
            usage_categories: Default::default(),
        }
    }

    /// Fold one Anthropic `usage` carrier (the `message_start` message or the
    /// `message_delta` event) into the running counters. The billed input
    /// includes prompt-cache writes and reads, which Anthropic reports beside
    /// `input_tokens` rather than in it.
    ///
    /// Returns `false` when a usage counter is malformed or its category sum
    /// overflows; the caller fails the stream closed, exactly as the Gemini
    /// normalizer does for a malformed `usageMetadata`.
    fn absorb_anthropic_usage(&mut self, carrier: &Value) -> bool {
        let usage = super::utils::ai_providers::extract_response_usage(
            carrier,
            super::utils::ai_providers::AiProvider::Anthropic,
        );
        let folded = self.usage_categories.absorb(usage);
        let (prompt_invalid, completion_invalid) = self.usage_categories.invalid_sides();
        if prompt_invalid || completion_invalid {
            return false;
        }
        if folded.prompt_tokens.is_some() {
            self.prompt_tokens = folded.prompt_tokens;
        }
        if folded.completion_tokens.is_some() {
            self.completion_tokens = folded.completion_tokens;
        }
        true
    }

    /// Merge Bedrock invocation metrics carried on any Anthropic event (an
    /// InvokeModel stream wrapping the Messages events) into the running
    /// usage. Returns `false` when they are malformed or overflow.
    fn absorb_invocation_metrics(&mut self, event: &Value) -> bool {
        let Some(metrics) = super::utils::ai_providers::extract_bedrock_invocation_metrics(event)
        else {
            return true;
        };
        let folded = self.usage_categories.absorb(metrics);
        let (prompt_invalid, completion_invalid) = self.usage_categories.invalid_sides();
        if prompt_invalid || completion_invalid {
            return false;
        }
        if folded.prompt_tokens.is_some() {
            self.prompt_tokens = folded.prompt_tokens;
        }
        if folded.completion_tokens.is_some() {
            self.completion_tokens = folded.completion_tokens;
        }
        true
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
        let id = self.synthetic_id.clone();
        self.stream_id = Some(id.clone());
        id
    }

    /// Envelope a single OpenAI streaming `choices[0].delta` as an SSE line,
    /// written straight into the bounded accumulator.
    fn write_chunk_line(
        &mut self,
        delta: Value,
        finish_reason: Option<&str>,
        out: &mut NormalizedSseOut,
    ) {
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
        out.write_sse_data_line(&payload);
    }

    /// The terminal finish and known usage, written through the bounded accumulator.
    /// Returns an error when provider-controlled u64 counts overflow on add so
    /// the caller can fail closed instead of publishing a wrapped total.
    fn write_terminal_lines(&mut self, out: &mut NormalizedSseOut) -> Result<(), &'static str> {
        let total = match (self.prompt_tokens, self.completion_tokens) {
            (Some(p), Some(c)) => Some(p.checked_add(c).ok_or(
                "upstream provider sent usage token counts that overflow u64 total; stream terminated",
            )?),
            _ => None,
        };
        let finish = self.finish_reason.unwrap_or(if self.next_tool_index > 0 {
            "tool_calls"
        } else {
            "stop"
        });
        self.write_chunk_line(json!({}), Some(finish), out);
        if self.prompt_tokens.is_none() && self.completion_tokens.is_none() {
            return Ok(());
        }
        let id = self.id();
        let payload = json!({
            "id": id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": [],
            "usage": {
                "prompt_tokens": self.prompt_tokens,
                "completion_tokens": self.completion_tokens,
                "total_tokens": total,
            },
        });
        out.write_sse_data_line(&payload);
        Ok(())
    }

    fn emit_upstream_error(&mut self, message: &str, out: &mut NormalizedSseOut) {
        let err = json!({
            "error": {
                "message": message,
                "type": "upstream_error",
            }
        });
        out.write_sse_data_line(&err);
    }

    fn fail_bound(&mut self, message: &'static str, out: &mut NormalizedSseOut) {
        self.clear_buffer();
        self.emit_upstream_error(message, out);
        self.finish(StreamTerminal::ProviderError, out);
    }

    /// Transcode one Anthropic event JSON into zero or more OpenAI SSE lines.
    /// Returns whether the upstream inspector driver should terminate now.
    fn transcode_event(&mut self, event: &Value, out: &mut NormalizedSseOut) -> bool {
        if !self.absorb_invocation_metrics(event) {
            self.fail_bound(
                "upstream provider sent malformed Bedrock invocation metrics; stream terminated",
                out,
            );
            return true;
        }
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
                // `output_tokens` here is a placeholder the terminal delta
                // supersedes; only the input side is authoritative.
                let start_usage =
                    super::utils::ai_providers::anthropic_message_start_usage(message);
                if !self.absorb_anthropic_usage(&start_usage) {
                    self.fail_bound(
                        "upstream provider sent malformed or overflowing Anthropic usage; stream terminated",
                        out,
                    );
                    return true;
                }
                if !self.role_emitted {
                    self.role_emitted = true;
                    self.write_chunk_line(json!({ "role": "assistant" }), None, out);
                }
                false
            }
            Some("content_block_start") => {
                if !self.require_message_start("content_block_start", out) {
                    return true;
                }
                let block = &event["content_block"];
                let block_type = block.get("type").and_then(Value::as_str);
                if matches!(
                    block_type,
                    Some("tool_use" | "server_tool_use" | "mcp_tool_use")
                ) {
                    let Some(index) = event["index"].as_u64() else {
                        self.fail_bound(
                            "upstream provider sent a tool block without an index",
                            out,
                        );
                        return true;
                    };
                    if self.tool_indices.contains_key(&index) {
                        self.fail_bound(
                            "upstream provider repeated an active tool block index",
                            out,
                        );
                        return true;
                    }
                    if block_type != Some("tool_use") {
                        self.tool_indices.insert(index, None);
                        return false;
                    }
                    if self.tools_forbidden {
                        self.emit_upstream_error(
                            "upstream provider emitted tool use despite tool_choice none",
                            out,
                        );
                        self.finish(StreamTerminal::UpstreamFailure, out);
                        return true;
                    }
                    let id = block.get("id").and_then(Value::as_str).unwrap_or("");
                    let name = block.get("name").and_then(Value::as_str).unwrap_or("");
                    if id.is_empty() || name.is_empty() {
                        self.fail_bound("upstream provider sent a tool call without identity", out);
                        return true;
                    }
                    let tool_index = self.next_tool_index;
                    self.next_tool_index += 1;
                    self.tool_indices.insert(index, Some(tool_index));
                    self.write_chunk_line(
                        json!({
                            "tool_calls": [{
                                "index": tool_index,
                                "id": id,
                                "type": "function",
                                "function": { "name": name, "arguments": "" },
                            }]
                        }),
                        None,
                        out,
                    );
                }
                false
            }
            Some("content_block_delta") => {
                if !self.require_message_start("content_block_delta", out) {
                    return true;
                }
                let delta = &event["delta"];
                match delta.get("type").and_then(Value::as_str) {
                    Some("text_delta") => {
                        if let Some(text) = delta.get("text").and_then(Value::as_str) {
                            self.ensure_role(out);
                            self.write_chunk_line(json!({ "content": text }), None, out);
                        }
                    }
                    Some("input_json_delta") => {
                        let tool_index = match event["index"]
                            .as_u64()
                            .and_then(|index| self.tool_indices.get(&index))
                        {
                            Some(Some(index)) => *index,
                            Some(None) => return false,
                            None => {
                                self.fail_bound(
                                    "upstream provider sent arguments without an active tool block",
                                    out,
                                );
                                return true;
                            }
                        };
                        if self.tools_forbidden {
                            self.emit_upstream_error(
                                "upstream provider emitted tool use despite tool_choice none",
                                out,
                            );
                            self.finish(StreamTerminal::UpstreamFailure, out);
                            return true;
                        }
                        if let Some(partial) = delta.get("partial_json").and_then(Value::as_str) {
                            self.write_chunk_line(
                                json!({
                                    "tool_calls": [{
                                        "index": tool_index,
                                        "function": { "arguments": partial },
                                    }]
                                }),
                                None,
                                out,
                            );
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
                if !self.absorb_anthropic_usage(event) {
                    self.fail_bound(
                        "upstream provider sent malformed or overflowing Anthropic usage; stream terminated",
                        out,
                    );
                    return true;
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
                if !event["delta"]["stop_reason"].is_null() {
                    let finish = stop_reason
                        .ok_or("upstream provider sent a non-string Anthropic stop_reason")
                        .and_then(super::ai_federation::map_anthropic_stop_reason);
                    let finish = match finish {
                        Ok(finish) => finish,
                        Err(message) => {
                            self.fail_bound(message, out);
                            return true;
                        }
                    };
                    if self
                        .finish_reason
                        .is_some_and(|previous| previous != finish)
                    {
                        self.fail_bound("upstream provider changed Anthropic stop_reason", out);
                        return true;
                    }
                    self.finish_reason = Some(finish);
                }
                false
            }
            Some("content_block_stop") => {
                if let Some(index) = event["index"].as_u64() {
                    self.tool_indices.remove(&index);
                }
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
            // ping and unknown events produce no output
            // (forward-compatible). Events with a present `type` that is not a
            // known Anthropic frame are ignored; malformed JSON is handled by
            // the caller as an upstream failure.
            _ => false,
        }
    }

    fn ensure_role(&mut self, out: &mut NormalizedSseOut) {
        if !self.role_emitted {
            self.role_emitted = true;
            self.write_chunk_line(json!({ "role": "assistant" }), None, out);
        }
    }

    fn require_message_start(&mut self, event_type: &str, out: &mut NormalizedSseOut) -> bool {
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

    /// Emit the finish and final usage (when successful), then the OpenAI `[DONE]`
    /// sentinel exactly once.
    fn finish(&mut self, terminal: StreamTerminal, out: &mut NormalizedSseOut) {
        if self.done_emitted {
            return;
        }
        let mut terminal = terminal;
        if terminal == StreamTerminal::MessageStop
            && let Err(message) = self.write_terminal_lines(out)
        {
            self.emit_upstream_error(message, out);
            terminal = StreamTerminal::ProviderError;
        }
        self.done_emitted = true;
        self.terminal = Some(terminal);
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

    fn apply_frame_outcome(&mut self, outcome: FrameOutcome, out: &mut NormalizedSseOut) -> bool {
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
    fn drain_complete(&mut self, out: &mut NormalizedSseOut) -> bool {
        loop {
            let end = {
                let scan_start = self.scan_cursor.max(self.cursor).min(self.buf.len());
                match sse_event_end(&self.buf[scan_start..]) {
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
            if self.events_seen >= self.limits.max_events {
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

    fn normalized_output_exceeded(&mut self, out: &mut NormalizedSseOut, terminal: bool) -> bool {
        let total = self.normalized_out_bytes.saturating_add(out.len());
        let allowed = if terminal {
            self.limits.max_output_bytes
        } else {
            self.limits
                .max_output_bytes
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
        //
        // On the buffered path the accumulator spans several calls, so this
        // rolls back to the start of the CURRENT call rather than clearing
        // everything — the emissions already handed to the client on the
        // streaming path are the ones a buffered response has already
        // accumulated, and neither may be rewritten retroactively.
        out.reset_call();
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
        if next > self.limits.max_plaintext_bytes {
            return Err(
                "upstream provider SSE stream exceeded the cumulative size limit; stream terminated",
            );
        }
        self.bytes_ingested = next;
        Ok(())
    }

    /// Ingest `chunk`, enforcing all resource bounds before expensive work.
    /// Returns whether the stream should terminate.
    fn push_chunk(&mut self, mut chunk: &[u8], out: &mut NormalizedSseOut) -> bool {
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
    fn finish_stream(&mut self, out: &mut NormalizedSseOut) {
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
            if self.events_seen >= self.limits.max_events {
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

    fn commit_forwarded(&mut self, out: &NormalizedSseOut) {
        self.normalized_out_bytes = self.normalized_out_bytes.saturating_add(out.len());
    }

    /// One driver call against a caller-owned accumulator. The trait impl below
    /// binds an unbounded per-call one (streaming retains nothing); the buffered
    /// path binds ONE ceiling-bounded accumulator across every call, so the
    /// producer's whole transient is the replacement it is building.
    ///
    /// Returns whether the stream should terminate.
    fn drive_chunk(&mut self, chunk: &[u8], out: &mut NormalizedSseOut) -> bool {
        out.begin_call();
        if self.push_chunk(chunk, out) {
            return true;
        }
        self.commit_forwarded(out);
        false
    }

    /// [`Self::drive_chunk`] for end-of-stream.
    fn drive_end(&mut self, out: &mut NormalizedSseOut) {
        out.begin_call();
        self.finish_stream(out);
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
        let mut out = NormalizedSseOut::unbounded();
        if self.drive_chunk(chunk, &mut out) {
            return ResponseStreamAction::Terminate(Some(Bytes::from(out.take_call_bytes())));
        }
        ResponseStreamAction::Forward(Bytes::from(out.take_call_bytes()))
    }

    async fn on_end(&mut self) -> ResponseStreamAction {
        if self.done_emitted {
            return ResponseStreamAction::Terminate(None);
        }
        let mut out = NormalizedSseOut::unbounded();
        self.drive_end(&mut out);
        ResponseStreamAction::Terminate(Some(Bytes::from(out.take_call_bytes())))
    }
}

// ---------------------------------------------------------------------------
// Gemini / Vertex stream → OpenAI chat.completion.chunk SSE normalizer
// ---------------------------------------------------------------------------

/// How Gemini/Vertex bytes are framed on the wire for one response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GeminiFraming {
    Undecided,
    Sse,
    /// Native `streamGenerateContent` without `alt=sse`, or Vertex JSON array /
    /// concatenated-object streams.
    JsonStream,
}

/// Strict JSON-array separator/value state. Concatenated-object streams stay
/// `Inactive` for the whole response; array streams never accept leading,
/// repeated, trailing, or missing commas, and reject bytes after `]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GeminiJsonArrayState {
    Inactive,
    /// After `[` — empty `[]` is allowed; a leading comma is not.
    ExpectFirstValueOrEnd,
    /// After `,` — a value is required; `]` would be a trailing comma.
    ExpectValueAfterComma,
    /// After a complete value; awaiting `,` or `]`.
    ExpectCommaOrEnd,
    /// Closing `]` consumed; only whitespace allowed afterward.
    Closed,
}

/// Per-candidate OpenAI choice state while Gemini deltas arrive.
#[derive(Default)]
struct GeminiCandidateState {
    role_emitted: bool,
    next_tool_index: u32,
    /// True once this candidate has emitted any client-visible OpenAI choice
    /// delta (role, content, tool_calls, or a terminal finish_reason chunk).
    emitted_client_visible: bool,
    finished: bool,
    saw_tool_call: bool,
}

/// Stateful normalizer for Gemini/`streamGenerateContent` (and Vertex-compatible)
/// response streams into OpenAI `chat.completion.chunk` SSE.
///
/// Accepts both SSE (`alt=sse`) and JSON array / object streams. Chunk splits
/// are buffered under the same per-event / cumulative / output / depth bounds
/// as the Anthropic normalizer. Malformed, oversized, or unrepresentable frames
/// fail closed with field-specific diagnostics that never echo provider
/// payloads, credentials, or tool-argument bodies.
///
/// Candidate lifecycle is fail-closed: every candidate that emitted
/// client-visible output must reach a terminal `finishReason` before clean EOF
/// succeeds, post-finish / duplicate-terminal candidate data is rejected, and
/// duplicate candidate indexes within one provider event are rejected.
/// Content parts are closed-shape: only `text` and `functionCall` map to OpenAI
/// deltas. The sole metadata-only exception is an empty JSON object `{}` (no
/// keys), which carries no provider output; any other non-empty part without a
/// representable field (media, code, thought-only, scalars, unknowns) fails
/// closed with a fixed-cardinality diagnostic.
struct GeminiStreamNormalizer {
    buf: Vec<u8>,
    cursor: usize,
    scan_cursor: usize,
    /// Resumable structural state for the JSON-framed value scanner. See
    /// [`JsonScanMemo`] for the staleness argument.
    json_scan: JsonScanMemo,
    bytes_ingested: usize,
    events_seen: usize,
    normalized_out_bytes: usize,
    limits: NormalizeLimits,
    framing: GeminiFraming,
    json_array_state: GeminiJsonArrayState,
    model: String,
    stream_id: Option<String>,
    /// First provider responseId, independent of any emitted synthetic identity.
    provider_response_id: Option<String>,
    created: i64,
    done_emitted: bool,
    terminal: Option<StreamTerminal>,
    tools_forbidden: bool,
    candidates: HashMap<u64, GeminiCandidateState>,
    saw_successful_finish: bool,
    usage: GeminiUsageCounters,
    call_id_prefix: String,
}

impl GeminiStreamNormalizer {
    fn new(model: String, tools_forbidden: bool, limits: NormalizeLimits) -> Self {
        Self {
            buf: Vec::new(),
            cursor: 0,
            scan_cursor: 0,
            json_scan: JsonScanMemo::Fresh,
            bytes_ingested: 0,
            events_seen: 0,
            normalized_out_bytes: 0,
            limits,
            framing: GeminiFraming::Undecided,
            json_array_state: GeminiJsonArrayState::Inactive,
            model,
            stream_id: None,
            provider_response_id: None,
            created: Utc::now().timestamp(),
            done_emitted: false,
            terminal: None,
            tools_forbidden,
            candidates: HashMap::new(),
            saw_successful_finish: false,
            usage: GeminiUsageCounters::default(),
            call_id_prefix: uuid::Uuid::new_v4().simple().to_string(),
        }
    }

    fn unread_len(&self) -> usize {
        self.buf.len().saturating_sub(self.cursor)
    }

    /// Sole cursor writer outside compaction.
    ///
    /// The JSON scan memo is expressed relative to the start of the value under
    /// scan, which is always `cursor`, so any cursor move invalidates it. Doing
    /// the reset here — rather than at each call site — is what makes a stale
    /// memo unrepresentable.
    fn set_cursor(&mut self, pos: usize) {
        if pos != self.cursor {
            self.json_scan = JsonScanMemo::Fresh;
        }
        self.cursor = pos;
    }

    fn clear_buffer(&mut self) {
        self.buf.clear();
        self.cursor = 0;
        self.scan_cursor = 0;
        self.json_scan = JsonScanMemo::Fresh;
        if self.buf.capacity() > 64 * 1024 {
            self.buf.shrink_to(4096);
        }
    }

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
            // Draining exactly `cursor` bytes leaves the unread region
            // byte-for-byte identical and moves its start to 0, so the
            // cursor-relative JSON scan memo stays valid without adjustment.
            self.cursor = 0;
        }
    }

    fn id(&mut self) -> String {
        if let Some(id) = &self.stream_id {
            return id.clone();
        }
        let id = format!("chatcmpl-stream-{}", self.call_id_prefix);
        self.stream_id = Some(id.clone());
        id
    }

    fn write_chunk_line(
        &mut self,
        choice_index: u64,
        delta: Value,
        finish_reason: Option<&str>,
        out: &mut NormalizedSseOut,
    ) {
        let id = self.id();
        let payload = json!({
            "id": id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": [{
                "index": choice_index,
                "delta": delta,
                "finish_reason": finish_reason,
            }],
        });
        out.write_sse_data_line(&payload);
    }

    fn write_usage_line(&mut self, out: &mut NormalizedSseOut) -> Result<(), &'static str> {
        let Some(usage) = self.usage.to_openai_usage()? else {
            return Ok(());
        };
        let id = self.id();
        let payload = json!({
            "id": id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": [],
            "usage": usage,
        });
        out.write_sse_data_line(&payload);
        Ok(())
    }

    fn emit_upstream_error(&mut self, message: &str, out: &mut NormalizedSseOut) {
        let message = truncate_provider_error_message(message);
        let err = json!({
            "error": {
                "message": message,
                "type": "upstream_error",
            }
        });
        out.write_sse_data_line(&err);
    }

    fn fail_bound(&mut self, message: &'static str, out: &mut NormalizedSseOut) {
        self.clear_buffer();
        self.emit_upstream_error(message, out);
        self.finish(StreamTerminal::ProviderError, out);
    }

    fn finish(&mut self, terminal: StreamTerminal, out: &mut NormalizedSseOut) {
        if self.done_emitted {
            return;
        }
        let mut terminal = terminal;
        if terminal == StreamTerminal::MessageStop
            && let Err(message) = self.write_usage_line(out)
        {
            self.emit_upstream_error(message, out);
            terminal = StreamTerminal::ProviderError;
        }
        self.done_emitted = true;
        self.terminal = Some(terminal);
        out.push_str("data: [DONE]\n\n");
    }

    fn candidate_state(&mut self, index: u64) -> &mut GeminiCandidateState {
        self.candidates.entry(index).or_default()
    }

    fn ensure_role(&mut self, choice_index: u64, out: &mut NormalizedSseOut) {
        if self.candidate_state(choice_index).role_emitted {
            return;
        }
        let state = self.candidate_state(choice_index);
        state.role_emitted = true;
        state.emitted_client_visible = true;
        self.write_chunk_line(choice_index, json!({ "role": "assistant" }), None, out);
    }

    fn mark_candidate_finished_visible(&mut self, choice_index: u64) {
        let state = self.candidate_state(choice_index);
        state.finished = true;
        state.emitted_client_visible = true;
    }

    fn candidate_already_finished(&self, choice_index: u64) -> bool {
        self.candidates
            .get(&choice_index)
            .is_some_and(|state| state.finished)
    }

    fn reject_post_finish_candidate(&mut self, out: &mut NormalizedSseOut) -> bool {
        self.emit_upstream_error(
            "upstream provider sent Gemini candidate output after a terminal finishReason; stream terminated",
            out,
        );
        self.finish(StreamTerminal::UpstreamFailure, out);
        true
    }

    /// Terminate on a `promptFeedback.blockReason` under the same
    /// candidate-lifecycle contract every other terminal obeys.
    ///
    /// A prompt block ends the whole generation, but it must not manufacture a
    /// second terminal chunk for a choice that already finished (a `stop`
    /// followed by a contradictory `content_filter`), and it must not close a
    /// multi-candidate stream with the success-shaped terminal while another
    /// candidate has emitted client-visible output and never reached a terminal
    /// `finishReason`. That second case is exactly the premature close
    /// `finish_stream` fails closed on, so it fails closed here too.
    fn finish_prompt_block(&mut self, out: &mut NormalizedSseOut) -> bool {
        if !self.candidate_already_finished(0) {
            self.ensure_role(0, out);
            self.write_chunk_line(0, json!({}), Some("content_filter"), out);
            self.mark_candidate_finished_visible(0);
            self.saw_successful_finish = true;
        }
        let unfinished_visible = self
            .candidates
            .values()
            .any(|state| state.emitted_client_visible && !state.finished);
        if unfinished_visible {
            self.emit_upstream_error(
                "upstream provider blocked the Gemini prompt before every candidate reached a terminal finishReason",
                out,
            );
            self.finish(StreamTerminal::UpstreamFailure, out);
            return true;
        }
        self.finish(StreamTerminal::MessageStop, out);
        true
    }

    /// Consume one optional leading UTF-8 byte-order mark.
    ///
    /// Returns `false` while the buffered bytes are still a strict prefix of the
    /// BOM: framing must not be decided from a byte that may turn out to be part
    /// of a mark the client never sees.
    fn strip_leading_bom(&mut self) -> bool {
        if self.cursor != 0 {
            return true;
        }
        if self.buf.starts_with(UTF8_BOM) {
            self.set_cursor(UTF8_BOM.len());
            self.scan_cursor = self.cursor;
            return true;
        }
        if self.buf.len() < UTF8_BOM.len() && UTF8_BOM.starts_with(&self.buf) {
            return false;
        }
        true
    }

    fn detect_framing(&mut self) -> Result<(), &'static str> {
        if self.framing != GeminiFraming::Undecided {
            return Ok(());
        }
        if !self.strip_leading_bom() {
            return Ok(());
        }
        let unread = self.buf.get(self.cursor..).unwrap_or_default();
        let Some(first) = unread.iter().find(|b| !b.is_ascii_whitespace()).copied() else {
            return Ok(());
        };
        match first {
            b'{' | b'[' => {
                self.framing = GeminiFraming::JsonStream;
                Ok(())
            }
            byte if sse_line_may_start_with(byte) => {
                self.framing = GeminiFraming::Sse;
                Ok(())
            }
            _ => Err(
                "upstream provider sent an unrecognized Gemini/Vertex stream framing; stream terminated",
            ),
        }
    }

    fn account_ingested(&mut self, chunk_len: usize) -> Result<(), &'static str> {
        let Some(next) = self.bytes_ingested.checked_add(chunk_len) else {
            return Err(
                "upstream provider SSE stream exceeded the cumulative size limit; stream terminated",
            );
        };
        if next > self.limits.max_plaintext_bytes {
            return Err(
                "upstream provider SSE stream exceeded the cumulative size limit; stream terminated",
            );
        }
        self.bytes_ingested = next;
        Ok(())
    }

    fn normalized_output_exceeded(&mut self, out: &mut NormalizedSseOut, terminal: bool) -> bool {
        let total = self.normalized_out_bytes.saturating_add(out.len());
        let allowed = if terminal {
            self.limits.max_output_bytes
        } else {
            self.limits
                .max_output_bytes
                .saturating_sub(SSE_NORMALIZED_OUTPUT_TERMINAL_RESERVE_BYTES)
        };
        if total <= allowed {
            return false;
        }
        out.reset_call();
        self.done_emitted = false;
        self.terminal = None;
        self.fail_bound(SSE_NORMALIZED_OUTPUT_LIMIT_MESSAGE, out);
        true
    }

    fn interpret_json_object(&mut self, raw: &str, out: &mut NormalizedSseOut) -> bool {
        if json_nesting_depth(raw) > MAX_SSE_EVENT_JSON_DEPTH {
            self.emit_upstream_error(
                "upstream provider sent a Gemini event with excessive JSON nesting; stream terminated",
                out,
            );
            self.finish(StreamTerminal::UpstreamFailure, out);
            return true;
        }
        let event: Value = match serde_json::from_str(raw) {
            Ok(value) => value,
            Err(_) => {
                self.emit_upstream_error(
                    "upstream provider sent a malformed Gemini JSON event; stream terminated",
                    out,
                );
                self.finish(StreamTerminal::UpstreamFailure, out);
                return true;
            }
        };
        self.transcode_event(&event, out)
    }

    fn transcode_event(&mut self, event: &Value, out: &mut NormalizedSseOut) -> bool {
        // Provider error envelopes (HTTP-shaped JSON inside the stream).
        if let Some(error) = event.get("error") {
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("upstream provider stream error");
            self.emit_upstream_error(message, out);
            self.finish(StreamTerminal::ProviderError, out);
            return true;
        }

        if let Some(response_id_value) = event.get("responseId") {
            let Some(response_id) = response_id_value.as_str() else {
                self.emit_upstream_error(
                    "upstream provider sent an invalid Gemini responseId; stream terminated",
                    out,
                );
                self.finish(StreamTerminal::UpstreamFailure, out);
                return true;
            };
            if response_id.is_empty() || response_id.len() > 128 {
                self.emit_upstream_error(
                    "upstream provider sent an invalid Gemini responseId; stream terminated",
                    out,
                );
                self.finish(StreamTerminal::UpstreamFailure, out);
                return true;
            }
            if let Some(existing) = self.provider_response_id.as_deref() {
                if existing != response_id {
                    self.emit_upstream_error(
                        "upstream provider changed Gemini responseId mid-stream; stream terminated",
                        out,
                    );
                    self.finish(StreamTerminal::UpstreamFailure, out);
                    return true;
                }
            } else {
                // Keep an already emitted synthetic id stable, while admitting
                // the first real provider id as the baseline for later checks.
                if self.stream_id.is_none() {
                    self.stream_id = Some(response_id.to_string());
                }
                self.provider_response_id = Some(response_id.to_string());
            }
        }
        // Validate provider modelVersion shape when present, but never replace
        // the claim-committed model stamped into normalized chunks.
        if let Some(model_version_value) = event.get("modelVersion") {
            let Some(model_version) = model_version_value.as_str() else {
                self.emit_upstream_error(
                    "upstream provider sent an invalid Gemini modelVersion; stream terminated",
                    out,
                );
                self.finish(StreamTerminal::UpstreamFailure, out);
                return true;
            };
            if !is_valid_url_model_component(model_version) {
                self.emit_upstream_error(
                    "upstream provider sent an invalid Gemini modelVersion; stream terminated",
                    out,
                );
                self.finish(StreamTerminal::UpstreamFailure, out);
                return true;
            }
        }

        if let Some(usage) = event.get("usageMetadata") {
            match apply_gemini_usage_metadata(usage, &mut self.usage) {
                Ok(()) => {}
                Err(message) => {
                    self.emit_upstream_error(message, out);
                    self.finish(StreamTerminal::UpstreamFailure, out);
                    return true;
                }
            }
        }

        match gemini_prompt_block_reason(event) {
            Ok(Some(_)) => return self.finish_prompt_block(out),
            Ok(None) => {}
            Err(message) => {
                self.emit_upstream_error(message, out);
                self.finish(StreamTerminal::UpstreamFailure, out);
                return true;
            }
        }

        let Some(candidates) = event.get("candidates") else {
            // Usage-only / empty keepalive objects are forward-compatible.
            return false;
        };
        let Some(candidates) = candidates.as_array() else {
            self.emit_upstream_error(
                "upstream provider sent Gemini candidates that were not an array; stream terminated",
                out,
            );
            self.finish(StreamTerminal::UpstreamFailure, out);
            return true;
        };

        let mut seen_indexes: HashSet<u64> = HashSet::with_capacity(candidates.len());
        for (fallback_index, candidate) in candidates.iter().enumerate() {
            let Some(candidate) = candidate.as_object() else {
                self.emit_upstream_error(
                    "upstream provider sent a non-object Gemini candidate; stream terminated",
                    out,
                );
                self.finish(StreamTerminal::UpstreamFailure, out);
                return true;
            };
            let choice_index = match candidate.get("index") {
                None => fallback_index as u64,
                Some(value) => match value.as_u64() {
                    Some(index) => index,
                    None => {
                        self.emit_upstream_error(
                            "upstream provider sent a Gemini candidate with a malformed index; stream terminated",
                            out,
                        );
                        self.finish(StreamTerminal::UpstreamFailure, out);
                        return true;
                    }
                },
            };
            if !seen_indexes.insert(choice_index) {
                self.emit_upstream_error(
                    "upstream provider sent duplicate Gemini candidate indexes in one event; stream terminated",
                    out,
                );
                self.finish(StreamTerminal::UpstreamFailure, out);
                return true;
            }

            if self.candidate_already_finished(choice_index) {
                return self.reject_post_finish_candidate(out);
            }

            let mapped_finish = match candidate.get("finishReason") {
                None => None,
                Some(Value::String(finish)) => match map_gemini_finish_reason(finish) {
                    Ok(mapped) => Some(mapped),
                    Err(message) => {
                        self.emit_upstream_error(message, out);
                        self.finish(StreamTerminal::UpstreamFailure, out);
                        return true;
                    }
                },
                Some(_) => {
                    self.emit_upstream_error(
                        "upstream provider sent a Gemini candidate with a malformed finishReason; stream terminated",
                        out,
                    );
                    self.finish(StreamTerminal::UpstreamFailure, out);
                    return true;
                }
            };

            // Emit content/tool deltas before the finish chunk when present.
            // Post-finish / duplicate-terminal checks above keep this fail-closed.
            if let Err(message) = self.emit_candidate_parts(choice_index, candidate, out) {
                self.emit_upstream_error(message, out);
                self.finish(StreamTerminal::UpstreamFailure, out);
                return true;
            }

            let Some(base_finish) = mapped_finish else {
                continue;
            };
            let saw_tool_call = self.candidate_state(choice_index).saw_tool_call;
            let finish_reason = if saw_tool_call {
                if base_finish != "stop" {
                    self.emit_upstream_error(
                        "upstream provider sent Gemini function calls with a non-STOP finishReason; stream terminated",
                        out,
                    );
                    self.finish(StreamTerminal::UpstreamFailure, out);
                    return true;
                }
                "tool_calls"
            } else {
                base_finish
            };
            self.ensure_role(choice_index, out);
            self.write_chunk_line(choice_index, json!({}), Some(finish_reason), out);
            self.mark_candidate_finished_visible(choice_index);
            self.saw_successful_finish = true;
        }
        false
    }

    fn emit_candidate_parts(
        &mut self,
        choice_index: u64,
        candidate: &serde_json::Map<String, Value>,
        out: &mut NormalizedSseOut,
    ) -> Result<(), &'static str> {
        let Some(content) = candidate.get("content") else {
            return Ok(());
        };
        let Some(content) = content.as_object() else {
            return Err(
                "upstream provider sent a Gemini candidate with a non-object content; stream terminated",
            );
        };
        match content.get("role") {
            None => {}
            Some(Value::String(role)) if role == "model" => {}
            Some(_) => {
                return Err(
                    "upstream provider sent a Gemini candidate content role that was not model; stream terminated",
                );
            }
        }
        let parts = match content.get("parts") {
            None => return Ok(()),
            Some(value) => value.as_array().ok_or(
                "upstream provider sent a Gemini content parts value that was not an array; stream terminated",
            )?,
        };
        for part in parts {
            let Some(part_obj) = part.as_object() else {
                return Err(
                    "upstream provider sent a non-object Gemini content part; stream terminated",
                );
            };
            // Gemini thinking models attach an opaque `thoughtSignature` to
            // function-call parts (and to text parts, including an empty final
            // text part while streaming). It is the one recognized sibling
            // field; every other extra member still fails closed.
            let thought_signature = match part_obj.get("thoughtSignature") {
                None => None,
                Some(Value::String(signature)) if valid_thought_signature(signature) => {
                    Some(signature.as_str())
                }
                Some(_) => {
                    return Err(
                        "upstream provider sent a malformed Gemini thoughtSignature; stream terminated",
                    );
                }
            };
            let representable_fields = 1 + usize::from(thought_signature.is_some());
            match (part_obj.get("text"), part_obj.get("functionCall")) {
                (Some(text_value), None) => {
                    // A text-part signature is not required for continuation
                    // (only function-call signatures are), and OpenAI content
                    // deltas have no carrier for it, so it is accepted and not
                    // surfaced.
                    if part_obj.len() != representable_fields {
                        return Err(
                            "upstream provider sent a Gemini content part with unrepresentable additional fields; stream terminated",
                        );
                    }
                    let Some(text) = text_value.as_str() else {
                        return Err(
                            "upstream provider sent a Gemini text part that was not a string; stream terminated",
                        );
                    };
                    if text.is_empty() {
                        continue;
                    }
                    self.ensure_role(choice_index, out);
                    self.write_chunk_line(choice_index, json!({ "content": text }), None, out);
                }
                (None, Some(function_call)) => {
                    if part_obj.len() != representable_fields {
                        return Err(
                            "upstream provider sent a Gemini content part with unrepresentable additional fields; stream terminated",
                        );
                    }
                    if self.tools_forbidden {
                        return Err("upstream provider emitted tool use despite tool_choice none");
                    }
                    let name = function_call
                        .get("name")
                        .and_then(Value::as_str)
                        .filter(|n| valid_tool_name(n))
                        .ok_or(
                            "upstream provider sent a Gemini functionCall without a valid name; stream terminated",
                        )?;
                    let args = function_call
                        .get("args")
                        .filter(|value| value.is_object())
                        .ok_or(
                            "upstream provider sent a Gemini functionCall without object args; stream terminated",
                        )?;
                    let args_json = serde_json::to_string(args).map_err(|_| {
                        "upstream provider sent unrepresentable Gemini functionCall args; stream terminated"
                    })?;
                    if args_json.len() > MAX_TOOL_ARGUMENTS_BYTES {
                        return Err(
                            "upstream provider sent oversized Gemini functionCall args; stream terminated",
                        );
                    }
                    let tool_index = {
                        let state = self.candidate_state(choice_index);
                        state.saw_tool_call = true;
                        state.emitted_client_visible = true;
                        let idx = state.next_tool_index;
                        state.next_tool_index = state.next_tool_index.saturating_add(1);
                        idx
                    };
                    // Monotonic per-candidate tool index — not per-event part_index —
                    // so multi-event tool calls cannot collide on the generated id.
                    let call_id = format!(
                        "call_gemini_{}_{choice_index}_{tool_index}",
                        self.call_id_prefix
                    );
                    let mut tool_call = json!({
                        "index": tool_index,
                        "id": call_id,
                        "type": "function",
                        "function": { "name": name, "arguments": args_json },
                    });
                    // Round-trip carrier in Google's OpenAI-compatibility shape:
                    // the client echoes `extra_content.google.thought_signature`
                    // on this assistant tool call, and request translation
                    // restores it onto the same Gemini `functionCall` part.
                    if let Some(signature) = thought_signature {
                        tool_call["extra_content"] =
                            json!({ "google": { "thought_signature": signature } });
                    }
                    self.ensure_role(choice_index, out);
                    self.write_chunk_line(
                        choice_index,
                        json!({ "tool_calls": [tool_call] }),
                        None,
                        out,
                    );
                }
                (None, None) if part_obj.len() == usize::from(thought_signature.is_some()) => {
                    // Metadata-only parts carry no provider output and cannot
                    // hide media/code/unknown parts: an empty object, or a
                    // part holding only a thought signature.
                }
                (None, None) => {
                    return Err(
                        "upstream provider sent an unrepresentable Gemini content part; stream terminated",
                    );
                }
                _ => {
                    return Err(
                        "upstream provider sent an ambiguous Gemini content part; stream terminated",
                    );
                }
            }
        }
        Ok(())
    }

    fn drain_sse(&mut self, out: &mut NormalizedSseOut) -> bool {
        loop {
            let end = {
                let scan_start = self.scan_cursor.max(self.cursor).min(self.buf.len());
                match sse_event_end(&self.buf[scan_start..]) {
                    Some(end_rel) => scan_start + end_rel,
                    None => {
                        self.scan_cursor = self.buf.len().saturating_sub(3).max(self.cursor);
                        break;
                    }
                }
            };
            let end_rel = end.saturating_sub(self.cursor);
            if end_rel > MAX_SSE_EVENT_BYTES {
                self.fail_bound(
                    "upstream provider sent an oversized SSE event; stream terminated",
                    out,
                );
                return true;
            }
            if self.events_seen >= self.limits.max_events {
                self.fail_bound(
                    "upstream provider SSE stream exceeded the event count limit; stream terminated",
                    out,
                );
                return true;
            }
            let start = self.cursor;
            let raw = &self.buf[start..end];
            let outcome = match extract_sse_event_result(raw) {
                Ok((_event_name, None)) => FrameOutcome::Ignore,
                Ok((_event_name, Some(data))) => {
                    if data == "[DONE]" {
                        FrameOutcome::Ignore
                    } else {
                        // Interpret immediately via a owned String to avoid
                        // holding a borrow across mutation.
                        FrameOutcome::Event(Value::String(data))
                    }
                }
                Err(_) => FrameOutcome::Fail(
                    "upstream provider sent a malformed SSE event; stream terminated",
                ),
            };
            self.set_cursor(end);
            self.scan_cursor = end;
            self.events_seen = self.events_seen.saturating_add(1);
            let terminate = match outcome {
                FrameOutcome::Ignore => false,
                FrameOutcome::Event(Value::String(data)) => self.interpret_json_object(&data, out),
                FrameOutcome::Event(_) => false,
                FrameOutcome::Fail(message) => {
                    self.emit_upstream_error(message, out);
                    self.finish(StreamTerminal::UpstreamFailure, out);
                    true
                }
            };
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

    fn skip_json_whitespace(&mut self) {
        let mut pos = self.cursor;
        while pos < self.buf.len() && self.buf[pos].is_ascii_whitespace() {
            pos += 1;
        }
        self.set_cursor(pos);
        self.scan_cursor = self.cursor;
    }

    fn fail_json_array_syntax(&mut self, out: &mut NormalizedSseOut) -> bool {
        self.emit_upstream_error(
            "upstream provider sent malformed Gemini JSON array framing; stream terminated",
            out,
        );
        self.finish(StreamTerminal::UpstreamFailure, out);
        true
    }

    fn drain_json_stream(&mut self, out: &mut NormalizedSseOut) -> bool {
        loop {
            self.skip_json_whitespace();
            if self.cursor >= self.buf.len() {
                break;
            }

            match self.json_array_state {
                GeminiJsonArrayState::Closed => {
                    // Non-whitespace after the closing `]` is hostile.
                    return self.fail_json_array_syntax(out);
                }
                GeminiJsonArrayState::Inactive => {
                    if self.buf[self.cursor] == b'[' {
                        self.json_array_state = GeminiJsonArrayState::ExpectFirstValueOrEnd;
                        self.set_cursor(self.cursor + 1);
                        self.scan_cursor = self.cursor;
                        continue;
                    }
                }
                GeminiJsonArrayState::ExpectFirstValueOrEnd => {
                    if self.buf[self.cursor] == b']' {
                        self.json_array_state = GeminiJsonArrayState::Closed;
                        self.set_cursor(self.cursor + 1);
                        self.scan_cursor = self.cursor;
                        continue;
                    }
                    if self.buf[self.cursor] == b',' {
                        return self.fail_json_array_syntax(out);
                    }
                }
                GeminiJsonArrayState::ExpectValueAfterComma => {
                    if self.buf[self.cursor] == b']' || self.buf[self.cursor] == b',' {
                        return self.fail_json_array_syntax(out);
                    }
                }
                GeminiJsonArrayState::ExpectCommaOrEnd => {
                    if self.buf[self.cursor] == b']' {
                        self.json_array_state = GeminiJsonArrayState::Closed;
                        self.set_cursor(self.cursor + 1);
                        self.scan_cursor = self.cursor;
                        continue;
                    }
                    if self.buf[self.cursor] == b',' {
                        self.set_cursor(self.cursor + 1);
                        self.scan_cursor = self.cursor;
                        self.json_array_state = GeminiJsonArrayState::ExpectValueAfterComma;
                        continue;
                    }
                    // Another value without a comma separator.
                    return self.fail_json_array_syntax(out);
                }
            }

            // Incremental framing scan: every `on_chunk` resumes where the last
            // one stopped instead of re-reading the whole unread window, so a
            // value delivered in tiny provider-controlled segments costs O(n)
            // in total rather than O(n^2).
            let resume = match self.json_scan {
                JsonScanMemo::Invalid => None,
                JsonScanMemo::Fresh => Some(JsonValueScan::default()),
                JsonScanMemo::Partial(state) => Some(state),
            };
            let step = match resume {
                Some(state) => scan_json_value(&self.buf[self.cursor..], state),
                None => JsonScanStep::Invalid,
            };
            let end_rel = match step {
                JsonScanStep::Complete(end_rel) => end_rel,
                JsonScanStep::Partial(state) => {
                    self.json_scan = JsonScanMemo::Partial(state);
                    if self.unread_len() > MAX_SSE_EVENT_BYTES {
                        self.fail_bound(
                            "upstream provider sent an oversized SSE event; stream terminated",
                            out,
                        );
                        return true;
                    }
                    break;
                }
                JsonScanStep::Invalid => {
                    // Monotone under appends: a first byte that cannot open a
                    // JSON value, or a structural close below depth 0, can
                    // never be repaired by more bytes. Remember it so the
                    // remainder of the stream is not rescanned; the unread
                    // window still fails closed once it exceeds the cap.
                    self.json_scan = JsonScanMemo::Invalid;
                    if self.unread_len() > MAX_SSE_EVENT_BYTES {
                        self.fail_bound(
                            "upstream provider sent an oversized SSE event; stream terminated",
                            out,
                        );
                        return true;
                    }
                    break;
                }
            };
            if end_rel > MAX_SSE_EVENT_BYTES {
                self.fail_bound(
                    "upstream provider sent an oversized SSE event; stream terminated",
                    out,
                );
                return true;
            }
            if self.events_seen >= self.limits.max_events {
                self.fail_bound(
                    "upstream provider SSE stream exceeded the event count limit; stream terminated",
                    out,
                );
                return true;
            }
            let start = self.cursor;
            let end = self.cursor + end_rel;
            let raw = match std::str::from_utf8(&self.buf[start..end]) {
                Ok(text) => text.to_string(),
                Err(_) => {
                    self.emit_upstream_error(
                        "upstream provider sent a malformed SSE event; stream terminated",
                        out,
                    );
                    self.finish(StreamTerminal::UpstreamFailure, out);
                    return true;
                }
            };
            self.set_cursor(end);
            self.scan_cursor = end;
            self.events_seen = self.events_seen.saturating_add(1);
            if matches!(
                self.json_array_state,
                GeminiJsonArrayState::ExpectFirstValueOrEnd
                    | GeminiJsonArrayState::ExpectValueAfterComma
            ) {
                self.json_array_state = GeminiJsonArrayState::ExpectCommaOrEnd;
            }
            let terminate = self.interpret_json_object(&raw, out);
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

    fn drain_complete(&mut self, out: &mut NormalizedSseOut) -> bool {
        if let Err(message) = self.detect_framing() {
            self.fail_bound(message, out);
            return true;
        }
        match self.framing {
            GeminiFraming::Undecided => false,
            GeminiFraming::Sse => self.drain_sse(out),
            GeminiFraming::JsonStream => self.drain_json_stream(out),
        }
    }

    fn push_chunk(&mut self, mut chunk: &[u8], out: &mut NormalizedSseOut) -> bool {
        if let Err(message) = self.account_ingested(chunk.len()) {
            self.fail_bound(message, out);
            return true;
        }
        while !chunk.is_empty() {
            let unread = self.unread_len();
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

    fn finish_stream(&mut self, out: &mut NormalizedSseOut) {
        if self.drain_complete(out) {
            return;
        }
        if self.unread_len() > 0 {
            let trailing = &self.buf[self.cursor..];
            let only_ws = trailing.iter().all(u8::is_ascii_whitespace);
            if !only_ws {
                self.emit_upstream_error(
                    "upstream provider ended the Gemini stream with malformed trailing data",
                    out,
                );
                self.finish(StreamTerminal::UpstreamFailure, out);
                let _ = self.normalized_output_exceeded(out, true);
                return;
            }
            self.clear_buffer();
        }
        match self.json_array_state {
            GeminiJsonArrayState::ExpectFirstValueOrEnd
            | GeminiJsonArrayState::ExpectValueAfterComma
            | GeminiJsonArrayState::ExpectCommaOrEnd => {
                self.emit_upstream_error(
                    "upstream provider sent malformed Gemini JSON array framing; stream terminated",
                    out,
                );
                self.finish(StreamTerminal::UpstreamFailure, out);
                let _ = self.normalized_output_exceeded(out, true);
                return;
            }
            GeminiJsonArrayState::Inactive | GeminiJsonArrayState::Closed => {}
        }
        // Premature EOF contract is one stable redacted diagnostic whether the
        // stream closed with zero candidates (e.g. `[]`) or with unfinished
        // client-visible candidates — never echo provider payload bytes.
        let unfinished_visible = self
            .candidates
            .values()
            .any(|state| state.emitted_client_visible && !state.finished);
        if self.saw_successful_finish && !unfinished_visible {
            self.finish(StreamTerminal::MessageStop, out);
            let _ = self.normalized_output_exceeded(out, true);
            return;
        }
        self.emit_upstream_error(
            "upstream provider closed the Gemini stream before every candidate reached a terminal finishReason",
            out,
        );
        self.finish(StreamTerminal::UpstreamFailure, out);
        let _ = self.normalized_output_exceeded(out, true);
    }

    fn commit_forwarded(&mut self, out: &NormalizedSseOut) {
        self.normalized_out_bytes = self.normalized_out_bytes.saturating_add(out.len());
    }

    fn drive_chunk(&mut self, chunk: &[u8], out: &mut NormalizedSseOut) -> bool {
        out.begin_call();
        if self.push_chunk(chunk, out) {
            return true;
        }
        self.commit_forwarded(out);
        false
    }

    fn drive_end(&mut self, out: &mut NormalizedSseOut) {
        out.begin_call();
        self.finish_stream(out);
    }
}

#[async_trait]
impl ResponseStreamInspector for GeminiStreamNormalizer {
    fn stage(&self) -> ResponseStreamInspectorStage {
        ResponseStreamInspectorStage::Normalize
    }

    async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction {
        if self.done_emitted {
            return ResponseStreamAction::Terminate(None);
        }
        let mut out = NormalizedSseOut::unbounded();
        if self.drive_chunk(chunk, &mut out) {
            return ResponseStreamAction::Terminate(Some(Bytes::from(out.take_call_bytes())));
        }
        ResponseStreamAction::Forward(Bytes::from(out.take_call_bytes()))
    }

    async fn on_end(&mut self) -> ResponseStreamAction {
        if self.done_emitted {
            return ResponseStreamAction::Terminate(None);
        }
        let mut out = NormalizedSseOut::unbounded();
        self.drive_end(&mut out);
        ResponseStreamAction::Terminate(Some(Bytes::from(out.take_call_bytes())))
    }
}

fn truncate_provider_error_message(message: &str) -> String {
    const MAX: usize = 256;
    if message.len() <= MAX {
        return message.to_string();
    }
    let mut truncated = message.chars().take(MAX).collect::<String>();
    truncated.push('…');
    truncated
}

/// Overflow diagnostic shared by every normalized-usage addition.
const GEMINI_USAGE_OVERFLOW_MESSAGE: &str =
    "upstream provider sent usage token counts that overflow u64 total; stream terminated";

/// Provider-reported Gemini token counters, kept in their native categories.
///
/// Gemini defines `totalTokenCount` as prompt + candidates + tool-use prompt +
/// thoughts. Recomputing a normalized total from prompt and candidates alone
/// therefore published a number BELOW what the provider billed for every
/// thinking or tool-using generation, and the downstream consumers of the
/// normalized OpenAI usage chunk (`ai_rate_limiter`, `ai_token_metrics`, and
/// anything else reading `usage.total_tokens`) treat an explicit total as
/// authoritative and complete. Carrying the provider's categories through the
/// adapter is what keeps a normalized route's budget equal to a native one
/// (`GHSA-v9p3-wj9f-wvpv`).
#[derive(Default)]
struct GeminiUsageCounters {
    prompt: Option<u64>,
    candidates: Option<u64>,
    /// Reasoning ("thinking") output tokens. Billed, and part of the provider
    /// total, but not part of `candidatesTokenCount`.
    thoughts: Option<u64>,
    /// Input-side tokens the provider billed for tool-use prompting.
    tool_use_prompt: Option<u64>,
    /// The provider's own authoritative total, when it sent one.
    total: Option<u64>,
}

impl GeminiUsageCounters {
    /// Render the terminal OpenAI-shaped `usage` object, or `None` when the
    /// provider reported no counter at all.
    ///
    /// Each side is published when reported. proto3 JSON omits zero counters,
    /// so an omitted base is zero when a sibling category on its side
    /// (tool-use prompt, thoughts) was reported; a side with nothing reported
    /// stays absent rather than charged as zero. A provider total is
    /// published when it is at least the reported components, raised to them
    /// when both sides are known, and otherwise withheld as inconsistent;
    /// without a provider total, only both sides make a complete one.
    fn to_openai_usage(&self) -> Result<Option<Value>, &'static str> {
        // proto3 JSON omits zero counters, so an omitted base is zero when a
        // sibling on its side was reported (same rule as the shared
        // `UsageCategories` fold every other metering surface uses).
        let prompt_base = self.prompt.or_else(|| self.tool_use_prompt.map(|_| 0));
        let candidates = self.candidates.or_else(|| self.thoughts.map(|_| 0));
        // Gemini bills tool-use prompting on the input side, and OpenAI's
        // `completion_tokens` is defined to include reasoning tokens, so each
        // extra category folds into the counter that already carries it.
        let prompt = prompt_base
            .map(|base| checked_usage_sum(base, self.tool_use_prompt))
            .transpose()?;
        let completion = candidates
            .map(|base| checked_usage_sum(base, self.thoughts))
            .transpose()?;
        if prompt.is_none() && completion.is_none() && self.total.is_none() {
            return Ok(None);
        }
        // Components the provider did report, even one-sided, are published;
        // an unreported side stays absent rather than charged as zero.
        let known = prompt
            .unwrap_or(0)
            .checked_add(completion.unwrap_or(0))
            .ok_or(GEMINI_USAGE_OVERFLOW_MESSAGE)?;
        // The provider's own total stays authoritative and may exceed the sum
        // of the categories this adapter can represent (a category added by a
        // later API revision). Never publish a total below the components
        // printed in the same chunk either. Without a provider total, only
        // both sides make a complete one.
        // A provider total below the reported components is raised to them
        // only when both sides are known; with a side missing it is an
        // inconsistent partial report and is not published as complete.
        let total = match (self.total, prompt, completion) {
            (Some(reported), _, _) if reported >= known => Some(reported),
            (Some(_), Some(_), Some(_)) | (None, Some(_), Some(_)) => Some(known),
            _ => None,
        };

        let mut usage = serde_json::Map::new();
        if let Some(prompt) = prompt {
            usage.insert("prompt_tokens".to_string(), json!(prompt));
        }
        if let Some(completion) = completion {
            usage.insert("completion_tokens".to_string(), json!(completion));
        }
        if let Some(total) = total {
            usage.insert("total_tokens".to_string(), json!(total));
        }
        if let Some(thoughts) = self.thoughts {
            usage.insert(
                "completion_tokens_details".to_string(),
                json!({ "reasoning_tokens": thoughts }),
            );
        }
        Ok(Some(Value::Object(usage)))
    }
}

fn checked_usage_sum(base: u64, extra: Option<u64>) -> Result<u64, &'static str> {
    let Some(extra) = extra else {
        return Ok(base);
    };
    base.checked_add(extra).ok_or(GEMINI_USAGE_OVERFLOW_MESSAGE)
}

/// Fail-closed Gemini `usageMetadata` admission for the stream normalizer.
///
/// A present `usageMetadata` must be an object. Every present recognized count
/// field (`promptTokenCount`, `candidatesTokenCount`, `completionTokenCount`,
/// `thoughtsTokenCount`, `toolUsePromptTokenCount`, `totalTokenCount`) must be a
/// JSON integer representable as `u64`. Omitted fields stay omitted.
/// `candidatesTokenCount` is preferred over `completionTokenCount` when both are
/// present and valid; a present malformed preferred field never falls through to
/// the alternate.
fn apply_gemini_usage_metadata(
    usage: &Value,
    counters: &mut GeminiUsageCounters,
) -> Result<(), &'static str> {
    let Some(usage) = usage.as_object() else {
        return Err(
            "upstream provider sent Gemini usageMetadata that was not an object; stream terminated",
        );
    };

    if let Some(prompt) = gemini_optional_usage_count(usage, "promptTokenCount")? {
        counters.prompt = Some(prompt);
    }

    // Validate every present recognized completion-side field first so a
    // malformed preferred key cannot silently fall back to the alternate.
    let candidates = gemini_optional_usage_count(usage, "candidatesTokenCount")?;
    let completion_alt = gemini_optional_usage_count(usage, "completionTokenCount")?;
    let thoughts = gemini_optional_usage_count(usage, "thoughtsTokenCount")?;
    let tool_use_prompt = gemini_optional_usage_count(usage, "toolUsePromptTokenCount")?;
    let total = gemini_optional_usage_count(usage, "totalTokenCount")?;

    if let Some(completion) = candidates.or(completion_alt) {
        counters.candidates = Some(completion);
    }
    if let Some(thoughts) = thoughts {
        counters.thoughts = Some(thoughts);
    }
    if let Some(tool_use_prompt) = tool_use_prompt {
        counters.tool_use_prompt = Some(tool_use_prompt);
    }
    if let Some(total) = total {
        counters.total = Some(total);
    }
    Ok(())
}

fn gemini_optional_usage_count(
    usage: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<Option<u64>, &'static str> {
    // ProtoJSON defines `null` as unset, the same as an omitted field.
    let Some(value) = usage.get(field).filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    match value.as_u64() {
        Some(count) => Ok(Some(count)),
        None => Err(match field {
            "promptTokenCount" => {
                "upstream provider sent a malformed Gemini usageMetadata.promptTokenCount; stream terminated"
            }
            "candidatesTokenCount" => {
                "upstream provider sent a malformed Gemini usageMetadata.candidatesTokenCount; stream terminated"
            }
            "completionTokenCount" => {
                "upstream provider sent a malformed Gemini usageMetadata.completionTokenCount; stream terminated"
            }
            "thoughtsTokenCount" => {
                "upstream provider sent a malformed Gemini usageMetadata.thoughtsTokenCount; stream terminated"
            }
            "toolUsePromptTokenCount" => {
                "upstream provider sent a malformed Gemini usageMetadata.toolUsePromptTokenCount; stream terminated"
            }
            "totalTokenCount" => {
                "upstream provider sent a malformed Gemini usageMetadata.totalTokenCount; stream terminated"
            }
            _ => {
                "upstream provider sent a malformed Gemini usageMetadata token count; stream terminated"
            }
        }),
    }
}

fn gemini_prompt_block_reason(event: &Value) -> Result<Option<&'static str>, &'static str> {
    let Some(feedback) = event.get("promptFeedback") else {
        return Ok(None);
    };
    let Some(feedback) = feedback.as_object() else {
        return Err("upstream provider sent a non-object Gemini promptFeedback; stream terminated");
    };
    let Some(reason) = feedback.get("blockReason") else {
        return Ok(None);
    };
    match reason.as_str() {
        Some(
            "SAFETY" | "BLOCKLIST" | "PROHIBITED_CONTENT" | "MODEL_ARMOR" | "IMAGE_SAFETY"
            | "JAILBREAK" | "OTHER",
        ) => Ok(Some("content_filter")),
        Some("BLOCK_REASON_UNSPECIFIED" | "BLOCKED_REASON_UNSPECIFIED") => Ok(None),
        Some(_) => Err(
            "upstream provider sent an unsupported Gemini promptFeedback.blockReason; stream terminated",
        ),
        None => Err(
            "upstream provider sent a non-string Gemini promptFeedback.blockReason; stream terminated",
        ),
    }
}

/// Map Gemini `finishReason` to an OpenAI finish_reason.
fn map_gemini_finish_reason(reason: &str) -> Result<&'static str, &'static str> {
    match reason {
        "STOP" | "OTHER" => Ok("stop"),
        "MAX_TOKENS" => Ok("length"),
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
        | "UNEXPECTED_TOOL_CALL" => Ok("content_filter"),
        _ => Err("upstream provider sent an unsupported Gemini finishReason; stream terminated"),
    }
}

/// Resume point for the top-level JSON value scanner.
///
/// `scanned` counts bytes already inspected from the START OF THE VALUE, and
/// the three flags are the exact structural state the scanner needs to continue
/// mid-string or mid-escape without misparsing. A resume offset alone would not
/// be enough: restarting inside a string would read `{`/`}`/`"` as structure.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct JsonValueScan {
    scanned: usize,
    depth: usize,
    in_string: bool,
    escape: bool,
}

/// Memoized scan position for the value that starts at the normalizer cursor.
///
/// Staleness is unrepresentable rather than merely avoided: every offset is
/// relative to `cursor`, `GeminiStreamNormalizer::set_cursor` drops the memo the
/// instant the cursor moves (including whitespace skips, array punctuation, and
/// consuming a completed value), `clear_buffer` resets it, and the only other
/// buffer mutations are appends at the end and a compaction that drains exactly
/// `cursor` bytes — neither of which changes the unread region or its offsets.
/// So `cursor + scanned <= buf.len()` always holds and the memo can only ever
/// describe still-unread bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JsonScanMemo {
    /// Nothing scanned yet for the value starting at the cursor.
    Fresh,
    /// Partial scan; resume without re-reading already-scanned bytes.
    Partial(JsonValueScan),
    /// These bytes can never complete a top-level JSON value.
    Invalid,
}

/// Outcome of one incremental scan pass.
enum JsonScanStep {
    /// One complete value ends this many bytes after the value start.
    Complete(usize),
    /// More bytes are needed; resume from the carried state.
    Partial(JsonValueScan),
    /// Not a JSON object/array, or a structural close below depth 0.
    Invalid,
}

/// Advance the scan for one complete top-level JSON value at `buf[0]`.
///
/// Resuming from `resume` is byte-for-byte equivalent to scanning `buf` from
/// zero: the scanner is a left-to-right DFA over `(depth, in_string, escape)`,
/// and the "must open with `{`/`[`" admission check runs exactly once, on the
/// fresh pass.
fn scan_json_value(buf: &[u8], resume: JsonValueScan) -> JsonScanStep {
    let mut state = resume;
    if state.scanned == 0 {
        match buf.iter().find(|b| !b.is_ascii_whitespace()).copied() {
            // Nothing structural yet; re-admit on the next pass.
            None => return JsonScanStep::Partial(state),
            Some(b'{' | b'[') => {}
            Some(_) => return JsonScanStep::Invalid,
        }
    }
    let start = state.scanned.min(buf.len());
    for (rel, &b) in buf[start..].iter().enumerate() {
        if state.in_string {
            if state.escape {
                state.escape = false;
                continue;
            }
            match b {
                b'\\' => state.escape = true,
                b'"' => state.in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => state.in_string = true,
            b'{' | b'[' => state.depth = state.depth.saturating_add(1),
            b'}' | b']' => {
                if state.depth == 0 {
                    return JsonScanStep::Invalid;
                }
                state.depth -= 1;
                if state.depth == 0 {
                    return JsonScanStep::Complete(start + rel + 1);
                }
            }
            _ => {}
        }
    }
    state.scanned = buf.len();
    JsonScanStep::Partial(state)
}

/// Decode residual provider content-coding chains, then feed plaintext into
/// the Anthropic/Gemini→OpenAI normalizer. Because a compressed stream's
/// checksum/trailer is not trustworthy until EOF — and intermediate layers of a
/// stacked list cannot be validated until the outer coding is complete — this
/// rare fallback buffers the encoded body within a strict cap before decoding
/// in reverse application order. Encoded octets are never forwarded to the
/// client; decode/limit failures emit an upstream-error SSE frame. Normal
/// requests strip Accept-Encoding and retain fully progressive identity stream
/// normalization.
struct ContentDecodingNormalizer {
    /// Canonical `#content-coding` list in application order.
    encoding: String,
    encoded: Vec<u8>,
    inner: NormalizeEngine,
}

enum NormalizeEngine {
    Anthropic(AnthropicSseNormalizer),
    Gemini(GeminiStreamNormalizer),
}

impl NormalizeEngine {
    fn done_emitted(&self) -> bool {
        match self {
            Self::Anthropic(inner) => inner.done_emitted,
            Self::Gemini(inner) => inner.done_emitted,
        }
    }

    fn emit_upstream_error(&mut self, message: &str, out: &mut NormalizedSseOut) {
        match self {
            Self::Anthropic(inner) => inner.emit_upstream_error(message, out),
            Self::Gemini(inner) => inner.emit_upstream_error(message, out),
        }
    }

    fn finish_failure(&mut self, out: &mut NormalizedSseOut) {
        match self {
            Self::Anthropic(inner) => inner.finish(StreamTerminal::UpstreamFailure, out),
            Self::Gemini(inner) => inner.finish(StreamTerminal::UpstreamFailure, out),
        }
    }

    fn drive_chunk(&mut self, chunk: &[u8], out: &mut NormalizedSseOut) -> bool {
        match self {
            Self::Anthropic(inner) => inner.drive_chunk(chunk, out),
            Self::Gemini(inner) => inner.drive_chunk(chunk, out),
        }
    }

    fn drive_end(&mut self, out: &mut NormalizedSseOut) {
        match self {
            Self::Anthropic(inner) => inner.drive_end(out),
            Self::Gemini(inner) => inner.drive_end(out),
        }
    }

    async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction {
        match self {
            Self::Anthropic(inner) => inner.on_chunk(chunk).await,
            Self::Gemini(inner) => inner.on_chunk(chunk).await,
        }
    }

    async fn on_end(&mut self) -> ResponseStreamAction {
        match self {
            Self::Anthropic(inner) => inner.on_end().await,
            Self::Gemini(inner) => inner.on_end().await,
        }
    }
}

impl ContentDecodingNormalizer {
    fn new(encoding: String, inner: NormalizeEngine) -> Self {
        Self {
            encoding,
            encoded: Vec::new(),
            inner,
        }
    }

    async fn fail_decode(&mut self, message: String) -> ResponseStreamAction {
        let mut out = NormalizedSseOut::unbounded();
        out.begin_call();
        self.inner
            .emit_upstream_error(safe_residual_decode_diagnostic(&message), &mut out);
        self.inner.finish_failure(&mut out);
        ResponseStreamAction::Terminate(Some(Bytes::from(out.take_call_bytes())))
    }
}

#[async_trait]
impl ResponseStreamInspector for ContentDecodingNormalizer {
    fn stage(&self) -> ResponseStreamInspectorStage {
        ResponseStreamInspectorStage::Normalize
    }

    async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction {
        if self.inner.done_emitted() {
            return ResponseStreamAction::Terminate(None);
        }
        let Some(next_len) = self.encoded.len().checked_add(chunk.len()) else {
            return self
                .fail_decode("encoded provider stream size overflowed".to_string())
                .await;
        };
        // Cap the wire buffer at the aggregate decode budget so a hostile
        // provider cannot pin more than the shared residual-decode ceiling
        // before any layer runs.
        if next_len > NORMALIZE_DECODE_LIMITS.max_cumulative_bytes {
            return self
                .fail_decode("encoded provider stream exceeds the streaming size limit".to_string())
                .await;
        }
        self.encoded.extend_from_slice(chunk);
        // Hold encoded frames until EOF+decode succeeds — never serve opaque
        // provider octets as normalized AI output.
        ResponseStreamAction::Forward(Bytes::new())
    }

    async fn on_end(&mut self) -> ResponseStreamAction {
        if self.inner.done_emitted() {
            return ResponseStreamAction::Terminate(None);
        }
        let decoded = match prepare_sse_bytes_for_normalization(
            &self.encoded,
            Some(self.encoding.as_str()),
        ) {
            Ok(bytes) => bytes.into_owned(),
            Err(message) => return self.fail_decode(message).await,
        };
        // Encoded working set is spent; drop it before driving the plaintext
        // normalizer so peak retention is decode output + normalized SSE, not
        // also the original wire bytes.
        // `mem::take` drops the spent allocation immediately without asking
        // the allocator to shrink a buffer this terminal inspector will never
        // reuse.
        drop(std::mem::take(&mut self.encoded));
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

/// Fixed diagnostic for a buffered normalization whose OpenAI-shaped output no
/// longer fits this response's retained ceiling.
const BUFFERED_NORMALIZED_CEILING_MESSAGE: &str = "upstream provider stream normalization exceeded the retained response size limit; stream terminated";

/// Buffered provider→OpenAI SSE normalization, written into a
/// `ceiling`-bounded accumulator from the FIRST normalized byte
/// (GHSA-pwcm-6rh8-f2gh).
///
/// Always returns the replacement. When the normalized output cannot fit the
/// ceiling (OpenAI chunk envelopes are larger than Anthropic deltas, so a raw
/// body that fits can normalize past it), the partial output is discarded and
/// the bounded upstream-error terminal replaces it — never the raw provider
/// bytes, which could carry provider-native framing or a tool call the claim
/// forbids.
async fn normalize_provider_stream_buffered(
    provider_type: ProviderType,
    model: String,
    body: &[u8],
    tools_forbidden: bool,
    ceiling: usize,
    limits: NormalizeLimits,
) -> Vec<u8> {
    let mut engine = match provider_type {
        ProviderType::Anthropic => {
            NormalizeEngine::Anthropic(AnthropicSseNormalizer::new(model, tools_forbidden, limits))
        }
        ProviderType::GoogleGemini => {
            NormalizeEngine::Gemini(GeminiStreamNormalizer::new(model, tools_forbidden, limits))
        }
        ProviderType::OpenAi | ProviderType::OpenAiCompatible | ProviderType::AzureOpenAi => {
            // Unreachable: only normalizing providers reach the buffered
            // normalizer. Fail closed rather than leave the body in place.
            return bounded_upstream_sse_error_body(
                "internal error: non-normalizing provider requested a stream normalizer",
                ceiling,
            );
        }
    };
    let mut out = NormalizedSseOut::with_ceiling(ceiling);
    for slice in body.chunks(BUFFERED_NORMALIZE_CHUNK_BYTES) {
        if engine.done_emitted() {
            break;
        }
        let terminate = engine.drive_chunk(slice, &mut out);
        if out.refused() || terminate {
            break;
        }
    }
    if !out.refused() && !engine.done_emitted() {
        engine.drive_end(&mut out);
    }
    match out.finish() {
        Some(normalized) => normalized,
        None => bounded_upstream_sse_error_body(BUFFERED_NORMALIZED_CEILING_MESSAGE, ceiling),
    }
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

/// Whether `byte` can legally open an SSE line (a comment or a field name).
///
/// The event-stream grammar constrains a field name only to "not a colon and
/// not a line terminator", so `id:`, `retry:`, and any field a provider adds
/// later are all legal openers. Admitting exactly `d`, `e`, and `:` therefore
/// rejected ordinary Gemini streams that merely carried an `id:` or `retry:`
/// preamble (issue #5299). What still cannot appear at the head of a
/// `text/event-stream` document is a C0 control or DEL — that is the signal
/// that the provider sent binary or otherwise unframed bytes, so it remains the
/// unrecognized-framing case.
fn sse_line_may_start_with(byte: u8) -> bool {
    !byte.is_ascii_control()
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
    for line in sse_lines(text) {
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
        let mut normalizer =
            AnthropicSseNormalizer::new("claude-test".to_string(), false, NormalizeLimits::DEFAULT);
        let event = b"data: {\"type\":\"ping\"}\n\n";
        let mut out = NormalizedSseOut::unbounded();
        let iterations = 4_096usize;
        for _ in 0..iterations {
            out.begin_call();
            assert!(
                !normalizer.push_chunk(event, &mut out),
                "ping flood under event-count cap must not terminate"
            );
            out.reset_call();
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

    /// Payload whose structural bytes are deliberately hidden inside strings and
    /// escapes, so a scanner that resumed on an offset alone would misparse it.
    const TRICKY_JSON: &[u8] = br#"{"a":"}{\"x\":[1]","b":{"c":["\\","]"]},"d":"\u007b"}"#;

    #[test]
    fn json_value_scan_resume_matches_single_pass() {
        let fresh = JsonValueScan::default();
        let one_shot = match scan_json_value(TRICKY_JSON, fresh) {
            JsonScanStep::Complete(end) => end,
            _ => panic!("payload must complete in a single pass"),
        };
        assert_eq!(one_shot, TRICKY_JSON.len());

        // Every possible two-piece split resumes to the same answer.
        for split in 1..TRICKY_JSON.len() {
            let state = match scan_json_value(&TRICKY_JSON[..split], fresh) {
                JsonScanStep::Partial(state) => state,
                _ => panic!("prefix must be incomplete at split {split}"),
            };
            assert_eq!(state.scanned, split, "split {split} must memoize progress");
            match scan_json_value(TRICKY_JSON, state) {
                JsonScanStep::Complete(end) => assert_eq!(end, one_shot, "split {split}"),
                _ => panic!("resumed scan must complete at split {split}"),
            }
        }

        // Byte-at-a-time never rescans: each pass consumes exactly the new byte.
        let mut state = JsonValueScan::default();
        let mut completed = None;
        for take in 1..=TRICKY_JSON.len() {
            match scan_json_value(&TRICKY_JSON[..take], state) {
                JsonScanStep::Complete(end) => {
                    completed = Some(end);
                    break;
                }
                JsonScanStep::Partial(next) => {
                    assert_eq!(next.scanned, take, "scan must not rewind at {take}");
                    state = next;
                }
                JsonScanStep::Invalid => panic!("valid payload rejected at {take}"),
            }
        }
        assert_eq!(completed, Some(one_shot));
    }

    #[test]
    fn json_value_scan_rejects_non_container_and_structural_underflow() {
        let fresh = JsonValueScan::default();
        for hostile in [b"5".as_slice(), b"\"str\"".as_slice(), b"}".as_slice()] {
            assert!(matches!(
                scan_json_value(hostile, fresh),
                JsonScanStep::Invalid
            ));
        }
        // A resumed pass keeps the same structural verdict.
        let state = match scan_json_value(b"[1", fresh) {
            JsonScanStep::Partial(state) => state,
            _ => panic!("prefix must be incomplete"),
        };
        assert!(matches!(
            scan_json_value(b"[1]]", state),
            JsonScanStep::Complete(3)
        ));
    }

    /// The framing memo must advance with the buffer rather than restarting, and
    /// must never describe bytes outside the unread window.
    #[test]
    fn gemini_json_framing_memo_is_incremental_and_never_stale() {
        let mut normalizer =
            GeminiStreamNormalizer::new("gemini-test".to_string(), false, NormalizeLimits::DEFAULT);
        let event =
            br#"{"candidates":[{"index":0,"content":{"role":"model","parts":[{"text":"hi"}]}}]}"#;
        let mut out = NormalizedSseOut::unbounded();
        for (idx, byte) in event.iter().enumerate() {
            out.begin_call();
            assert!(
                !normalizer.push_chunk(&[*byte], &mut out),
                "partial value must not terminate at byte {idx}"
            );
            out.reset_call();
            if idx + 1 == event.len() {
                break;
            }
            match normalizer.json_scan {
                JsonScanMemo::Partial(state) => {
                    assert_eq!(
                        state.scanned,
                        normalizer.unread_len(),
                        "memo must cover exactly the unread window at byte {idx}"
                    );
                    assert!(
                        normalizer.cursor + state.scanned <= normalizer.buf.len(),
                        "memo must never point past the buffer at byte {idx}"
                    );
                }
                other => panic!("byte {idx} must memoize a partial scan: {other:?}"),
            }
        }
        // The completed value consumed the buffer and dropped the memo.
        assert_eq!(normalizer.json_scan, JsonScanMemo::Fresh);
        assert_eq!(normalizer.events_seen, 1);
        assert_eq!(normalizer.unread_len(), 0);
    }
}

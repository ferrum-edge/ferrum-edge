//! Request Mirror Plugin
//!
//! Duplicates live proxy traffic to a secondary destination for shadow testing,
//! validation, or migration checks without affecting client responses. Mirrored
//! requests are fire-and-forget — the gateway does not wait for the mirror
//! target's response and never propagates mirror failures to the client.
//!
//! Similar to APISIX's `proxy-mirror` plugin.
//!
//! ## How it works
//!
//! During the finalized-request-egress phase — after request-body transforms and
//! after every `on_final_request_body` policy hook has accepted the
//! backend-visible representation (advisory `GHSA-4vr5-4wm3-x5xv`) — the plugin
//! captures the request method, path, query string, headers, and optionally the
//! body, then spawns an async task to replay the request against the configured
//! mirror destination. The main request proceeds immediately — mirror latency
//! has zero impact on client response time. A request rejected by final
//! request-body policy is therefore never mirrored, and the shadow destination
//! never sees a field an operator configured `request_transformer` to remove or
//! redact. Later backend-admission or transport failures can still occur after
//! mirror dispatch.
//!
//! Multiple independent `request_mirror` instances on one proxy each dispatch
//! and each push their own result receiver onto a per-request collection. A
//! later instance never overwrites an earlier one. Transaction logging emits
//! one `mirror: true` summary per dispatched instance, attributable by plugin
//! config id and query-stripped destination URL. Sampled-out work leaves no
//! record; concurrency-limit rejection still publishes an explicit per-instance
//! failure (preserving prior observability).
//!
//! Outbound mirror headers cross the same canonical secondary-request boundary
//! as primary backend dispatch (Connection-listed hop-by-hop, Trailer, framing,
//! Ferrum request-only markers, and proxy-owned `X-Forwarded-*`). Forwarding
//! identity is stripped rather than regenerated. Off-mesh mirrors omit client
//! `Host` so authority comes from the mirror URL. When `mesh_route_dispatch`
//! has already matched the request, the mirror instead applies Istio/Envoy
//! shadow Host/:authority semantics: dial and validate the configured mirror
//! destination, but set Host to a protocol-valid shadow authority — DNS
//! hostnames receive a `-shadow` suffix before any port, while IPv4 and
//! bracketed IPv6 literals keep their literal form (suffixing would yield an
//! invalid Host). Cross-origin credential forwarding is deny-by-default: any
//! header whose lowercased name is a built-in credential (`Authorization`,
//! `Cookie`, `Proxy-Authorization`, `Proxy-Authenticate`, `WWW-Authenticate`,
//! `X-Api-Key`, …),
//! contains a built-in credential substring (so vendor variants like
//! `x-openai-api-key`, `x-amz-security-token`, `x-vendor-auth-token` are also
//! caught), or matches an operator `sensitive_header_patterns` entry is stripped
//! before the distinct mirror origin. Because native gRPC metadata is carried as
//! HTTP/2 headers, the same predicate covers gRPC credential metadata. Forwarding
//! any denied header requires the high-friction, fail-closed pair
//! `forward_sensitive_headers=true` plus an exact-name
//! `forward_sensitive_header_allowlist`. Native gRPC content-types
//! re-synthesise `te: trailers` for HTTP/2-capable mirror targets. Native gRPC
//! mirrors dial through `PluginHttpClient::get_http2` (h2c prior knowledge for
//! cleartext `http` targets, ALPN `h2` for `https`); ordinary HTTP mirrors keep
//! the default all-version client so HTTP/1.1 destinations continue to work.
//! The request-target prefers the canonical backend-visible query (transformer
//! outbound query when present, otherwise the original raw query, after the
//! same auth credential strips the primary backend uses) so duplicate keys,
//! order, flags, `+`, percent escapes, and encoded bytes match the primary
//! contract.
//!
//! Path selection precedence when building the mirror URL:
//! 1. explicit plugin `mirror_path` (operator override; wins)
//! 2. else mesh `route_override_path` when set (final selected/rebased URI;
//!    read without consuming the override primary dispatch still needs)
//! 3. else the backend-effective authorized path when backend-path policy is
//!    active
//! 4. else the original request path
//!
//! The mirror request uses the gateway's shared `PluginHttpClient`, which means
//! it inherits the gateway's DNS cache, connection pool keepalive, TLS
//! settings (CA bundle, skip-verify), egress screening, and redacted logging.
//!
//! ## Mirror response logging
//!
//! The spawned task captures mirror response metadata (status code, response
//! size, latency) and writes it to a `tokio::sync::watch` channel. Transaction
//! logging consumes that channel from a separate detached task for the mirror
//! task's full configured lifetime, so late results remain visible without
//! delaying the client response. The channel is seeded with a sanitized task
//! failure fallback; concurrency drops are published as completed failures.
//!
//! Alongside the per-event summary, each instance keeps bounded-lifetime
//! `AtomicU64` counters (`MirrorMetrics`) for the mirror lifecycle — dispatched,
//! completed, request/drain timeouts, request/drain failures, drain truncations,
//! cancellations, and concurrency/byte-budget drops. A cancellation (runtime
//! shutdown, panic, or future cancellation before a terminal outcome) is counted
//! via a drop guard, so a stalled/cancelled mirror is never silently invisible.
//! Counters are pure tallies (no header names, URLs, plugin IDs, or credential
//! material) and dual-write into Ferrum's process-wide authenticated Prometheus
//! registry (`ferrum_request_mirror_*_total`). Per-instance values reset on
//! config reload; the Prometheus series remain monotonic for the process.
//! Mirror *transaction summaries* stay excluded from request/billing histograms —
//! that exclusion does not apply to these label-safe lifecycle counters.
//!
//! Mirror timeout prefers an optional plugin `mirror_timeout_ms`, else the
//! matched proxy's `backend_read_timeout_ms` when positive, else a finite
//! 60s default, always capped by a hard maximum. A zero primary
//! `backend_read_timeout_ms` therefore never disables the mirror deadline.
//! Mirror response bodies are always drained under `max_response_body_bytes`
//! and a short drain timeout so HTTP/1.1 keep-alive pools can reclaim sockets
//! even when `Content-Length` is advertised. A finalized body is copied once
//! into an owned `bytes::Bytes` for each selected mirror instance; that
//! detached-task copy is admitted under both `max_in_flight` and a per-instance
//! `max_retained_request_body_bytes` budget, and its lease releases when the
//! task ends.
//!
//! ## Pre-buffer admission (advisory `GHSA-jv66-mq44-m9v3`)
//!
//! Mirroring a request body is the only reason this plugin makes the gateway
//! collect one, so every reason NOT to mirror is evaluated *before* the body is
//! read:
//!
//! 1. **Deterministic disablement at construction.** `mirror_request_body:
//!    false` or a `percentage` that quantizes to threshold `0` clears the body
//!    capabilities outright (`RequestMirror::body_admission_enabled`). The
//!    plugin cache's config-time upper bound then never marks the proxy as
//!    needing a request-body buffer for this instance, so no per-request work
//!    happens at all.
//! 2. **Sampling and bounded admission in the `authorize` phase.** For a
//!    body-mirroring instance, the plugin's `authorize` hook advances the
//!    deterministic sampler once and, when the request is selected, acquires
//!    the `max_in_flight` permit and reserves retained bytes from the aggregate
//!    budget. A sampled-out or refused request stages a non-admitting decision
//!    and keeps streaming — nothing is buffered, copied, or retained. The
//!    built-in priority places this after the built-in rejecting authorization
//!    hooks. Even when an operator priority override or custom plugin runs a
//!    rejecting hook later, the proxy does not collect the body until the
//!    complete authorization phase succeeds; rejection drops the staged permit
//!    and reservation without reading the upload.
//! 3. **Per-request buffering follows admission.** `should_buffer_request_body`
//!    is a pure read of that staged decision (it is evaluated several times per
//!    request), so only admitted requests buffer.
//! 4. **A positive plugin-local ceiling.** `max_mirrored_request_body_bytes`
//!    bounds a single mirrored body even when the global
//!    `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` is configured as `0` (unlimited).
//!    A request that already declares more than the ceiling is skipped before
//!    sampling: it keeps streaming and is not mirrored, rather than truncating
//!    the shadow payload or turning shadow policy into a client-visible `413`.
//!    Otherwise every admitted request reserves the whole positive plugin-local
//!    ceiling before collection — regardless of method, protocol, missing or
//!    present `Content-Length`, or a declared zero/small length. Declared size
//!    is untrusted for aggregate accounting: H3 drains under the collection
//!    ceiling without enforcing equality with `Content-Length`, and Hyper's H2
//!    `Incoming` length is likewise not the Ferrum allocation bound. Charging
//!    only an attacker-declared byte would let many concurrent tiny declarations
//!    each allocate up to the ceiling before finalized-egress reconciliation,
//!    exceeding `max_retained_request_body_bytes`. Finalized request egress then
//!    reconciles the reservation to the observed length, returning the surplus
//!    (down to `0` for an empty body) to the aggregate budget exactly once. The
//!    tradeoff: mirroring mostly-bodyless traffic at high concurrency wants
//!    `max_retained_request_body_bytes` sized against `max_in_flight ×
//!    max_mirrored_request_body_bytes`, or a lower ceiling.
//!    An undeclared (chunked) body larger than the ceiling is still rejected by
//!    the combined request-body limit — raise `max_mirrored_request_body_bytes`
//!    when mirroring routes that accept larger streamed uploads. That combined
//!    limit is checked against the *collected* body, and a buffered-body
//!    normalizer (configured request decompression) runs afterwards, so an
//!    inflated buffer can still land above the ceiling; such a request is
//!    refused rather than truncated, and its `mirror_error` names the ceiling
//!    instead of the aggregate budget.
//!
//! The permit and the byte reservation are owned values held across body
//! buffering, dispatch, and the detached task. Every exit — client
//! cancellation, a body read error, a later plugin rejection, a mirror request
//! timeout, a drain failure, or ordinary completion — drops them exactly once,
//! so admission can neither leak nor double-release. A request claimed by
//! `ai_stream_router` after admission releases both immediately and dispatches
//! nothing; it does consume a sampling slot.
//!
//! ## Configuration
//!
//! ```json
//! {
//!   "mirror_host": "mirror.example.com",
//!   "mirror_port": 8080,
//!   "mirror_protocol": "https",
//!   "mirror_path": "/shadow",
//!   "percentage": 100.0,
//!   "mirror_request_body": true,
//!   "max_response_body_bytes": 1048576
//! }
//! ```
//!
//! | Field | Type | Default | Description |
//! |-------|------|---------|-------------|
//! | `mirror_host` | string | **(required)** | Hostname or IP of the mirror target |
//! | `mirror_port` | u16 | 80 (http) / 443 (https) | Port of the mirror target |
//! | `mirror_protocol` | string | `"http"` | `"http"` or `"https"` |
//! | `mirror_path` | string | (none) | Override the request path for the mirror. Must start with `/` and cannot contain a query or fragment. When unset, prefers the mesh route rewrite path when present; otherwise the backend-effective authorized path if backend-path policy is active; otherwise the original request path |
//! | `percentage` | f64 | `100.0` | Percentage of requests to mirror (0.0–100.0). Deterministic evenly spaced sampling at 0.1% granularity (see sampling notes below) |
//! | `mirror_request_body` | bool | `true` | Whether to include the request body in the mirror request |
//! | `max_response_body_bytes` | u64 | `1048576` (1 MiB) | Cap on bytes drained from every mirror response (with or without `Content-Length`). Streaming aborts as soon as the limit is crossed; bytes are discarded after sizing so keep-alive pools can reclaim the socket. |
//! | `max_in_flight` | u64 | `256` | Maximum concurrent detached mirror tasks per plugin instance (minimum 1, maximum 1048576). Requests that arrive while every permit is in use are still served normally but are not mirrored — saturation drops the new mirror attempt without affecting the primary request. Values above the cap are rejected at construction rather than panicking Tokio's semaphore. |
//! | `max_retained_request_body_bytes` | u64 | `67108864` (64 MiB) | Aggregate retained request-body budget for in-flight mirrors on this instance. Charged at admission (before the body is read: every admitted request reserves the whole `max_mirrored_request_body_bytes` ceiling) and reconciled to the observed length; exhaustion drops the new mirror attempt without affecting the primary request. Size against `max_in_flight × max_mirrored_request_body_bytes` when mirroring at high concurrency. |
//! | `max_mirrored_request_body_bytes` | u64 | `10485760` (10 MiB) | Positive plugin-local ceiling on one mirrored request body, applied even when the global request-body limit is unlimited (`0`). An explicit value above `max_retained_request_body_bytes` is rejected at construction; the default clamps down to it instead, so a smaller aggregate budget alone never fails construction. Applies only to requests this instance admitted. |
//! | `mirror_timeout_ms` | u64 | (proxy / 60000) | Finite mirror request deadline in milliseconds (minimum 1, maximum 300000). When omitted, uses the matched proxy `backend_read_timeout_ms` when positive, otherwise 60000. Zero primary timeout never disables this deadline. |
//! | `forward_sensitive_headers` | bool | `false` | Dangerous opt-in. When `true`, selected origin-bound credential headers may cross to the mirror origin, but only exact names listed in `forward_sensitive_header_allowlist` (fail-closed: both fields required together, allowlist must be non-empty). |
//! | `forward_sensitive_header_allowlist` | string[] | `[]` | Lowercased exact allowlist of denied sensitive header names to forward when `forward_sensitive_headers` is `true`. Each entry must be a valid HTTP header name (≤256 chars) that the deny-by-default policy actually strips (a built-in credential or a `sensitive_header_patterns` match); at most 64 entries; non-sensitive names are rejected at construction. |
//! | `sensitive_header_patterns` | string[] | `[]` | Additional lowercased substrings (matched against the header name; each ≤128 chars, at most 64 entries) that extend the built-in deny-by-default credential set. Covers HTTP headers and native gRPC metadata. |
//!
//! ## Percentage sampling
//!
//! Sampling is **deterministic and evenly spaced** (Bresenham / dithered
//! accumulator), not randomized and not a contiguous prefix of each 1,000-request
//! window. Configuration is quantized to tenths of a percent: the effective
//! threshold is `round(percentage × 10)` clamped to `0..=1000`.
//!
//! Selection is evaluated once per eligible request, in the `authorize` phase
//! for body-mirroring instances (so a sampled-out request never buffers) and in
//! finalized request egress otherwise. Either way each eligible request
//! advances the phase exactly once.
//!
//! - `0%` (threshold 0) never selects; the phase accumulator is not advanced.
//! - `100%` (threshold 1000) always selects; the phase accumulator is not advanced.
//! - Otherwise each eligible request adds `threshold` to a phase in `0..1000`.
//!   When the sum reaches or exceeds `1000`, that request is mirrored and the
//!   phase wraps by subtracting `1000`. Every complete 1,000-request cycle
//!   therefore mirrors exactly `threshold` requests, spaced with gaps of
//!   `floor(1000/threshold)` or `ceil(1000/threshold)`.
//!
//! **Construction / reload:** each plugin instance starts with phase `0`. The
//! first selection is deferred until the accumulator crosses `1000`, so reload
//! does not reopen with a mirrored burst/prefix. Recreating the plugin (config
//! reload) resets the phase to `0`.
//!
//! **Concurrency:** selection uses a single `AtomicU64` phase with a lock-free
//! compare-exchange update (relaxed ordering). No per-request allocation, RNG,
//! formatting, or mutex. The sampler guarantees system-wide progress under
//! contention; an individual caller may retry after a competing update.
//!
//! **Wrap / exhaustion:** the phase is bounded to `0..1000` at every successful
//! update, so integer wraparound of an unbounded counter cannot occur, cannot
//! panic, and cannot bias a complete sampling cycle.

use async_trait::async_trait;
use bytes::Bytes;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::warn;
use url::{Host, form_urlencoded};

use super::load_testing::{HEADER_FANOUT, HEADER_TRIGGER_KEY};
use super::utils::response_body::{
    BoundedReadError, measure_response_body_bounded, parse_max_response_body_bytes,
};
use super::{MirrorResponseMeta, Plugin, PluginHttpClient, PluginResult, RequestContext};
use crate::proxy::headers::{
    SecondaryRequestHostPolicy, filter_secondary_request_headers,
    synthesize_grpc_te_trailers_if_needed,
};
use crate::util::unknown_keys::suggest_key;

/// Authoritative closed set of top-level `request_mirror` configuration keys.
///
/// Constructor admission, OpenAPI `RequestMirrorConfig`, and operator docs must
/// stay in lockstep with this list so misspelled sampling, body, protocol, or
/// endpoint controls cannot silently fall back to security-sensitive defaults.
pub const REQUEST_MIRROR_CONFIG_KEYS: &[&str] = &[
    "forward_sensitive_header_allowlist",
    "forward_sensitive_headers",
    "max_in_flight",
    "max_mirrored_request_body_bytes",
    "max_response_body_bytes",
    "max_retained_request_body_bytes",
    "mirror_host",
    "mirror_path",
    "mirror_port",
    "mirror_protocol",
    "mirror_request_body",
    "mirror_timeout_ms",
    "percentage",
    "sensitive_header_patterns",
];

/// Default cap on the size of mirror response bodies the gateway is willing
/// to drain. The body is discarded — only its length is reported in mirror
/// metadata — so 1 MiB is plenty for the size-derivation use case while still
/// protecting against a misbehaving mirror endpoint streaming an unbounded
/// response over a fire-and-forget task.
const DEFAULT_MIRROR_MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_IN_FLIGHT_MIRRORS: usize = 256;
/// Deployment-safe hard ceiling on `max_in_flight`. This is deliberately far
/// below `tokio::sync::Semaphore::MAX_PERMITS` (`usize::MAX >> 3`): a config
/// value between this cap and `MAX_PERMITS` still fits `usize` and passes the
/// nonzero check, but would panic inside `Semaphore::new`. Rejecting above this
/// bound turns an unreasonable value into an ordinary validation error instead
/// of a process/admission crash. 2^20 concurrent detached mirror tasks per
/// instance is already far beyond any real deployment.
const MAX_MAX_IN_FLIGHT_MIRRORS: usize = 1 << 20;
/// Per-instance retained request-body budget for detached mirror tasks.
const DEFAULT_MAX_RETAINED_REQUEST_BODY_BYTES: u64 = 64 * 1024 * 1024;
/// Plugin-local per-request ceiling on a mirrored request body.
///
/// Mirroring a body is the only reason this plugin forces the gateway to
/// collect one, so it must carry its own positive ceiling: the global
/// `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` can be configured as `0` (unlimited),
/// which would otherwise let one mirrored upload buffer without bound
/// (advisory `GHSA-jv66-mq44-m9v3`). 10 MiB matches the global default, so the
/// ceiling is a no-op on a default deployment and only bites when the operator
/// removed or raised the global bound.
const DEFAULT_MAX_MIRRORED_REQUEST_BODY_BYTES: u64 = 10 * 1024 * 1024;
/// Finite mirror deadline when the proxy has no positive read timeout.
const DEFAULT_MIRROR_TIMEOUT_MS: u64 = 60_000;
/// Hard ceiling on every mirror request deadline (plugin or proxy derived).
const MAX_MIRROR_TIMEOUT_MS: u64 = 300_000;
/// Bound on post-header body discard so a slow CL body cannot pin the task
/// for the full request budget after headers arrive.
const MIRROR_RESPONSE_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
const MIRROR_TASK_INCOMPLETE_ERROR: &str =
    "mirror task ended before publishing a result (cancelled or failed)";
const MIRROR_CONCURRENCY_DROP_ERROR: &str =
    "mirror request dropped because max_in_flight limit was reached";
const MIRROR_BODY_BUDGET_DROP_ERROR: &str =
    "mirror request dropped because max_retained_request_body_bytes budget was exhausted";
/// Distinct from [`MIRROR_BODY_BUDGET_DROP_ERROR`]: the aggregate budget had
/// room, but the collected body exceeded this instance's per-request ceiling.
/// Reachable when a buffered-body normalizer (configured request decompression)
/// inflates the stored buffer after the proxy's combined request-body limit
/// already accepted the collected bytes. Naming the aggregate budget here would
/// send the operator to a knob that cannot fix it.
const MIRROR_BODY_CEILING_DROP_ERROR: &str =
    "mirror request dropped because the collected body exceeded max_mirrored_request_body_bytes";
const MIRROR_DRAIN_TIMEOUT_ERROR: &str = "mirror response body drain timed out";
const MIRROR_DRAIN_TRANSPORT_ERROR: &str = "mirror response body stream failed";

/// Hard ceiling on operator `sensitive_header_patterns` entries so an admitted
/// config cannot create unbounded per-request substring scans or retained
/// config memory.
const MAX_SENSITIVE_HEADER_PATTERNS: usize = 64;
/// Maximum UTF-8 byte length of one `sensitive_header_patterns` entry.
const MAX_SENSITIVE_HEADER_PATTERN_LEN: usize = 128;
/// Hard ceiling on `forward_sensitive_header_allowlist` entries.
const MAX_FORWARD_SENSITIVE_ALLOWLIST: usize = 64;
/// Maximum UTF-8 byte length of one allowlist header name.
const MAX_FORWARD_SENSITIVE_ALLOWLIST_ITEM_LEN: usize = 256;

/// Well-known origin-bound credential / session header names stripped from
/// cross-origin mirror requests unless an explicit fail-closed allowlist opts
/// in. Most are also matched by [`MIRROR_SENSITIVE_HEADER_SUBSTRINGS`]; the
/// exact list is retained as a self-documenting inventory of standard
/// credentials (including challenge headers such as `WWW-Authenticate` /
/// `Proxy-Authenticate` that may appear on secondary requests).
const MIRROR_SENSITIVE_HEADER_NAMES: &[&str] = &[
    "authorization",
    "cookie",
    "cookie2",
    "proxy-authorization",
    "proxy-authenticate",
    "www-authenticate",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
];

/// Built-in credential/session substrings applied to lowercased header names so
/// vendor-prefixed variants (`x-openai-api-key`, `x-amz-security-token`,
/// `x-vendor-auth-token`) are stripped without an exact-name allowlist. Chosen
/// to match credential families only: bare `token`/`key`/`session`/`auth`
/// substrings are deliberately excluded because they also match benign headers
/// such as pagination cursors (`x-continuation-token`). `authenticate` is
/// included so `Proxy-Authenticate` / `WWW-Authenticate` variants are covered
/// without a bare `auth` match. Operators extend this with
/// `sensitive_header_patterns`. gRPC metadata is carried as HTTP/2 headers,
/// so the same predicate covers native gRPC credential metadata.
const MIRROR_SENSITIVE_HEADER_SUBSTRINGS: &[&str] = &[
    "authorization",
    "cookie",
    "authenticate",
    "api-key",
    "apikey",
    "api_key",
    "auth-token",
    "access-token",
    "refresh-token",
    "id-token",
    "session-token",
    "security-token",
    "csrf",
    "xsrf",
    "bearer",
    "password",
    "passwd",
    "secret",
    "credential",
];

/// Sampling period for percentage decisions: threshold is tenths of a percent
/// in `0..=SAMPLE_PERIOD`, so each complete cycle of `SAMPLE_PERIOD` requests
/// mirrors exactly `threshold` of them when `0 < threshold < SAMPLE_PERIOD`.
const SAMPLE_PERIOD: u64 = 1000;

fn strip_query_params(url: &str) -> &str {
    url.split_once('?').map_or(url, |(base, _)| base)
}

fn mirror_failure_meta(
    plugin_id: Option<String>,
    target_url: String,
    error: &'static str,
) -> MirrorResponseMeta {
    MirrorResponseMeta {
        mirror_plugin_id: plugin_id,
        mirror_target_url: target_url,
        mirror_response_status_code: None,
        mirror_response_size_bytes: None,
        mirror_response_advertised_size_bytes: None,
        mirror_latency_ms: 0.0,
        mirror_error: Some(error.to_string()),
    }
}

fn is_numeric_port(port: &str) -> bool {
    !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_port_suffix(rest: &str) -> bool {
    matches!(rest.strip_prefix(':'), Some(port) if is_numeric_port(port))
}

/// Deny-by-default sensitivity test for a lowercased header name. A header is
/// sensitive if it is a well-known credential name, contains a built-in
/// credential substring, or contains any operator-configured
/// `sensitive_header_patterns` substring.
fn is_mirror_sensitive_header(name_lower: &str, operator_patterns: &[String]) -> bool {
    MIRROR_SENSITIVE_HEADER_NAMES.contains(&name_lower)
        || MIRROR_SENSITIVE_HEADER_SUBSTRINGS
            .iter()
            .any(|substr| name_lower.contains(substr))
        || operator_patterns
            .iter()
            .any(|pattern| name_lower.contains(pattern.as_str()))
}

/// Append Envoy/Istio's `-shadow` suffix to a Host/:authority value when the
/// host portion is a DNS name.
///
/// Matches Envoy's documented shadowing behavior for hostnames (`cluster1` →
/// `cluster1-shadow`, `internal.example:8080` → `internal.example-shadow:8080`).
/// IPv4 literals and bracketed IPv6 authorities (with or without a port) are
/// left unchanged: appending `-shadow` after a closing bracket or onto a dotted
/// quad produces a protocol-invalid Host. Malformed authorities are returned
/// unchanged rather than rewritten into a different invalid form.
pub(crate) fn append_shadow_host_suffix(authority: &str) -> String {
    let authority = authority.trim();
    if authority.is_empty() {
        return String::new();
    }

    if authority.starts_with('[') {
        let Some(close) = authority.find(']') else {
            return authority.to_string();
        };
        let inner = &authority[1..close];
        let rest = &authority[close + 1..];
        if inner.parse::<std::net::Ipv6Addr>().is_ok() && (rest.is_empty() || is_port_suffix(rest))
        {
            // Bracketed IPv6 (+ optional port): keep a valid authority as-is.
            return authority.to_string();
        }
        return authority.to_string();
    }

    if let Some((host, port)) = authority.rsplit_once(':')
        && !host.is_empty()
        && !host.contains(':')
        && is_numeric_port(port)
    {
        if host.parse::<std::net::Ipv4Addr>().is_ok() {
            return authority.to_string();
        }
        let mut shadow = String::with_capacity(authority.len() + "-shadow".len());
        shadow.push_str(host);
        shadow.push_str("-shadow");
        shadow.push(':');
        shadow.push_str(port);
        return shadow;
    }

    if authority.parse::<std::net::Ipv4Addr>().is_ok() {
        return authority.to_string();
    }
    // Unbracketed IPv6 (or other multi-colon forms) cannot receive a DNS suffix
    // without becoming an invalid authority.
    if authority.bytes().filter(|b| *b == b':').count() >= 2 {
        return authority.to_string();
    }

    let mut shadow = String::with_capacity(authority.len() + "-shadow".len());
    shadow.push_str(authority);
    shadow.push_str("-shadow");
    shadow
}

/// Resolve the finite mirror request deadline in milliseconds.
///
/// Preference: explicit plugin `mirror_timeout_ms` → positive proxy
/// `backend_read_timeout_ms` → [`DEFAULT_MIRROR_TIMEOUT_MS`]. Every path is
/// clamped to [`MAX_MIRROR_TIMEOUT_MS`].
pub(crate) fn resolve_mirror_timeout_ms(
    configured_mirror_timeout_ms: Option<u64>,
    backend_read_timeout_ms: Option<u64>,
) -> u64 {
    let raw = configured_mirror_timeout_ms
        .or_else(|| backend_read_timeout_ms.filter(|ms| *ms > 0))
        .unwrap_or(DEFAULT_MIRROR_TIMEOUT_MS);
    raw.clamp(1, MAX_MIRROR_TIMEOUT_MS)
}

/// Strip origin-bound credentials before a distinct mirror origin. Deny by
/// default: a sensitive header survives only when `forward_sensitive_headers`
/// is set and the exact lowercased name is in the fail-closed allowlist.
fn apply_mirror_credential_policy(
    headers: &mut Vec<(String, String)>,
    forward_sensitive_headers: bool,
    allowlist: &[String],
    operator_patterns: &[String],
) {
    headers.retain(|(name, _)| {
        let lower = name.to_ascii_lowercase();
        if !is_mirror_sensitive_header(&lower, operator_patterns) {
            return true;
        }
        forward_sensitive_headers && allowlist.iter().any(|allowed| allowed == &lower)
    });
}

#[derive(Debug)]
struct MirrorBodyBudget {
    used: AtomicU64,
    max_bytes: u64,
}

impl MirrorBodyBudget {
    fn new(max_bytes: u64) -> Arc<Self> {
        Arc::new(Self {
            used: AtomicU64::new(0),
            max_bytes,
        })
    }

    /// Reserve `bytes` of the aggregate retained-body budget, returning a lease
    /// that releases the reservation exactly once when dropped.
    ///
    /// Reservation happens BEFORE the body is collected (advisory
    /// `GHSA-jv66-mq44-m9v3`), so callers reserve the worst case they can be
    /// forced to retain — the full plugin-local per-request ceiling for every
    /// admitted request. Declared `Content-Length` is never trusted for this
    /// charge. [`MirrorBodyLease::reconcile`] shrinks the lease to the observed
    /// length once the body exists.
    fn try_reserve(self: &Arc<Self>, bytes: u64) -> Option<MirrorBodyLease> {
        if !self.try_add(bytes) {
            return None;
        }
        Some(MirrorBodyLease {
            reserved: bytes,
            budget: Arc::clone(self),
        })
    }

    /// Lock-free bounded add. Returns `false` without mutating when the budget
    /// cannot cover `bytes`.
    ///
    /// `max_bytes` is operator-configurable across the whole `u64` range, so the
    /// candidate total is computed with `checked_add` and the *same* value is
    /// both compared and published. A saturating comparison would let
    /// `used + bytes` wrap past a `u64::MAX` ceiling (silently in release,
    /// panicking in debug) and hand out capacity the budget does not have;
    /// arithmetic overflow is itself an exhausted budget and fails closed.
    fn try_add(&self, bytes: u64) -> bool {
        if bytes == 0 {
            return true;
        }
        let mut current = self.used.load(Ordering::Relaxed);
        loop {
            let Some(candidate) = current.checked_add(bytes) else {
                return false;
            };
            if candidate > self.max_bytes {
                return false;
            }
            match self.used.compare_exchange_weak(
                current,
                candidate,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    /// Return `bytes` to the budget.
    ///
    /// Leases release exactly what they hold exactly once, so this never
    /// underflows in practice. An invariant violation leaves the charge in
    /// place: under-accounting would reopen the memory cap, while wrapping
    /// would panic in debug or wedge the budget in release.
    fn release(&self, bytes: u64) {
        if bytes > 0
            && let Err(current) =
                self.used
                    .fetch_update(Ordering::SeqCst, Ordering::Relaxed, |current| {
                        current.checked_sub(bytes)
                    })
        {
            warn!(
                current,
                release_bytes = bytes,
                "request_mirror retained-body budget release underflow refused"
            );
        }
    }

    fn used_for_test(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }
}

/// Owning claim on a slice of the aggregate retained-body budget.
///
/// Held from pre-buffer admission (`authorize`) through body collection,
/// dispatch, and the detached task's terminal outcome. Dropping the lease —
/// on client cancellation, a body read error, a plugin rejection before
/// finalized request egress, a mirror timeout, or ordinary task completion —
/// releases the reservation exactly once.
struct MirrorBodyLease {
    reserved: u64,
    budget: Arc<MirrorBodyBudget>,
}

impl MirrorBodyLease {
    /// Resize the reservation to the observed body length.
    ///
    /// Shrinking always succeeds and returns the surplus immediately. Growing
    /// (possible on the rare fallback path that reserved less than the observed
    /// body) is bounded by the same budget and returns `false` when it cannot
    /// be covered, so the mirror attempt is dropped instead of retaining
    /// unbudgeted bytes. Pre-buffer admission always reserves the full ceiling,
    /// so the authorize → finalized-egress path only shrinks.
    fn reconcile(&mut self, actual: u64) -> bool {
        if actual == self.reserved {
            return true;
        }
        if actual < self.reserved {
            self.budget.release(self.reserved - actual);
            self.reserved = actual;
            return true;
        }
        if !self.budget.try_add(actual - self.reserved) {
            return false;
        }
        self.reserved = actual;
        true
    }
}

impl Drop for MirrorBodyLease {
    fn drop(&mut self) {
        self.budget.release(self.reserved);
    }
}

/// Pre-buffer admission decision for one `request_mirror` instance on one
/// request, staged by the `authorize` phase and consumed by finalized request
/// egress.
pub(crate) struct RequestMirrorAdmission {
    instance_id: u64,
    state: MirrorAdmissionState,
}

enum MirrorAdmissionState {
    /// The deterministic sampler did not select this request. No body is
    /// buffered and no observability record is emitted (existing contract).
    NotSelected,
    /// Selected, and both a concurrency permit and a retained-byte reservation
    /// were acquired before any body was read.
    Admitted {
        permit: tokio::sync::OwnedSemaphorePermit,
        lease: MirrorBodyLease,
    },
    /// Selected but refused by `max_in_flight` or the aggregate byte budget.
    /// The request stays streaming; finalized request egress publishes the
    /// attributable failure summary once the mirror target URL is known.
    Dropped(&'static str),
    /// Finalized request egress already took this instance's decision and now
    /// owns (or has released) the lease. The tombstone prevents any duplicate
    /// phase invocation from sampling, acquiring capacity, or dispatching a
    /// second shadow request.
    Consumed { admitted: bool },
}

impl RequestMirrorAdmission {
    pub(crate) fn instance_id(&self) -> u64 {
        self.instance_id
    }

    /// Whether this instance forced a request-body buffer for this request.
    /// Stays `true` after finalized request egress consumes the lease so the
    /// predicate remains stable for the whole request.
    pub(crate) fn is_admitted(&self) -> bool {
        matches!(
            self.state,
            MirrorAdmissionState::Admitted { .. }
                | MirrorAdmissionState::Consumed { admitted: true }
        )
    }
}

/// Staged `request_mirror` admissions for one live request context.
///
/// The common case is one effective `request_mirror` instance, so the first
/// admission is stored inline in [`Self::first`] and the overflow `Vec` stays
/// unallocated until a distinct second instance is staged. Arbitrary multi-
/// instance support is preserved without bounding count.
///
/// Owned semaphore permits and retained-byte leases live only on the live
/// request. Custom `Clone` returns an empty wrapper so `RequestContext`'s
/// derived `Clone` cannot duplicate or double-release admission capacity.
/// Custom `Debug` summarizes staging count only and never prints permit,
/// lease, or drop-reason state.
#[derive(Default)]
pub(crate) struct RequestMirrorAdmissions {
    first: Option<RequestMirrorAdmission>,
    overflow: Vec<RequestMirrorAdmission>,
}

impl Clone for RequestMirrorAdmissions {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl std::fmt::Debug for RequestMirrorAdmissions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let staged = usize::from(self.first.is_some()) + self.overflow.len();
        f.debug_struct("RequestMirrorAdmissions")
            .field("staged", &staged)
            .finish()
    }
}

impl RequestMirrorAdmissions {
    /// Stage one instance's admission, replacing any earlier entry for the
    /// same instance so a repeated evaluation cannot accumulate two leases.
    pub(crate) fn stage(&mut self, admission: RequestMirrorAdmission) {
        let instance_id = admission.instance_id();
        if let Some(first) = self.first.as_mut()
            && first.instance_id() == instance_id
        {
            *first = admission;
            return;
        }
        if let Some(slot) = self
            .overflow
            .iter_mut()
            .find(|staged| staged.instance_id() == instance_id)
        {
            *slot = admission;
            return;
        }
        if self.first.is_none() {
            self.first = Some(admission);
        } else {
            self.overflow.push(admission);
        }
    }

    /// Whether the given instance was admitted and therefore needs the request
    /// body buffered. Read-only and idempotent.
    pub(crate) fn body_admitted(&self, instance_id: u64) -> bool {
        if let Some(first) = self.first.as_ref()
            && first.instance_id() == instance_id
        {
            return first.is_admitted();
        }
        self.overflow
            .iter()
            .any(|staged| staged.instance_id() == instance_id && staged.is_admitted())
    }

    /// Take one instance's staged admission, transferring ownership of its
    /// permit and retained-byte lease to the caller.
    ///
    /// The slot is left in place as a [`MirrorAdmissionState::Consumed`]
    /// tombstone rather than removed: the lease moves out exactly once (a second
    /// take yields `Consumed`, never a second permit), while
    /// `should_buffer_request_body` keeps reporting the same answer it gave
    /// before the body was collected.
    pub(crate) fn take(&mut self, instance_id: u64) -> Option<RequestMirrorAdmission> {
        let slot = if self
            .first
            .as_ref()
            .is_some_and(|first| first.instance_id() == instance_id)
        {
            self.first.as_mut()?
        } else {
            let index = self
                .overflow
                .iter()
                .position(|staged| staged.instance_id() == instance_id)?;
            self.overflow.get_mut(index)?
        };
        let tombstone = MirrorAdmissionState::Consumed {
            admitted: slot.is_admitted(),
        };
        let state = std::mem::replace(&mut slot.state, tombstone);
        Some(RequestMirrorAdmission { instance_id, state })
    }
}

/// Per-instance, bounded-lifetime mirror observability counters.
///
/// Lifetime is bounded to the plugin instance: a config reload rebuilds the
/// plugin and resets every *per-instance* counter to zero (no unbounded growth,
/// no cross-generation accumulation). Counts are aggregate outcome tallies only
/// — they never carry header names, URLs, plugin IDs, or credential material.
/// Each bump also dual-writes into the process-wide authenticated Prometheus
/// registry (`ferrum_request_mirror_*_total`) so operators can scrape
/// label-safe lifecycle counters on `/metrics`. Mirror *transaction summaries*
/// remain excluded from request/billing histograms; that exclusion does not
/// apply to these safe counters.
///
/// Every dispatched task terminates in exactly one of
/// `{completed, request_timeouts, request_failures, drain_timeouts,
/// drain_failures, drain_truncations, cancellations}`, so those seven sum to
/// `dispatched`. A task that is dropped before recording a terminal outcome —
/// runtime shutdown, panic, or the executor cancelling the future — is counted
/// as a cancellation by [`MirrorTaskGuard`].
#[derive(Debug, Default)]
struct MirrorMetrics {
    /// Detached tasks spawned (admitted past both concurrency and byte budgets).
    dispatched: AtomicU64,
    /// Tasks that received a response and drained its body fully within bounds.
    completed: AtomicU64,
    /// Request-phase deadline expiries (connect/header/body request timeout).
    request_timeouts: AtomicU64,
    /// Other transport failures before a response (DNS, refused, reset, TLS…).
    request_failures: AtomicU64,
    /// Response-body drain-phase deadline expiries.
    drain_timeouts: AtomicU64,
    /// Response-body transport failures during the bounded drain.
    drain_failures: AtomicU64,
    /// Response bodies truncated at `max_response_body_bytes` (still drained).
    drain_truncations: AtomicU64,
    /// Tasks dropped before a terminal outcome (shutdown/panic/cancellation).
    cancellations: AtomicU64,
    /// Mirror attempts dropped at admission because `max_in_flight` was full.
    concurrency_drops: AtomicU64,
    /// Mirror attempts dropped at byte admission: either the aggregate
    /// `max_retained_request_body_bytes` budget was full, or the collected body
    /// exceeded the per-request `max_mirrored_request_body_bytes` ceiling. The
    /// published `mirror_error` names which of the two refused the attempt.
    budget_drops: AtomicU64,
}

/// Plain-`u64` snapshot of [`MirrorMetrics`] for external assertion in tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MirrorMetricsSnapshot {
    pub dispatched: u64,
    pub completed: u64,
    pub request_timeouts: u64,
    pub request_failures: u64,
    pub drain_timeouts: u64,
    pub drain_failures: u64,
    pub drain_truncations: u64,
    pub cancellations: u64,
    pub concurrency_drops: u64,
    pub budget_drops: u64,
}

impl MirrorMetrics {
    fn snapshot(&self) -> MirrorMetricsSnapshot {
        MirrorMetricsSnapshot {
            dispatched: self.dispatched.load(Ordering::Relaxed),
            completed: self.completed.load(Ordering::Relaxed),
            request_timeouts: self.request_timeouts.load(Ordering::Relaxed),
            request_failures: self.request_failures.load(Ordering::Relaxed),
            drain_timeouts: self.drain_timeouts.load(Ordering::Relaxed),
            drain_failures: self.drain_failures.load(Ordering::Relaxed),
            drain_truncations: self.drain_truncations.load(Ordering::Relaxed),
            cancellations: self.cancellations.load(Ordering::Relaxed),
            concurrency_drops: self.concurrency_drops.load(Ordering::Relaxed),
            budget_drops: self.budget_drops.load(Ordering::Relaxed),
        }
    }

    fn bump_dispatched(&self) {
        self.dispatched.fetch_add(1, Ordering::Relaxed);
        super::prometheus_metrics::global_registry().record_request_mirror_dispatched();
    }

    fn bump_concurrency_drop(&self) {
        self.concurrency_drops.fetch_add(1, Ordering::Relaxed);
        super::prometheus_metrics::global_registry().record_request_mirror_concurrency_drop();
    }

    fn bump_budget_drop(&self) {
        self.budget_drops.fetch_add(1, Ordering::Relaxed);
        super::prometheus_metrics::global_registry().record_request_mirror_budget_drop();
    }
}

/// Terminal outcome recorded by a settled [`MirrorTaskGuard`].
#[derive(Debug, Clone, Copy)]
enum MirrorTaskOutcome {
    Completed,
    RequestTimeout,
    RequestFailure,
    DrainTimeout,
    DrainFailure,
    DrainTruncation,
}

/// Guards a detached mirror task so a drop before recording a terminal outcome
/// (runtime shutdown, panic, or future cancellation) is counted as a
/// cancellation exactly once.
struct MirrorTaskGuard {
    metrics: Arc<MirrorMetrics>,
    settled: bool,
}

impl MirrorTaskGuard {
    fn new(metrics: Arc<MirrorMetrics>) -> Self {
        Self {
            metrics,
            settled: false,
        }
    }

    /// Record a terminal outcome; the guard then no longer counts a
    /// cancellation. Only the first outcome per task is recorded (defensive).
    fn settle(&mut self, outcome: MirrorTaskOutcome) {
        if self.settled {
            return;
        }
        self.settled = true;
        let counter = match outcome {
            MirrorTaskOutcome::Completed => &self.metrics.completed,
            MirrorTaskOutcome::RequestTimeout => &self.metrics.request_timeouts,
            MirrorTaskOutcome::RequestFailure => &self.metrics.request_failures,
            MirrorTaskOutcome::DrainTimeout => &self.metrics.drain_timeouts,
            MirrorTaskOutcome::DrainFailure => &self.metrics.drain_failures,
            MirrorTaskOutcome::DrainTruncation => &self.metrics.drain_truncations,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        let registry = super::prometheus_metrics::global_registry();
        match outcome {
            MirrorTaskOutcome::Completed => registry.record_request_mirror_completed(),
            MirrorTaskOutcome::RequestTimeout => registry.record_request_mirror_request_timeout(),
            MirrorTaskOutcome::RequestFailure => registry.record_request_mirror_request_failure(),
            MirrorTaskOutcome::DrainTimeout => registry.record_request_mirror_drain_timeout(),
            MirrorTaskOutcome::DrainFailure => registry.record_request_mirror_drain_failure(),
            MirrorTaskOutcome::DrainTruncation => registry.record_request_mirror_drain_truncation(),
        }
    }
}

impl Drop for MirrorTaskGuard {
    fn drop(&mut self) {
        if !self.settled {
            self.metrics.cancellations.fetch_add(1, Ordering::Relaxed);
            super::prometheus_metrics::global_registry().record_request_mirror_cancellation();
        }
    }
}

/// Classify a redacted transport-error string as a request-phase timeout.
///
/// `execute_redacted` / `execute_http2_redacted` render errors as
/// `"{error_class} calling {url}"` using the stable snake_case `ErrorClass`
/// Display tokens, so a leading `connection_timeout` / `read_write_timeout`
/// identifies the mirror deadline firing (the #3057 never-responding target)
/// without re-plumbing a typed error through the redaction boundary.
fn redacted_error_is_timeout(error: &str) -> bool {
    error.starts_with("connection_timeout") || error.starts_with("read_write_timeout")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MirrorDrainOutcome {
    Complete { observed: u64 },
    Truncated { observed: u64 },
    Timeout,
    TransportFailure,
}

/// Discard a mirror response body under the configured byte cap and drain
/// timeout so pooled HTTP/1.1 connections can be reclaimed.
async fn drain_mirror_response_body(
    response: reqwest::Response,
    max_bytes: usize,
) -> (Option<u64>, MirrorDrainOutcome) {
    // Record the advertised `Content-Length` independently, then always drain.
    // The advertised value is never used to short-circuit the drain: a body
    // whose real length is within `max_bytes` (even when Content-Length
    // over-advertises) must still be consumed to EOF so the pooled HTTP/1.1
    // socket is reclaimed, and the reported observed size must reflect bytes
    // actually read, not a fabricated `max_bytes`. Memory and time stay bounded
    // by `max_bytes` (the measure helper discards bytes as it counts) and the
    // drain timeout, so an oversized or slow body cannot pin the task.
    let advertised = response.content_length();
    match tokio::time::timeout(
        MIRROR_RESPONSE_DRAIN_TIMEOUT,
        measure_response_body_bounded(response, max_bytes),
    )
    .await
    {
        Err(_) => (advertised, MirrorDrainOutcome::Timeout),
        Ok(Ok(observed)) => (advertised, MirrorDrainOutcome::Complete { observed }),
        Ok(Err(BoundedReadError::LimitExceeded { read_so_far, .. })) => (
            advertised,
            MirrorDrainOutcome::Truncated {
                observed: read_so_far as u64,
            },
        ),
        Ok(Err(BoundedReadError::Stream(_))) => (advertised, MirrorDrainOutcome::TransportFailure),
    }
}

/// Declared request body length, read before the body exists.
///
/// Prefers the raw wire headers (no map materialization required) and falls
/// back to the folded map for synthetic/test contexts that never carried raw
/// headers. A malformed or absent value yields `None`, which admission treats
/// as "unknown length" and charges the full plugin-local ceiling.
fn request_content_length(ctx: &RequestContext) -> Option<u64> {
    if ctx.has_raw_headers() {
        // Every real proxy path sets raw headers, so the folded-map scan below
        // never runs on the hot path — including for the common no-`Content-
        // Length` request, where it would otherwise walk the whole map.
        return ctx
            .raw_header_get("content-length")
            .and_then(|raw| raw.trim().parse::<u64>().ok());
    }
    ctx.headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<u64>().ok())
}

fn request_host_header(headers: &HashMap<String, String>) -> Option<&str> {
    headers
        .iter()
        .find(|(name, _)| {
            name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case(":authority")
        })
        .map(|(_, value)| value.as_str())
}

fn completed_mirror_result(
    meta: MirrorResponseMeta,
) -> tokio::sync::watch::Receiver<Option<MirrorResponseMeta>> {
    let (_tx, rx) = tokio::sync::watch::channel(Some(meta));
    rx
}

/// Quantize a configured percentage to the integer tenth-percent threshold
/// used by the deterministic sampler (`0..=1000`).
fn sample_threshold_from_percentage(percentage: f64) -> u64 {
    // `percentage` is already validated to `[0.0, 100.0]` at construction.
    let rounded = (percentage * 10.0).round();
    if rounded <= 0.0 {
        0
    } else if rounded >= 1000.0 {
        SAMPLE_PERIOD
    } else {
        rounded as u64
    }
}

/// Process-unique identity for one constructed `RequestMirror`.
///
/// Multiple instances may be attached to one proxy, and each admits
/// independently. The per-request admission slot is keyed on this id so one
/// instance can never observe, consume, or release another instance's lease.
/// Reload builds new instances and therefore new ids; a stale id simply never
/// matches.
static MIRROR_INSTANCE_SEQ: AtomicU64 = AtomicU64::new(1);

pub struct RequestMirror {
    /// Process-unique id used to key this instance's per-request admission.
    instance_id: u64,
    http_client: PluginHttpClient,
    /// Stable plugin-config resource id when constructed through the plugin
    /// cache / factory. Surfaced on mirror summaries for multi-instance
    /// attribution; never a secret.
    plugin_config_id: Option<String>,
    mirror_host: String,
    mirror_port: u16,
    mirror_protocol: String,
    mirror_path: Option<String>,
    /// `round(percentage × 10)` clamped to `0..=1000` (0.1% granularity).
    sample_threshold: u64,
    mirror_request_body: bool,
    /// Maximum number of bytes to drain from every mirror response when
    /// deriving `mirror_response_size_bytes`. The body is discarded after
    /// measurement so this bounds memory/time for fire-and-forget tasks
    /// against misbehaving sinks, including Content-Length responses.
    max_response_body_bytes: usize,
    /// Optional plugin-level mirror deadline. When set, overrides the proxy
    /// `backend_read_timeout_ms` for detached mirror work.
    mirror_timeout_ms: Option<u64>,
    /// When true, only names in `forward_sensitive_header_allowlist` may cross
    /// to the mirror origin. Default false strips the sensitive set.
    forward_sensitive_headers: bool,
    /// Lowercased allowlist consulted only when `forward_sensitive_headers`.
    forward_sensitive_header_allowlist: Vec<String>,
    /// Operator-configured lowercased substrings that extend the built-in
    /// deny-by-default sensitive-header set (`sensitive_header_patterns`).
    sensitive_header_patterns: Vec<String>,
    mirror_hostname: Option<String>,
    /// Bresenham phase accumulator in `0..SAMPLE_PERIOD` for evenly spaced
    /// deterministic percentage sampling. Reset to `0` on construction/reload.
    sample_phase: AtomicU64,
    /// Bounds concurrent mirror tasks to prevent unbounded background work.
    mirror_in_flight: Arc<tokio::sync::Semaphore>,
    /// Aggregate retained request-body bytes across in-flight mirror tasks.
    body_budget: Arc<MirrorBodyBudget>,
    /// Positive plugin-local ceiling on one mirrored request body, applied even
    /// when the global request-body limit is unlimited.
    max_mirrored_request_body_bytes: u64,
    /// Per-instance, bounded-lifetime mirror lifecycle counters.
    metrics: Arc<MirrorMetrics>,
}

impl RequestMirror {
    #[allow(dead_code)] // direct/test construction; production factory supplies the config id
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        Self::new_with_config_id(config, http_client, None)
    }

    pub fn new_with_config_id(
        config: &Value,
        http_client: PluginHttpClient,
        plugin_config_id: Option<&str>,
    ) -> Result<Self, String> {
        let config_obj = config.as_object().ok_or_else(|| {
            format!(
                "request_mirror: config must be an object; allowed keys: {}",
                REQUEST_MIRROR_CONFIG_KEYS.join(", ")
            )
        })?;
        reject_unknown_request_mirror_keys(config_obj)?;

        let raw_mirror_host = optional_string(config, "mirror_host")?
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "request_mirror: 'mirror_host' is required".to_string())?
            .to_ascii_lowercase();
        let (mirror_host, mirror_hostname) = parse_mirror_host(&raw_mirror_host)?;

        let mirror_protocol = optional_string(config, "mirror_protocol")?
            .unwrap_or_else(|| "http".to_string())
            .to_ascii_lowercase();

        if mirror_protocol != "http" && mirror_protocol != "https" {
            return Err(format!(
                "request_mirror: 'mirror_protocol' must be 'http' or 'https' (got '{}')",
                mirror_protocol
            ));
        }

        let default_port: u16 = if mirror_protocol == "https" { 443 } else { 80 };
        let mirror_port = optional_u64(config, "mirror_port")?
            .map(|p| {
                if p == 0 || p > 65535 {
                    Err(format!(
                        "request_mirror: 'mirror_port' must be 1–65535 (got {})",
                        p
                    ))
                } else {
                    Ok(p as u16)
                }
            })
            .transpose()?
            .unwrap_or(default_port);

        let mirror_path = optional_string(config, "mirror_path")?.filter(|s| !s.is_empty());
        if let Some(path) = &mirror_path
            && !path.starts_with('/')
        {
            return Err("request_mirror: 'mirror_path' must start with '/'".to_string());
        }
        if let Some(path) = &mirror_path
            && (path.contains('?') || path.contains('#'))
        {
            return Err(
                "request_mirror: 'mirror_path' must not contain a query or fragment".to_string(),
            );
        }

        let percentage = optional_f64(config, "percentage")?.unwrap_or(100.0);
        if !(0.0..=100.0).contains(&percentage) {
            return Err(format!(
                "request_mirror: 'percentage' must be 0.0–100.0 (got {})",
                percentage
            ));
        }
        let sample_threshold = sample_threshold_from_percentage(percentage);

        let mirror_request_body = optional_bool(config, "mirror_request_body")?.unwrap_or(true);

        let max_in_flight = optional_u64(config, "max_in_flight")?
            .map(|v| {
                if v == 0 {
                    return Err("request_mirror: 'max_in_flight' must be >= 1".to_string());
                }
                // Range-check against the deployment-safe hard cap before the
                // value ever reaches `Semaphore::new`. A value above the cap
                // (up to and past Tokio's `MAX_PERMITS`) fits `usize` and would
                // otherwise panic construction; reject it as a config error.
                let v = usize::try_from(v).map_err(|_| {
                    format!(
                        "request_mirror: 'max_in_flight' must be 1–{MAX_MAX_IN_FLIGHT_MIRRORS}"
                    )
                })?;
                if v > MAX_MAX_IN_FLIGHT_MIRRORS {
                    return Err(format!(
                        "request_mirror: 'max_in_flight' must be 1–{MAX_MAX_IN_FLIGHT_MIRRORS} (got {v})"
                    ));
                }
                Ok(v)
            })
            .transpose()?
            .unwrap_or(DEFAULT_MAX_IN_FLIGHT_MIRRORS);

        let max_retained_request_body_bytes =
            optional_u64(config, "max_retained_request_body_bytes")?
                .map(|v| {
                    if v == 0 {
                        Err(
                            "request_mirror: 'max_retained_request_body_bytes' must be >= 1"
                                .to_string(),
                        )
                    } else {
                        Ok(v)
                    }
                })
                .transpose()?
                .unwrap_or(DEFAULT_MAX_RETAINED_REQUEST_BODY_BYTES);

        let configured_max_mirrored_request_body_bytes =
            optional_u64(config, "max_mirrored_request_body_bytes")?
                .map(|v| {
                    if v == 0 {
                        Err(
                            "request_mirror: 'max_mirrored_request_body_bytes' must be >= 1"
                                .to_string(),
                        )
                    } else if usize::try_from(v).is_err() {
                        Err(
                            "request_mirror: 'max_mirrored_request_body_bytes' is too large for this platform"
                                .to_string(),
                        )
                    } else {
                        Ok(v)
                    }
                })
                .transpose()?;
        // A per-request ceiling above the aggregate budget could never be
        // admitted (admission reserves the full ceiling up front), so the
        // instance would silently never mirror a body. An explicit operator
        // value that contradicts the aggregate budget is rejected at
        // construction; the *default* ceiling instead clamps down to the
        // configured budget, so an existing config that only sets a small
        // `max_retained_request_body_bytes` keeps loading rather than failing
        // startup on a key it never set.
        let max_mirrored_request_body_bytes = match configured_max_mirrored_request_body_bytes {
            Some(configured) => {
                if configured > max_retained_request_body_bytes {
                    return Err(format!(
                        "request_mirror: 'max_mirrored_request_body_bytes' ({configured}) must not exceed 'max_retained_request_body_bytes' ({max_retained_request_body_bytes})"
                    ));
                }
                configured
            }
            // `max_retained_request_body_bytes` is validated `>= 1` above, so
            // the clamped default stays a positive ceiling.
            None => DEFAULT_MAX_MIRRORED_REQUEST_BODY_BYTES.min(max_retained_request_body_bytes),
        };

        let mirror_timeout_ms = optional_u64(config, "mirror_timeout_ms")?
            .map(|v| {
                if v == 0 || v > MAX_MIRROR_TIMEOUT_MS {
                    Err(format!(
                        "request_mirror: 'mirror_timeout_ms' must be 1–{MAX_MIRROR_TIMEOUT_MS} (got {v})"
                    ))
                } else {
                    Ok(v)
                }
            })
            .transpose()?;

        // Parse operator patterns first: the allowlist may re-permit a header
        // that only a configured pattern denies.
        let sensitive_header_patterns = parse_sensitive_header_patterns(config)?;

        let forward_sensitive_headers =
            optional_bool(config, "forward_sensitive_headers")?.unwrap_or(false);
        let forward_sensitive_header_allowlist = parse_forward_sensitive_header_allowlist(
            config,
            forward_sensitive_headers,
            &sensitive_header_patterns,
        )?;

        let max_response_body_bytes = parse_max_response_body_bytes(
            config,
            "request_mirror",
            "max_response_body_bytes",
            DEFAULT_MIRROR_MAX_RESPONSE_BODY_BYTES,
        )?;

        let plugin_config_id = match plugin_config_id {
            Some(id) if id.trim().is_empty() => {
                return Err("request_mirror: plugin_config_id must not be blank".to_string());
            }
            Some(id) => Some(id.trim().to_owned()),
            None => None,
        };

        Ok(Self {
            instance_id: MIRROR_INSTANCE_SEQ.fetch_add(1, Ordering::Relaxed),
            http_client,
            plugin_config_id,
            mirror_host,
            mirror_port,
            mirror_protocol,
            mirror_path,
            sample_threshold,
            mirror_request_body,
            max_response_body_bytes,
            mirror_timeout_ms,
            forward_sensitive_headers,
            forward_sensitive_header_allowlist,
            sensitive_header_patterns,
            mirror_hostname,
            // Phase 0 defers the first selection until the accumulator crosses
            // SAMPLE_PERIOD — construction/reload never opens with a mirrored prefix.
            sample_phase: AtomicU64::new(0),
            // `max_in_flight` is range-checked above, so `Semaphore::new` cannot
            // panic on an out-of-range permit count.
            mirror_in_flight: Arc::new(tokio::sync::Semaphore::new(max_in_flight)),
            body_budget: MirrorBodyBudget::new(max_retained_request_body_bytes),
            max_mirrored_request_body_bytes,
            metrics: Arc::new(MirrorMetrics::default()),
        })
    }

    /// Effective sampling threshold in tenths of a percent (`0..=1000`).
    // This accessor exists for the external sampling contract tests. The
    // production request path reads the field directly in `should_mirror`.
    #[allow(dead_code)]
    pub(crate) fn sample_threshold_for_test(&self) -> u64 {
        self.sample_threshold
    }

    /// Current Bresenham phase in `0..SAMPLE_PERIOD`.
    // This accessor exists for the external sampling contract tests. The
    // production request path updates the atomic directly in `should_mirror`.
    #[allow(dead_code)]
    pub(crate) fn sample_phase_for_test(&self) -> u64 {
        self.sample_phase.load(Ordering::Relaxed)
    }

    /// Configured mirror timeout override when present.
    #[allow(dead_code)]
    pub(crate) fn mirror_timeout_ms_for_test(&self) -> Option<u64> {
        self.mirror_timeout_ms
    }

    /// Current retained request-body budget usage for external tests.
    #[allow(dead_code)]
    pub(crate) fn retained_request_body_bytes_for_test(&self) -> u64 {
        self.body_budget.used_for_test()
    }

    /// Configured retained-body ceiling for external tests.
    #[allow(dead_code)]
    pub(crate) fn max_retained_request_body_bytes_for_test(&self) -> u64 {
        self.body_budget.max_bytes
    }

    /// Configured plugin-local per-request body ceiling for external tests.
    #[allow(dead_code)]
    pub(crate) fn max_mirrored_request_body_bytes_for_test(&self) -> u64 {
        self.max_mirrored_request_body_bytes
    }

    /// Whether this instance can ever force a pre-`before_proxy` request-body
    /// buffer.
    ///
    /// Deterministic disablement (advisory `GHSA-jv66-mq44-m9v3`): an instance
    /// with `mirror_request_body: false` never needs a body, and one quantized
    /// to `percentage: 0` can never select a request, so neither may declare a
    /// body capability. Both cases therefore keep every request streaming at
    /// config time — the plugin cache's upper bound, the per-request buffering
    /// predicate, and the `authorize`-phase admission hook all collapse to
    /// "no body" without evaluating anything per request.
    fn body_admission_enabled(&self) -> bool {
        self.mirror_request_body && self.sample_threshold > 0
    }

    /// Bytes to reserve from the aggregate budget before the body is read.
    ///
    /// Fail-closed (advisory `GHSA-jv66-mq44-m9v3`): every otherwise admitted
    /// body-mirroring request reserves the full positive plugin-local ceiling,
    /// regardless of method, protocol, missing/present `Content-Length`, or a
    /// declared zero/small length. Declared size is untrusted for aggregate
    /// accounting — H3's collector enforces the collection ceiling without
    /// requiring equality with `Content-Length`, and Hyper's H2 `Incoming`
    /// length is not Ferrum's allocation bound — so charging only an
    /// attacker-declared byte would let many concurrent tiny declarations each
    /// allocate up to the ceiling before finalized-egress reconciliation,
    /// exceeding `max_retained_request_body_bytes`.
    ///
    /// Oversized declared lengths are skipped *before* this reservation (see
    /// [`Self::authorize`]). The tradeoff is accepted and bounded: a tiny or
    /// bodyless request briefly holds the ceiling, and finalized request egress
    /// returns the surplus (down to `0` for an empty body) exactly once as soon
    /// as the observed length is known. Operators
    /// mirroring mostly-bodyless traffic at high concurrency should size
    /// `max_retained_request_body_bytes` against
    /// `max_in_flight × max_mirrored_request_body_bytes`, or lower the ceiling.
    fn reserved_body_bytes(&self) -> u64 {
        self.max_mirrored_request_body_bytes
    }

    /// Snapshot of the per-instance mirror lifecycle counters for external
    /// tests. Process-wide authenticated `/metrics` also exports the same
    /// aggregate tallies as `ferrum_request_mirror_*_total` (monotonic across
    /// reloads); this hook asserts the per-instance, reload-reset view.
    #[allow(dead_code)]
    pub(crate) fn mirror_metrics_snapshot_for_test(&self) -> MirrorMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Select the path segment for the mirror URL without consuming primary
    /// route overrides.
    ///
    /// Precedence: explicit `mirror_path` → mesh `route_override_path` →
    /// authorized backend path → original `ctx.path`.
    fn select_mirror_path<'a>(&'a self, ctx: &'a RequestContext) -> &'a str {
        if let Some(path) = self.mirror_path.as_deref() {
            return path;
        }
        if ctx.mesh_route_dispatch_matched
            && let Some(path) = ctx.route_override_path.as_deref()
        {
            return path;
        }
        ctx.authorized_backend_path().unwrap_or(&ctx.path)
    }

    /// Build the full mirror URL from the configured or gateway-selected path.
    ///
    /// Prefer the effective backend query string (transformer outbound query
    /// composed with auth credential strips) so duplicate keys, ordering,
    /// flags, empty values, `+`, percent escapes, and non-ASCII encoded bytes
    /// match primary dispatch. Fall back to the materialised `query_params`
    /// map only when no raw/outbound query is available (tests / already-decoded
    /// contexts).
    fn build_mirror_url(
        &self,
        original_path: &str,
        raw_query: Option<&str>,
        query_params: &HashMap<String, String>,
    ) -> String {
        let path = self.mirror_path.as_deref().unwrap_or(original_path);

        let mut url = String::with_capacity(
            self.mirror_protocol.len() + 3 + self.mirror_host.len() + 1 + 5 + path.len(),
        );
        url.push_str(&self.mirror_protocol);
        url.push_str("://");
        url.push_str(&self.mirror_host);
        url.push(':');
        let _ = write!(&mut url, "{}", self.mirror_port);
        url.push_str(path);

        if let Some(query) = raw_query {
            // `Some("")` is authoritative: an auth strip may have removed the
            // entire raw query, so falling back to the materialised map here
            // would reintroduce the credential.
            if !query.is_empty() {
                url.push('?');
                url.push_str(query);
            }
        } else if !query_params.is_empty() {
            url.push('?');
            let encoded: String = form_urlencoded::Serializer::new(String::new())
                .extend_pairs(query_params.iter())
                .finish();
            url.push_str(&encoded);
        }

        url
    }

    /// Should this request be mirrored (deterministic evenly spaced sampling)?
    ///
    /// See the module-level "Percentage sampling" section for phase/reset,
    /// concurrency, and wrap semantics.
    fn should_mirror(&self) -> bool {
        let threshold = self.sample_threshold;
        if threshold == 0 {
            return false;
        }
        if threshold >= SAMPLE_PERIOD {
            return true;
        }

        // Lock-free Bresenham: keep phase in [0, SAMPLE_PERIOD). Successful
        // updates always store `next < SAMPLE_PERIOD`, and `threshold` is at
        // most 999, so `current + threshold` stays far below u64::MAX and
        // cannot overflow or panic.
        let mut current = self.sample_phase.load(Ordering::Relaxed);
        loop {
            let sum = current + threshold;
            let (selected, next) = if sum >= SAMPLE_PERIOD {
                (true, sum - SAMPLE_PERIOD)
            } else {
                (false, sum)
            };
            match self.sample_phase.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return selected,
                Err(observed) => current = observed,
            }
        }
    }

    /// External-test probe for the real state-advancing sampler without
    /// widening the production API surface.
    #[allow(dead_code)]
    pub(crate) fn should_mirror_for_test(&self) -> bool {
        self.should_mirror()
    }
}

fn reject_unknown_request_mirror_keys(object: &Map<String, Value>) -> Result<(), String> {
    let mut unknown: Vec<&str> = object
        .keys()
        .filter(|key| !REQUEST_MIRROR_CONFIG_KEYS.contains(&key.as_str()))
        .map(String::as_str)
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    unknown.sort_unstable();
    let details: Vec<String> = unknown
        .into_iter()
        .map(|key| match suggest_key(key, REQUEST_MIRROR_CONFIG_KEYS) {
            Some(suggestion) => format!("'{key}' (did you mean '{suggestion}'?)"),
            None => format!("'{key}'"),
        })
        .collect();
    Err(format!(
        "request_mirror: unknown configuration key(s): {}; allowed keys: {}",
        details.join(", "),
        REQUEST_MIRROR_CONFIG_KEYS.join(", ")
    ))
}

fn parse_mirror_host(raw_host: &str) -> Result<(String, Option<String>), String> {
    let host = raw_host.trim();
    if host.is_empty() {
        return Err("request_mirror: 'mirror_host' is required".to_string());
    }
    if host
        .chars()
        .any(|c| c.is_ascii_whitespace() || c.is_control())
        || host.contains("://")
        || host.contains(['/', '?', '#', '@'])
    {
        return Err(
            "request_mirror: 'mirror_host' must be a hostname or IP address without scheme, path, query, fragment, or credentials"
                .to_string(),
        );
    }

    let bracketed = host.starts_with('[') || host.ends_with(']');
    let host_for_ip = if let Some(inner) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
    {
        inner
    } else {
        host
    };

    if let Ok(ip) = host_for_ip.parse::<std::net::IpAddr>() {
        return Ok(match ip {
            std::net::IpAddr::V4(ip) => (ip.to_string(), None),
            std::net::IpAddr::V6(ip) => (format!("[{ip}]"), None),
        });
    }

    if bracketed || host.contains(':') {
        return Err(
            "request_mirror: 'mirror_host' must not include brackets or a port unless it is an IPv6 literal"
                .to_string(),
        );
    }

    match Host::parse(host) {
        Ok(Host::Domain(domain)) if !domain.is_empty() => {
            let hostname = domain.to_ascii_lowercase();
            Ok((hostname.clone(), Some(hostname)))
        }
        _ => {
            Err("request_mirror: 'mirror_host' must be a valid hostname or IP address".to_string())
        }
    }
}

/// Parse the operator-configured `sensitive_header_patterns` list: lowercased,
/// trimmed, non-blank substrings that extend the built-in deny-by-default set.
/// Item count and per-item length are hard-capped so an admitted config cannot
/// create unbounded per-request substring scans or retained config memory.
fn parse_sensitive_header_patterns(config: &Value) -> Result<Vec<String>, String> {
    match config.get("sensitive_header_patterns") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => {
            if items.len() > MAX_SENSITIVE_HEADER_PATTERNS {
                return Err(format!(
                    "request_mirror: 'sensitive_header_patterns' must contain at most {MAX_SENSITIVE_HEADER_PATTERNS} entries"
                ));
            }
            let mut out = Vec::with_capacity(items.len());
            for (idx, item) in items.iter().enumerate() {
                let Some(pattern) = item.as_str() else {
                    return Err(format!(
                        "request_mirror: 'sensitive_header_patterns[{idx}]' must be a string"
                    ));
                };
                let trimmed = pattern.trim();
                if trimmed.is_empty() {
                    return Err(format!(
                        "request_mirror: 'sensitive_header_patterns[{idx}]' must not be blank"
                    ));
                }
                if trimmed.len() > MAX_SENSITIVE_HEADER_PATTERN_LEN {
                    return Err(format!(
                        "request_mirror: 'sensitive_header_patterns[{idx}]' exceeds maximum length of {MAX_SENSITIVE_HEADER_PATTERN_LEN} bytes"
                    ));
                }
                let lower = trimmed.to_ascii_lowercase();
                if !out.iter().any(|existing| existing == &lower) {
                    out.push(lower);
                }
            }
            Ok(out)
        }
        Some(_) => Err(
            "request_mirror: 'sensitive_header_patterns' must be an array of strings".to_string(),
        ),
    }
}

fn parse_forward_sensitive_header_allowlist(
    config: &Value,
    forward_sensitive_headers: bool,
    operator_patterns: &[String],
) -> Result<Vec<String>, String> {
    let raw = match config.get("forward_sensitive_header_allowlist") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => {
            if items.len() > MAX_FORWARD_SENSITIVE_ALLOWLIST {
                return Err(format!(
                    "request_mirror: 'forward_sensitive_header_allowlist' must contain at most {MAX_FORWARD_SENSITIVE_ALLOWLIST} entries"
                ));
            }
            let mut out = Vec::with_capacity(items.len());
            for (idx, item) in items.iter().enumerate() {
                let Some(name) = item.as_str() else {
                    return Err(format!(
                        "request_mirror: 'forward_sensitive_header_allowlist[{idx}]' must be a string"
                    ));
                };
                let trimmed = name.trim();
                if trimmed.is_empty() {
                    return Err(format!(
                        "request_mirror: 'forward_sensitive_header_allowlist[{idx}]' must not be blank"
                    ));
                }
                if trimmed.len() > MAX_FORWARD_SENSITIVE_ALLOWLIST_ITEM_LEN {
                    return Err(format!(
                        "request_mirror: 'forward_sensitive_header_allowlist[{idx}]' exceeds maximum length of {MAX_FORWARD_SENSITIVE_ALLOWLIST_ITEM_LEN} bytes"
                    ));
                }
                if http::HeaderName::from_bytes(trimmed.as_bytes()).is_err() {
                    return Err(format!(
                        "request_mirror: 'forward_sensitive_header_allowlist[{idx}]' is not a valid HTTP header name"
                    ));
                }
                let lower = trimmed.to_ascii_lowercase();
                // The allowlist re-permits deny-by-default headers, so every
                // entry must actually be denied by the effective policy
                // (built-in credential name/substring or a configured
                // sensitive_header_patterns match). Rejecting non-sensitive
                // names catches typos and keeps the allowlist meaningful — a
                // name that is not stripped could never be "forwarded" by it.
                if !is_mirror_sensitive_header(&lower, operator_patterns) {
                    return Err(format!(
                        "request_mirror: 'forward_sensitive_header_allowlist[{idx}]' ('{lower}') is not a recognized sensitive header (built-in credential or a configured sensitive_header_patterns match)"
                    ));
                }
                if !out.iter().any(|existing| existing == &lower) {
                    out.push(lower);
                }
            }
            out
        }
        Some(_) => {
            return Err(
                "request_mirror: 'forward_sensitive_header_allowlist' must be an array of strings"
                    .to_string(),
            );
        }
    };

    match (forward_sensitive_headers, raw.is_empty()) {
        (false, true) => Ok(raw),
        (false, false) => Err(
            "request_mirror: 'forward_sensitive_header_allowlist' requires forward_sensitive_headers=true"
                .to_string(),
        ),
        (true, true) => Err(
            "request_mirror: forward_sensitive_headers=true requires a non-empty forward_sensitive_header_allowlist (fail-closed)"
                .to_string(),
        ),
        (true, false) => Ok(raw),
    }
}

fn optional_bool(config: &Value, key: &str) -> Result<Option<bool>, String> {
    match config.get(key) {
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!("request_mirror: '{key}' must be a boolean")),
    }
}

fn optional_f64(config: &Value, key: &str) -> Result<Option<f64>, String> {
    match config.get(key) {
        Some(Value::Number(value)) => value
            .as_f64()
            .map(Some)
            .ok_or_else(|| format!("request_mirror: '{key}' must be a number")),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!("request_mirror: '{key}' must be a number")),
    }
}

fn optional_string(config: &Value, key: &str) -> Result<Option<String>, String> {
    match config.get(key) {
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!("request_mirror: '{key}' must be a string")),
    }
}

fn optional_u64(config: &Value, key: &str) -> Result<Option<u64>, String> {
    match config.get(key) {
        Some(Value::Number(value)) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("request_mirror: '{key}' must be an unsigned integer")),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!(
            "request_mirror: '{key}' must be an unsigned integer"
        )),
    }
}

#[async_trait]
impl Plugin for RequestMirror {
    fn name(&self) -> &str {
        "request_mirror"
    }

    fn priority(&self) -> u16 {
        super::priority::REQUEST_MIRROR
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_GRPC_PROTOCOLS
    }

    /// Keeps the admitted body collected on the early pre-`before_proxy` buffer
    /// (the `GHSA-jv66-mq44-m9v3` admission design depends on that timing). The
    /// mirror does not read it there: the bytes it replays come from the
    /// finalized-request-egress phase parameter, after transforms and final
    /// request policy.
    fn requires_request_body_before_before_proxy(&self) -> bool {
        self.body_admission_enabled()
    }

    /// Buffer only for a request this instance already admitted.
    ///
    /// The decision is made once per request by the `authorize` hook, before any
    /// body is read, and is only read back here: this predicate is evaluated
    /// several times per request by the proxy and must stay pure. A
    /// percentage-zero, sampled-out, or admission-refused request therefore
    /// never forces a buffer and keeps streaming (advisory
    /// `GHSA-jv66-mq44-m9v3`).
    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        self.body_admission_enabled() && ctx.request_mirror_body_admitted(self.instance_id)
    }

    /// The mirror reads the finalized body from the finalized-request-egress
    /// phase parameter, never from `ctx.request_body_bytes` (which holds the
    /// PRE-transform client body). Declining the context copy avoids a full-body
    /// `Bytes::copy_from_slice` per request that nothing would read.
    fn needs_request_body_bytes(&self) -> bool {
        false
    }

    /// The mirror replays raw bytes only. Declining the UTF-8 copy avoids
    /// retaining a second full-body representation alongside the shared
    /// `Bytes` the detached task forwards.
    fn needs_request_body_text(&self) -> bool {
        false
    }

    /// Positive plugin-local ceiling on a mirrored body, combined with the
    /// global limit by the proxy (strictest positive value wins). This is the
    /// bound that survives `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES=0`.
    ///
    /// It applies only to requests this instance admitted, so a sampled-out or
    /// unmirrored request never inherits a mirror-derived request-size policy.
    fn request_body_buffer_limit(&self) -> Option<usize> {
        self.body_admission_enabled()
            .then(|| usize::try_from(self.max_mirrored_request_body_bytes).unwrap_or(usize::MAX))
    }

    /// Body-mirroring instances participate in the `authorize` phase purely to
    /// decide admission before the gateway collects a request body. They never
    /// reject: mirroring stays fail-open for the primary request.
    fn is_authorize_plugin(&self) -> bool {
        self.body_admission_enabled()
    }

    /// Decide sampling and bounded mirror admission BEFORE body collection.
    ///
    /// The built-in priority places this after the built-in rejecting
    /// authorization hooks. Operator priority overrides and custom plugins can
    /// place another authorization hook later, but body collection still waits
    /// for the complete authorization phase to succeed. A later rejection
    /// therefore drops this staged decision without reading the upload. A
    /// request that is not selected, or that cannot get a concurrency permit
    /// and a retained-byte reservation, stages a non-admitting decision and
    /// stays streaming.
    ///
    /// The sampler advances here rather than in finalized request egress.
    /// Requests rejected before this hook do not advance it. A later custom or
    /// priority-overridden authorization rejection can consume a sampling slot,
    /// as can a request later claimed by `ai_stream_router`; in both cases the
    /// permit and reservation are released without dispatching a mirror.
    async fn authorize(&self, ctx: &mut RequestContext) -> PluginResult {
        if !self.body_admission_enabled() {
            return PluginResult::Continue;
        }
        let declared_length = request_content_length(ctx);
        // A body that already declares more than the plugin-local ceiling can
        // never be mirrored intact. Skip it before sampling: the request keeps
        // streaming, the primary path is untouched (no shadow-driven 413), and
        // no truncated payload is replayed to the shadow destination.
        let too_large_to_mirror =
            declared_length.is_some_and(|len| len > self.max_mirrored_request_body_bytes);
        let state = if too_large_to_mirror || !self.should_mirror() {
            MirrorAdmissionState::NotSelected
        } else {
            match self.mirror_in_flight.clone().try_acquire_owned() {
                Ok(permit) => match self.body_budget.try_reserve(self.reserved_body_bytes()) {
                    Some(lease) => MirrorAdmissionState::Admitted { permit, lease },
                    None => {
                        self.metrics.bump_budget_drop();
                        MirrorAdmissionState::Dropped(MIRROR_BODY_BUDGET_DROP_ERROR)
                    }
                },
                Err(_) => {
                    self.metrics.bump_concurrency_drop();
                    MirrorAdmissionState::Dropped(MIRROR_CONCURRENCY_DROP_ERROR)
                }
            }
        };
        ctx.stage_request_mirror_admission(RequestMirrorAdmission {
            instance_id: self.instance_id,
            state,
        });
        PluginResult::Continue
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.mirror_hostname.iter().cloned().collect()
    }

    /// The mirror is dispatched in the finalized-request-egress phase, after
    /// request-body transforms and every final request-policy hook have
    /// accepted the backend-visible representation. A shadow destination
    /// therefore never receives a field `request_transformer` was configured to
    /// remove, and never receives a request that WAF, OpenAPI-schema, or
    /// request-size policy goes on to reject (GHSA-4vr5-4wm3-x5xv).
    fn dispatches_finalized_request_egress(&self) -> bool {
        true
    }

    /// Dispatch the shadow request over the finalized representation.
    ///
    /// `headers` is the finalized pre-egress baseline and `body` is the exact
    /// finalized body the primary backend receives. A preceding
    /// `serverless_function` may publish a later backend-only header overlay, so
    /// mirror headers deliberately need not include those injected fields. The
    /// mirror never mutates the outbound request and publishes nothing into
    /// `backend_header_overlay`.
    async fn dispatch_finalized_request_egress(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
        body: &[u8],
        _backend_header_overlay: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Take this instance's pre-buffer admission (staged by `authorize`)
        // exactly once. Dropping it here releases the permit and the retained
        // byte reservation; carrying it forward transfers ownership to the
        // detached task.
        let staged_admission = ctx.take_request_mirror_admission(self.instance_id);
        if ctx
            .metadata
            .get("ai_stream_router_claimed")
            .map(String::as_str)
            == Some("true")
        {
            // The request was claimed after admission. Release the permit and
            // reservation immediately rather than holding them for work that
            // will never be dispatched.
            drop(staged_admission);
            return PluginResult::Continue;
        }
        let staged_state = match staged_admission {
            Some(admission) => Some(admission.state),
            // No staged decision: this instance does not mirror bodies, is
            // quantized to `percentage: 0`, or finalized request egress was
            // invoked directly without the authorize phase. Fall back to the
            // request-time sampler so behavior is unchanged for those paths.
            None => {
                if !self.should_mirror() {
                    return PluginResult::Continue;
                }
                None
            }
        };
        if matches!(staged_state, Some(MirrorAdmissionState::NotSelected)) {
            // Sampled out before the body was collected. No shadow request, no
            // observability record (existing contract), and nothing buffered.
            return PluginResult::Continue;
        }
        if matches!(staged_state, Some(MirrorAdmissionState::Consumed { .. })) {
            // This instance already ran finalized request egress for this
            // request. Never dispatch, sample, or acquire capacity a second
            // time.
            return PluginResult::Continue;
        }

        // Mirror the final route-selected path without consuming the override
        // that primary dispatch still needs. An explicit operator mirror_path
        // remains authoritative.
        let mirror_path = self.select_mirror_path(ctx);
        // Match primary backend query construction: transformer-published
        // outbound query (when present) composed with auth credential strips.
        // Primary and mirror must observe the same canonical request-target
        // query identity and ordering. Fall back to the materialised map only
        // when neither a raw nor outbound query was retained (synthetic tests).
        let effective_query =
            if ctx.outbound_query_string().is_some() || ctx.raw_query_string().is_some() {
                Some(crate::proxy::effective_backend_query_string(ctx))
            } else {
                None
            };
        let mirror_url =
            self.build_mirror_url(mirror_path, effective_query.as_deref(), &ctx.query_params);
        let method = ctx.method.clone();

        // Mirror destinations are an egress boundary just like the primary
        // backend. Apply the canonical secondary-request sanitizer (hop-by-hop,
        // Connection-listed, framing, proxy-owned forwarding identity, Host
        // strip) before any mirror-specific exclusions.
        let mesh_shadow_host = if ctx.mesh_route_dispatch_matched {
            ctx.route_override_authority
                .as_deref()
                .or_else(|| request_host_header(headers))
                .filter(|authority| !authority.is_empty())
                .map(append_shadow_host_suffix)
        } else {
            None
        };
        let mut mirror_headers = filter_secondary_request_headers(
            headers,
            SecondaryRequestHostPolicy::Strip,
            &[HEADER_TRIGGER_KEY, HEADER_FANOUT],
        );
        apply_mirror_credential_policy(
            &mut mirror_headers,
            self.forward_sensitive_headers,
            &self.forward_sensitive_header_allowlist,
            &self.sensitive_header_patterns,
        );
        if let Some(shadow_host) = mesh_shadow_host {
            // Keep the configured mirror URL as the dial/TLS identity. Only
            // the application Host/:authority follows Envoy's route-local
            // shadow contract.
            mirror_headers.push(("host".to_string(), shadow_host));
        }
        // gRPC mirrors need `te: trailers` after the generic strip removes `te`.
        synthesize_grpc_te_trailers_if_needed(&mut mirror_headers);
        let is_native_grpc = mirror_headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("content-type")
                && crate::proxy::backend_dispatch::is_native_grpc_content_type(value.as_bytes())
        });

        // Apply the operator-configured baggage strip
        // (`FERRUM_MESH_EGRESS_STRIP_BAGGAGE_KEYS`) so mesh-internal identity
        // claims like `source.principal` don't leak to mirror analytics /
        // auditing services that the operator considers off-mesh.
        self.http_client
            .strip_egress_baggage_in_vec(&mut mirror_headers);

        // Strip query params before ANY logging of the mirror URL — it is built
        // from the original request's query string and can carry secrets
        // (`?access_token=`, `?api_key=`, `?sig=`). Computed here, before the
        // permit-exhaustion drop path, so every log site uses the stripped form
        // (the full `mirror_url` is still used for the actual mirror request).
        let mirror_url_for_log = strip_query_params(&mirror_url).to_string();

        // Resolve the concurrency permit and any pre-buffer byte reservation.
        // An admitted request already owns both from the authorize phase; the
        // legacy path (body mirroring disabled or a direct invocation) acquires
        // the permit here exactly as before.
        let (permit, prereserved_lease) = match staged_state {
            Some(MirrorAdmissionState::Admitted { permit, lease }) => (permit, Some(lease)),
            Some(MirrorAdmissionState::Dropped(reason)) => {
                // Refused before the body was collected. The primary request
                // was unaffected and stayed streaming; publish the attributable
                // failure now that the target URL is known.
                warn!(
                    "request_mirror: dropped mirror request for {} {} at pre-buffer admission: {}",
                    method, mirror_url_for_log, reason
                );
                ctx.push_mirror_result_rx(completed_mirror_result(mirror_failure_meta(
                    self.plugin_config_id.clone(),
                    mirror_url_for_log,
                    reason,
                )));
                return PluginResult::Continue;
            }
            // Handled above; kept exhaustive so a future state cannot silently
            // fall through to an unadmitted dispatch.
            Some(MirrorAdmissionState::NotSelected | MirrorAdmissionState::Consumed { .. }) => {
                return PluginResult::Continue;
            }
            None => match self.mirror_in_flight.clone().try_acquire_owned() {
                Ok(permit) => (permit, None),
                Err(_) => {
                    self.metrics.bump_concurrency_drop();
                    warn!(
                        "request_mirror: dropping mirror request for {} {} because max_in_flight limit was reached",
                        method, mirror_url_for_log
                    );
                    ctx.push_mirror_result_rx(completed_mirror_result(mirror_failure_meta(
                        self.plugin_config_id.clone(),
                        mirror_url_for_log,
                        MIRROR_CONCURRENCY_DROP_ERROR,
                    )));
                    return PluginResult::Continue;
                }
            },
        };

        // The finalized backend-visible body, not `ctx.request_body_bytes` /
        // `ctx.metadata["request_body"]` — those hold the PRE-transform client
        // body, and replaying them is exactly the disclosure this advisory
        // describes. One `Bytes` allocation for the detached task; the primary
        // buffer is untouched.
        let body_bytes: Option<Bytes> = if self.mirror_request_body {
            Some(Bytes::copy_from_slice(body))
        } else {
            None
        };
        let observed_body_bytes = body_bytes.as_ref().map_or(0, |body| body.len() as u64);
        // Reconcile the pre-buffer reservation with the real length: shrink the
        // full-ceiling admission charge back into the budget, and refuse rather
        // than retain unbudgeted bytes if the body somehow exceeds what was
        // reserved or the plugin-local per-request ceiling.
        //
        // The two refusals are attributed separately. The proxy enforces the
        // combined request-body limit on the *collected* body, but a buffered
        // body normalizer runs after that check — configured request
        // decompression can inflate the stored buffer past this instance's
        // per-request ceiling. Reporting that as an exhausted aggregate budget
        // would point the operator at `max_retained_request_body_bytes` when
        // only `max_mirrored_request_body_bytes` can fix it.
        let body_lease = if observed_body_bytes > self.max_mirrored_request_body_bytes {
            // Release the staged full-ceiling reservation now rather than
            // holding it while the failure summary is published.
            drop(prereserved_lease);
            Err(MIRROR_BODY_CEILING_DROP_ERROR)
        } else {
            match prereserved_lease {
                Some(mut lease) => {
                    if lease.reconcile(observed_body_bytes) {
                        Ok(lease)
                    } else {
                        Err(MIRROR_BODY_BUDGET_DROP_ERROR)
                    }
                }
                None => self
                    .body_budget
                    .try_reserve(observed_body_bytes)
                    .ok_or(MIRROR_BODY_BUDGET_DROP_ERROR),
            }
        };
        let body_lease = match body_lease {
            Ok(lease) => lease,
            Err(reason) => {
                self.metrics.bump_budget_drop();
                warn!(
                    "request_mirror: dropped mirror request for {} {} after body collection: {}",
                    method, mirror_url_for_log, reason
                );
                drop(permit);
                ctx.push_mirror_result_rx(completed_mirror_result(mirror_failure_meta(
                    self.plugin_config_id.clone(),
                    mirror_url_for_log,
                    reason,
                )));
                return PluginResult::Continue;
            }
        };

        let backend_timeout_ms = ctx
            .matched_proxy
            .as_ref()
            .map(|p| p.backend_read_timeout_ms);
        let mirror_timeout = Duration::from_millis(resolve_mirror_timeout_ms(
            self.mirror_timeout_ms,
            backend_timeout_ms,
        ));

        // Seed the channel with a sanitized failure result. The detached
        // collector waits for the task's update, but if the task is cancelled
        // or panics its sender closes and the fallback becomes the explicit
        // mirror outcome instead of disappearing from observability.
        let task_fallback = mirror_failure_meta(
            self.plugin_config_id.clone(),
            mirror_url_for_log.clone(),
            MIRROR_TASK_INCOMPLETE_ERROR,
        );
        let (tx, rx) = tokio::sync::watch::channel(Some(task_fallback));
        ctx.push_mirror_result_rx(rx);

        let http_client = self.http_client.clone();
        let max_response_body_bytes = self.max_response_body_bytes;
        let mirror_plugin_id = self.plugin_config_id.clone();
        let body_for_request = body_bytes;
        let metrics = Arc::clone(&self.metrics);
        metrics.bump_dispatched();

        // Fire-and-forget: spawn an async task to send the mirror request.
        // The main request proceeds immediately — mirror latency has zero
        // impact on client response time.
        tokio::spawn(async move {
            // Hold both admission resources for the whole task lifetime. Both
            // release exactly once — on completion, timeout, transport/drain
            // error, or cancellation — because they are owned values dropped
            // when this future ends.
            let _permit = permit;
            let _retained_body_lease = body_lease;
            // Count a cancellation if this task is dropped (runtime shutdown,
            // panic, or future cancellation) before recording a terminal
            // outcome. Settled below once a terminal metric is recorded.
            let mut task_guard = MirrorTaskGuard::new(metrics);
            let start = std::time::Instant::now();

            // Native gRPC must speak HTTP/2 (h2c prior knowledge on cleartext,
            // ALPN h2 on TLS). Ordinary HTTP mirrors keep the default client so
            // HTTP/1.1 destinations continue to work.
            let outbound = if is_native_grpc {
                http_client.get_http2()
            } else {
                http_client.get()
            };

            let mut req_builder = match method.as_str() {
                "GET" => outbound.get(&mirror_url),
                "POST" => outbound.post(&mirror_url),
                "PUT" => outbound.put(&mirror_url),
                "DELETE" => outbound.delete(&mirror_url),
                "PATCH" => outbound.patch(&mirror_url),
                "HEAD" => outbound.head(&mirror_url),
                _ => outbound.request(
                    reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET),
                    &mirror_url,
                ),
            };

            // Always apply a finite deadline — never leave detached mirror work
            // unbounded when the primary proxy timeout is zero/absent.
            req_builder = req_builder.timeout(mirror_timeout);

            // Forward sanitized headers from the original (transformed) request.
            // The canonical secondary-request filter already removed hop-by-hop,
            // Connection-listed, framing, proxy-owned forwarding, and Host
            // fields; credential policy then stripped origin-bound secrets.
            for (key, value) in &mirror_headers {
                req_builder = req_builder.header(key.as_str(), value.as_str());
            }

            if let Some(body) = body_for_request {
                req_builder = req_builder.body(body);
            }

            // Route through `execute_redacted` so the mirror URL used in logs
            // and the returned error string is the query-stripped
            // `mirror_url_for_log`, never the full `mirror_url`. The full URL is
            // built from the original request's query params and can carry
            // credentials (`?access_token=...`, `?api_key=...`, `?sig=...`); a
            // raw `reqwest::Error` renders the full request URL in its Display
            // output, so stringifying it into `mirror_error` would leak those
            // secrets to every logging sink. `execute_redacted` reduces the
            // transport error to an `ErrorClass` plus the stripped URL.
            let response = if is_native_grpc {
                http_client
                    .execute_http2_redacted(req_builder, "request_mirror", &mirror_url_for_log)
                    .await
            } else {
                http_client
                    .execute_redacted(req_builder, "request_mirror", &mirror_url_for_log)
                    .await
            };
            let (status_code, response_size, advertised_size, error_msg) = match response {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    // Always drain/discard under byte + time bounds so HTTP/1.1
                    // keep-alive pools reclaim the socket even when
                    // Content-Length is known. Report advertised and observed
                    // sizes independently when CL was present.
                    let (advertised, drain) =
                        drain_mirror_response_body(resp, max_response_body_bytes).await;
                    let (size, body_error) = match drain {
                        MirrorDrainOutcome::Complete { observed } => {
                            task_guard.settle(MirrorTaskOutcome::Completed);
                            (Some(observed), None)
                        }
                        MirrorDrainOutcome::Truncated { observed } => {
                            task_guard.settle(MirrorTaskOutcome::DrainTruncation);
                            warn!(
                                "request_mirror: response from {} truncated at {} bytes \
                                     (max_response_body_bytes = {}; advertised = {:?})",
                                mirror_url_for_log, observed, max_response_body_bytes, advertised
                            );
                            (Some(observed), None)
                        }
                        MirrorDrainOutcome::Timeout => {
                            task_guard.settle(MirrorTaskOutcome::DrainTimeout);
                            warn!(
                                "request_mirror: response body drain timed out for {}",
                                mirror_url_for_log
                            );
                            (None, Some(MIRROR_DRAIN_TIMEOUT_ERROR.to_string()))
                        }
                        MirrorDrainOutcome::TransportFailure => {
                            task_guard.settle(MirrorTaskOutcome::DrainFailure);
                            (None, Some(MIRROR_DRAIN_TRANSPORT_ERROR.to_string()))
                        }
                    };
                    (Some(status), size, advertised, body_error)
                }
                Err(err) => {
                    // `err` is already sanitized by `execute_redacted`
                    // (ErrorClass + stripped URL); it never contains the query
                    // string. Use the same string for the log line and the
                    // structured `mirror_error` field. Classify the mirror
                    // deadline firing (never-responding target) as a timeout.
                    if redacted_error_is_timeout(&err) {
                        task_guard.settle(MirrorTaskOutcome::RequestTimeout);
                    } else {
                        task_guard.settle(MirrorTaskOutcome::RequestFailure);
                    }
                    warn!(
                        "request_mirror: failed to mirror {} {} → {}",
                        method, mirror_url_for_log, err
                    );
                    (None, None, None, Some(err))
                }
            };

            let elapsed = start.elapsed();

            let meta = MirrorResponseMeta {
                mirror_plugin_id,
                mirror_target_url: mirror_url_for_log,
                mirror_response_status_code: status_code,
                mirror_response_size_bytes: response_size,
                mirror_response_advertised_size_bytes: advertised_size,
                mirror_latency_ms: elapsed.as_secs_f64() * 1000.0,
                mirror_error: error_msg,
            };

            // Send to the watch channel. Transaction logging owns a detached
            // receiver for the task's full configured request lifetime, so a
            // late-but-valid result is not discarded at an unrelated cutoff.
            let _ = tx.send(Some(meta));
        });

        PluginResult::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::{RequestMirror, parse_mirror_host, strip_query_params};
    use crate::plugins::PluginHttpClient;
    use serde_json::json;
    use std::collections::HashMap;

    #[test]
    fn strip_query_params_removes_sensitive_query_data() {
        assert_eq!(
            strip_query_params("https://mirror.example.com:8443/path?token=secret&sig=abc"),
            "https://mirror.example.com:8443/path"
        );
        assert_eq!(
            strip_query_params("https://mirror.example.com:8443/path"),
            "https://mirror.example.com:8443/path"
        );
    }

    #[test]
    fn parse_mirror_host_brackets_ipv6_for_url_authority() {
        assert_eq!(
            parse_mirror_host("2001:db8::10").unwrap(),
            ("[2001:db8::10]".to_string(), None)
        );
        assert_eq!(
            parse_mirror_host("[2001:db8::10]").unwrap(),
            ("[2001:db8::10]".to_string(), None)
        );
    }

    #[test]
    fn build_mirror_url_uses_bracketed_ipv6_authority() {
        let plugin = RequestMirror::new(
            &json!({
                "mirror_host": "2001:db8::10",
                "mirror_port": 8443,
                "mirror_protocol": "https"
            }),
            PluginHttpClient::default(),
        )
        .unwrap();
        let mut query_params = HashMap::new();
        query_params.insert("page".to_string(), "1".to_string());

        assert_eq!(
            plugin.build_mirror_url("/shadow", None, &query_params),
            "https://[2001:db8::10]:8443/shadow?page=1"
        );
        assert_eq!(
            plugin.build_mirror_url("/shadow", Some("tag=red&tag=blue&q=a+b"), &query_params),
            "https://[2001:db8::10]:8443/shadow?tag=red&tag=blue&q=a+b"
        );
    }

    #[test]
    fn build_mirror_url_preserves_raw_query_edge_cases_byte_for_byte() {
        let plugin = RequestMirror::new(
            &json!({ "mirror_host": "mirror.example", "mirror_port": 8080 }),
            PluginHttpClient::default(),
        )
        .unwrap();
        let collapsed = HashMap::from([("tag".to_string(), "only-one".to_string())]);
        for raw in [
            "tag=red&tag=blue",
            "b=1&a=2",
            "flag",
            "empty=",
            "q=a+b",
            "path=%2Froot&k=a%26b",
            "key=a%2Fb",
            "name=%E2%9C%93&q=%C3%A9",
            "tag=red&tag=blue&q=a+b&flag&empty=&path=%2Froot&key=a%2Fb&name=%E2%9C%93",
        ] {
            let url = plugin.build_mirror_url("/api", Some(raw), &collapsed);
            assert!(
                url.ends_with(&format!("?{raw}")),
                "raw query must be preserved exactly: got {url}"
            );
            assert!(
                !url.contains("only-one"),
                "lossy query map must not replace raw query: {url}"
            );
        }
    }
}

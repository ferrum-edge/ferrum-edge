//! Plugin system with a trait-based architecture.
//!
//! Plugins execute in priority order (lower number = runs first) through
//! lifecycle phases: `on_request_received` → `authenticate` → `authorize` →
//! `normalize_buffered_request_body_before_before_proxy` →
//! `before_proxy` → backend-path policy enforcement →
//! deferred routing-header hooks → remaining deferred `before_proxy` hooks →
//! `transform_request_body` →
//! `on_final_request_body` → `backend_admission` → `after_proxy` →
//! `normalize_response_body` → `on_response_body` →
//! `transform_response_body` → `on_final_response_body` →
//! `on_response_committed` (buffered responses only) →
//! `on_response_stream_terminated` (streamed responses only) → `log` →
//! `on_ws_frame`.
//!
//! `backend_admission` runs last on the request side — after request-body
//! transforms and `on_final_request_body`, immediately before the backend
//! dispatch — so a rejected admission still skips the actual upstream call but
//! not the body hooks that precede it.
//!
//! Each plugin declares which protocols it supports via `supported_protocols()`.
//! The `PluginCache` pre-filters plugins per protocol at config reload time
//! so the hot path does zero filtering.
//!
//! Enabled plugin configs that fail validation cause startup or config reload
//! publication to fail; the gateway keeps the last known-good plugin cache on
//! reload. Disabled plugin configs are not instantiated.

pub mod a2a_gateway;
pub mod access_control;
pub mod adaptive_concurrency;
pub mod ai_federation;
pub mod ai_prompt_compressor;
pub mod ai_prompt_shield;
pub mod ai_rate_limiter;
pub mod ai_request_guard;
pub mod ai_response_guard;
pub mod ai_semantic_cache;
pub mod ai_semantic_firewall;
pub mod ai_stream_router;
pub mod ai_token_metrics;
pub mod ai_tool_governor;
pub mod ai_transcript_audit;
pub mod api_chargeback;
pub mod api_chargeback_sink;
pub mod basic_auth;
pub mod body_validator;
pub mod bot_detection;
pub mod builtin_parity;
pub mod chargeback;
pub mod compression;
pub mod correlation_id;
pub mod cors;
pub mod fault_injection;
pub mod geo_restriction;
pub mod graphql;
pub mod grpc_deadline;
pub mod grpc_method_router;
pub mod grpc_web;
pub mod hmac_auth;
pub mod http_logging;
pub mod ip_restriction;
pub mod jwks_auth;
pub mod jwt_auth;
pub mod kafka_logging;
pub mod key_auth;
pub mod ldap_auth;
pub mod load_testing;
pub mod loki_logging;
pub mod mcp_gateway;
pub mod mesh;
pub mod mesh_route_dispatch;
pub mod mtls_auth;
pub mod oauth2_introspection;
pub mod oidc_relying_party;
pub mod opa;
pub mod openapi_validator;
pub mod otel_tracing;
pub mod prometheus_metrics;
pub mod proxy_alerts;
pub mod rate_limiting;
pub mod request_deduplication;
pub mod request_mirror;
pub mod request_size_limiting;
pub mod request_termination;
pub mod request_transformer;
pub mod response_caching;
pub mod response_mock;
pub(crate) mod response_representation;
pub mod response_size_limiting;
pub mod response_transformer;
pub mod security_headers;
pub mod serverless_function;
pub mod soap_ws_security;
pub mod spec_expose;
pub mod sse;
pub mod statsd_logging;
pub mod stdout_logging;
pub mod tcp_connection_throttle;
pub mod tcp_logging;
pub mod transaction_debugger;
pub mod transaction_log_schema;
pub mod udp_logging;
pub mod udp_rate_limiting;
pub mod utils;
pub mod waf;
pub mod ws_frame_logging;
pub mod ws_logging;
pub mod ws_message_size_limiting;
pub mod ws_rate_limiting;

pub use builtin_parity::{
    BUILTIN_PLUGIN_PARITY_META, BuiltinPluginClassification, BuiltinPluginParityMeta,
    builtin_plugin_parity_meta,
};
pub use utils::PluginHttpClient;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use http::HeaderMap;
use percent_encoding::percent_decode_str;
use serde::ser::{Serialize, SerializeMap};
use serde_json::Value;
use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use self::utils::runtime_bool_gate::GatePolicyStamp;
use crate::config::types::{
    BackendScheme, BackendTlsConfig, Consumer, DispatchKind, HttpFlavor, Proxy,
    ResolvedPortOverride, RetryConfig, Upstream, UpstreamTarget,
};
use crate::consumer_index::ConsumerIndex;
use crate::modes::mesh::MeshTrafficDirection;
use crate::proxy::grpc_proxy::{
    GATEWAY_DEADLINE_EXCEEDED_MESSAGE, GATEWAY_DEADLINE_EXCEEDED_STATUS_HEADER,
};

/// Internal provenance marker set after a request-phase plugin has issued an
/// external operation whose result must not be replayed from an ambiguous
/// synthetic-response pipeline.
pub(crate) const EXTERNAL_OPERATION_COMPLETED_METADATA_KEY: &str =
    "ferrum:external_operation_completed";

/// Internal marker set when a request is committed to a synthetic rejection
/// before any external operation or backend dispatch could have started.
/// Ownership plugins consume it from `on_response_committed` to release this
/// request's exact local/distributed in-flight token safely.
pub(crate) const RELEASE_INFLIGHT_ON_COMMIT_METADATA_KEY: &str =
    "ferrum:release_dedup_inflight_on_commit";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtAuthAttributeValue {
    Scalar(String),
    StringList(Vec<String>),
}

/// Protocol categories that plugins can declare support for.
///
/// TLS/DTLS are transport-layer concerns — a plugin that works on TCP also
/// works on TCP+TLS, and similarly for UDP+DTLS. So we use 5 variants, not 7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyProtocol {
    /// HTTP/1.1, HTTP/2, HTTP/3 (includes HTTPS — TLS is transport-layer)
    Http,
    /// gRPC / gRPCs (HTTP/2-based RPC)
    Grpc,
    /// WebSocket / WSS
    WebSocket,
    /// Raw TCP stream proxy (includes TLS termination/origination)
    Tcp,
    /// Raw UDP datagram proxy (includes DTLS termination/origination)
    Udp,
}

/// All protocol variants, for plugins that support every protocol.
pub const ALL_PROTOCOLS: &[ProxyProtocol] = &[
    ProxyProtocol::Http,
    ProxyProtocol::Grpc,
    ProxyProtocol::WebSocket,
    ProxyProtocol::Tcp,
    ProxyProtocol::Udp,
];

/// HTTP-family protocols (HTTP, gRPC, WebSocket) — no raw stream support.
pub const HTTP_FAMILY_PROTOCOLS: &[ProxyProtocol] = &[
    ProxyProtocol::Http,
    ProxyProtocol::Grpc,
    ProxyProtocol::WebSocket,
];

/// HTTP + gRPC only (plugins that modify HTTP headers/body but not WebSocket frames).
pub const HTTP_GRPC_PROTOCOLS: &[ProxyProtocol] = &[ProxyProtocol::Http, ProxyProtocol::Grpc];

/// HTTP family + all stream protocols (TCP + UDP/DTLS). Used by plugins that
/// authenticate via TLS/DTLS client certificates across all transport types.
pub const HTTP_FAMILY_AND_STREAM_PROTOCOLS: &[ProxyProtocol] = &[
    ProxyProtocol::Http,
    ProxyProtocol::Grpc,
    ProxyProtocol::WebSocket,
    ProxyProtocol::Tcp,
    ProxyProtocol::Udp,
];

/// HTTP-only (single protocol).
pub const HTTP_ONLY_PROTOCOLS: &[ProxyProtocol] = &[ProxyProtocol::Http];

/// WebSocket-only (plugins that operate on WebSocket frames, not HTTP request/response).
pub const WS_ONLY_PROTOCOLS: &[ProxyProtocol] = &[ProxyProtocol::WebSocket];

/// Canonical metadata key for the request ID selected by the first configured
/// correlation-ID instance in lifecycle order.
///
/// Later instances retain their independently resolved values in
/// header-scoped slots and must not overwrite this consumer-facing key. The
/// first correlation instance claims ownership independently of any generic
/// metadata value an earlier custom plugin may have stored under this key.
pub const REQUEST_ID_METADATA_KEY: &str = "request_id";

/// Parser-level limits contributed by a WebSocket size-policy plugin.
///
/// The relay combines every applicable instance before either peer is read,
/// so the strictest frame and reassembled-message ceilings are enforced by
/// tungstenite itself rather than by a post-reassembly `on_ws_frame` hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSocketSizeLimits {
    /// Maximum payload bytes accepted in any one wire frame.
    pub max_frame_bytes: usize,
    /// Maximum payload bytes accepted after continuation reassembly.
    pub max_message_bytes: usize,
    /// RFC 6455 Close reason paired with code 1009 on either violation.
    pub close_reason: Arc<str>,
}

/// gRPC-only (single protocol).
pub const GRPC_ONLY_PROTOCOLS: &[ProxyProtocol] = &[ProxyProtocol::Grpc];

/// TCP-only (raw stream plugins that do not apply to UDP/DTLS).
pub const TCP_ONLY_PROTOCOLS: &[ProxyProtocol] = &[ProxyProtocol::Tcp];

/// UDP-only (datagram-level plugins that do not apply to TCP or HTTP).
pub const UDP_ONLY_PROTOCOLS: &[ProxyProtocol] = &[ProxyProtocol::Udp];

/// Apply the pre-filtered initial-response header policy chain in configured
/// priority order.
///
/// The plugin cache builds this list once per proxy/protocol generation. Callers
/// at protocol-specific client boundaries (notably WebSocket handshakes) can
/// therefore enforce deterministic response policy without filtering or
/// allocating on the request path. Ordinary HTTP responses continue to use the
/// full `after_proxy` lifecycle.
pub fn apply_initial_response_header_policies(
    policy_plugins: &[Arc<dyn Plugin>],
    response_headers: &mut HashMap<String, String>,
) {
    for plugin in policy_plugins {
        plugin.apply_initial_response_header_policy(response_headers);
    }
}

/// Representation metadata that becomes invalid whenever a buffered response
/// transform replaces the client-visible bytes.
const TRANSFORM_INVALIDATED_RESPONSE_HEADERS: &[&str] = &[
    "accept-ranges",
    "content-range",
    "content-md5",
    "digest",
    "content-digest",
    "repr-digest",
    "etag",
    "last-modified",
    "delta-base",
    "im",
    "variant-key",
    "signature",
    "signature-input",
    "content-signature",
    "content-signature-input",
    "content-checksum",
];

fn starts_with_ascii_case_insensitive(value: &str, prefix: &str) -> bool {
    value
        .as_bytes()
        .get(..prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix.as_bytes()))
}

fn is_transform_invalidated_response_header(name: &str) -> bool {
    TRANSFORM_INVALIDATED_RESPONSE_HEADERS
        .iter()
        .any(|header| name.eq_ignore_ascii_case(header))
        || starts_with_ascii_case_insensitive(name, "x-amz-checksum-")
        || starts_with_ascii_case_insensitive(name, "x-checksum-")
        || name.eq_ignore_ascii_case("x-goog-hash")
        || name.eq_ignore_ascii_case("x-ms-content-crc64")
}

/// Whether buffered response bytes may be rewritten while preserving the
/// response status semantics.
///
/// A `206 Partial Content` body is only the selected range, not a complete
/// representation. A `226 IM Used` body is a delta whose interpretation
/// depends on `IM` and `Delta-Base`. Rewriting either body while removing its
/// representation metadata would leave the unchanged status incoherent. Keep
/// both response forms untouched.
///
/// # Layering
///
/// This is the *presentation* rule, and it is the second half of one decision,
/// not a competing one. The shared representation gate
/// ([`response_representation`]) runs first on every buffered path and answers
/// the security question — whether a configured body policy claims these bytes:
///
/// * A claimed fragment never reaches this predicate. The gate rejects it
///   ([`response_representation::RepresentationRejection::PartialRepresentation`]),
///   because the gateway cannot reconstruct the complete resource and must not
///   present a rewritten slice as one.
/// * An unclaimed fragment reaches this predicate, which keeps it untouched so
///   presentation transforms (compression, gRPC-Web framing) cannot rewrite a
///   body the unchanged status no longer describes.
///
/// So a `206` is never both silently forwarded past a configured redaction and
/// never relabeled as a complete `200`. Plugins additionally consult this
/// predicate for their own behavior on fragments; that use is unchanged.
pub(crate) fn response_body_rewrite_allowed(response_status: u16) -> bool {
    !matches!(response_status, 206 | 226)
}

/// Drop every response header that describes the *previous* bytes.
///
/// Validators (`ETag`, `Last-Modified`), digests/checksums (`Digest`,
/// `Content-Digest`, `Content-MD5`, vendor checksum families), content-bound
/// signatures, and range/delta metadata are all bound to a specific octet
/// sequence. Once the gateway changes the client-visible bytes, keeping them
/// would hand the client a validator for a representation it never receives —
/// corrupting cache revalidation and integrity checks.
///
/// This is deliberately shared rather than inlined: **every** point that changes
/// the client-visible bytes must invalidate identically. Today that is a
/// permitted body rewrite ([`finalize_response_body_transformation`]) and a
/// representation decode
/// ([`response_representation::install_decoded_response_body`]) — including a
/// decode whose transform phase then matches no rule, which still replaces
/// encoded bytes with identity bytes and so still invalidates.
pub(crate) fn invalidate_content_bound_response_headers(
    response_headers: &mut HashMap<String, String>,
) {
    response_headers.retain(|name, _| !is_transform_invalidated_response_header(name));
}

/// Finalize one successful buffered response-body transformation.
///
/// Every protocol path calls this immediately after replacing the bytes and
/// recomputing `Content-Length`. The lifecycle owns invalidation of upstream
/// validators, range metadata, integrity digests, and content-bound signatures
/// so an individual transformer cannot accidentally leave stale metadata. The
/// plugin-specific hook runs afterward and may attach metadata it recomputed
/// for the new representation. Returning `None` from the transform skips this
/// function, preserving untouched response semantics — except that a
/// representation *decode* invalidates at the decode itself (see
/// [`invalidate_content_bound_response_headers`]), because it has already
/// changed the client-visible octets whether or not a rule then matches.
pub(crate) fn finalize_response_body_transformation(
    plugin: &dyn Plugin,
    ctx: &mut RequestContext,
    response_headers: &mut HashMap<String, String>,
) {
    invalidate_content_bound_response_headers(response_headers);
    plugin.on_response_body_transformed(ctx, response_headers);
}

/// Ordered outcome of deterministic initial-response policy for a buffered
/// response whose hook-visible map also contains trailer compatibility fields.
///
/// `desired_headers` starts from genuine backend initial HEADERS, while
/// `observed_headers` starts from the merged header+trailer view passed to
/// `after_proxy`. After each hook, [`Self::record_after_proxy_plugin`] advances
/// the desired map: policy plugins apply directly to genuine initial-header
/// state, while any mutation made by another (including custom) plugin is
/// copied from the already-ordered real hook result. This preserves priority
/// overrides and multiple-instance ordering without rerunning hooks or scanning
/// the plugin chain at the client boundary.
#[derive(Debug, Clone)]
pub struct BufferedInitialResponseHeaderPolicyState {
    header_names: Arc<Vec<String>>,
    desired_headers: HashMap<String, String>,
    observed_headers: HashMap<String, String>,
    /// Application-trailer outcomes immediately before initial-header policy
    /// first changed each name. A later non-policy hook clears the entry and
    /// owns both visible copies. Otherwise a final policy set/override restores
    /// this pre-policy outcome on the trailer channel, while a final policy
    /// removal suppresses both compatibility-view copies.
    pre_policy_application_trailers: HashMap<String, Option<String>>,
}

/// Header provenance for an uncommitted response that may be replaced by the
/// request's absolute gRPC deadline.
///
/// The pristine map is captured before response hooks run. Completed gateway
/// hooks then advance `observed_headers` and record only fields they added or
/// changed. Deadline replacement rebuilds from that gateway-owned output rather
/// than trusting a backend value merely because its name resembles a known
/// decorator. This state exists only for deadline-bound buffered responses.
#[derive(Debug, Clone)]
struct BufferedDeadlineResponseHeaderProvenance {
    observed_headers: HashMap<String, String>,
    gateway_headers: HashMap<String, String>,
    /// The backend response's original `Set-Cookie` lines (newline-separated,
    /// captured before any trusted hook runs). `Set-Cookie` provenance is
    /// line-granular: a trusted hook (sticky-affinity injection,
    /// `oidc_relying_party`'s rolling session, ...) commonly APPENDS its cookie
    /// onto the backend's existing `Set-Cookie` value, which mutation tracking
    /// would otherwise record wholesale — dragging the backend cookie across a
    /// synthesized DEADLINE_EXCEEDED response. Only lines absent from this
    /// backend baseline are gateway-authored and may cross. Empty for gateway
    /// rejections (no backend contributed the response).
    backend_set_cookie_lines: Vec<String>,
    /// The pristine BACKEND header snapshot, captured before any trusted hook
    /// runs. `Set-Cookie` is not the only field a trusted hook APPENDS to: a
    /// route-level response `add` rule appends onto an existing backend value
    /// with a comma (`apply_route_header_transforms`), so a backend
    /// `x-meta: secret` plus a route `add` of `public` yields
    /// `x-meta: secret,public`. Mutation tracking sees only "the field changed"
    /// and would record the whole post-hook value, crediting the backend
    /// portion as gateway-authored and crossing it onto a synthesized
    /// DEADLINE_EXCEEDED response. This baseline lets
    /// [`Self::gateway_appended_value`] partition such a value and keep only the
    /// appended elements. Empty for gateway rejections, and retired per field
    /// once a trusted hook declares authoritative ownership of it (see
    /// [`Self::record_gateway_mutations`]).
    backend_headers: HashMap<String, String>,
}

/// Case-insensitive membership test for a borrowed owned-header-name slice.
/// Written as a loop rather than an iterator chain so no temporary is built on
/// the deadline-provenance path.
fn header_name_is_declared(declared: &[&str], name: &str) -> bool {
    for candidate in declared {
        if candidate.eq_ignore_ascii_case(name) {
            return true;
        }
    }
    false
}

impl BufferedDeadlineResponseHeaderProvenance {
    fn backend_response(headers: &HashMap<String, String>) -> Self {
        let observed_headers = Self::canonical_snapshot(headers);
        let backend_set_cookie_lines = Self::set_cookie_lines(observed_headers.get("set-cookie"));
        Self {
            backend_headers: observed_headers.clone(),
            observed_headers,
            gateway_headers: HashMap::new(),
            backend_set_cookie_lines,
        }
    }

    /// Rejection headers are gateway/plugin output rather than backend
    /// metadata. Their provenance is already known; later non-replacing hooks
    /// are tracked by mutation like buffered responses.
    fn gateway_rejection(headers: &HashMap<String, String>) -> Self {
        let observed_headers = Self::canonical_snapshot(headers);
        let gateway_headers = observed_headers.clone();
        Self {
            observed_headers,
            gateway_headers,
            // A gateway rejection has no backend contribution, so every
            // `Set-Cookie` line — and every element of every other field — is
            // gateway-authored.
            backend_set_cookie_lines: Vec::new(),
            backend_headers: HashMap::new(),
        }
    }

    /// Split a `Set-Cookie` header value into its individual cookie lines. The
    /// gateway stores multiple `Set-Cookie` values newline-joined (RFC 6265
    /// requires separate header lines downstream); this recovers each line so
    /// backend-vs-gateway provenance can be tracked per cookie.
    fn set_cookie_lines(value: Option<&String>) -> Vec<String> {
        value
            .map(|value| value.split('\n').map(str::to_string).collect())
            .unwrap_or_default()
    }

    /// Reduce a live `Set-Cookie` value to only its gateway-authored lines by
    /// dropping every line the backend originally supplied. Returns `None` when
    /// nothing gateway-authored remains, so the caller drops the header entirely
    /// rather than crossing a backend cookie onto the deadline response.
    ///
    /// Matching is by OCCURRENCE, not by value membership: each backend line is
    /// consumed at most once. A trusted hook may author a cookie line that is
    /// byte-for-byte identical to one the backend already sent (a deterministic
    /// affinity cookie, or a session refresh that reproduces the upstream
    /// value). Value-only filtering would drop every copy including the
    /// gateway's, leaving the client with no cookie at all on a deadline
    /// rebuild.
    ///
    /// The exact invariant this enforces is therefore: a line survives only to
    /// the extent the live value carries MORE occurrences of it than the backend
    /// baseline did. Every backend-supplied occurrence is always dropped; only
    /// the surplus a trusted hook added crosses onto the deadline response. A
    /// hook that re-appends a byte-identical copy of a backend line is
    /// consequently indistinguishable from having authored it — that copy is
    /// treated as gateway-authored, which is the deliberate trade for not
    /// silently destroying deterministic gateway cookies.
    ///
    /// Implemented by [`Self::gateway_surplus_value`], which partitions by
    /// per-line occurrence count in a single linear pass (cookie-line counts are
    /// tiny, and the whole path runs only for a deadline-tracked response).
    ///
    /// Surplus filtering is the APPEND defence, so it is deliberately NOT
    /// consulted for a field a trusted hook authoritatively OWNS. Ownership is
    /// declared only for whole-value REPLACEMENT writes, which leave no backend
    /// line underneath; [`Self::record_gateway_mutations`] credits those
    /// directly and retires this baseline instead of calling here, so a
    /// replacement followed by a gateway append cannot be mistaken for a bare
    /// append and lose the operator-configured cookie.
    fn gateway_set_cookie_value(&self, value: &str) -> Option<String> {
        if self.backend_set_cookie_lines.is_empty() {
            // No backend contributed to this response (a gateway rejection), so
            // every line is gateway-authored. Skips the partition below entirely.
            return Some(value.to_string());
        }
        Self::gateway_surplus_value(
            value,
            "\n",
            self.backend_set_cookie_lines.iter().map(String::as_str),
        )
    }

    /// The ordinary-header counterpart of [`Self::gateway_set_cookie_value`]:
    /// reduce a changed list-valued header to only the elements a trusted hook
    /// APPENDED beyond the backend baseline, comma being the RFC 9110 list
    /// separator that route-level `add` rules use.
    ///
    /// Without this partition, a route override adding `x-meta: public` on top
    /// of a backend `x-meta: secret` produced `secret,public`, and mutation
    /// tracking recorded that whole value as gateway-authored — so a gRPC
    /// deadline rebuild emitted the backend's `secret` even though the backend
    /// response itself was discarded.
    ///
    /// Occurrence semantics, the trade they make, and the reason surplus (not
    /// value membership) is the test are identical to
    /// [`Self::gateway_set_cookie_value`]; see that docstring. A pure
    /// replacement is unaffected: none of its elements match the baseline, so
    /// the entire new value is surplus. A header with no backend baseline (a
    /// field the gateway introduced, or a gateway rejection) is wholly
    /// gateway-authored.
    fn gateway_appended_value(&self, name: &str, value: &str) -> Option<String> {
        let Some(backend_value) = self.backend_headers.get(name) else {
            return Some(value.to_string());
        };
        Self::gateway_surplus_value(value, ",", backend_value.split(','))
    }

    /// Occurrence-surplus partition shared by the `Set-Cookie` (newline-joined
    /// lines) and ordinary list-valued (comma-joined elements) paths.
    ///
    /// An element survives only to the extent the live value carries MORE
    /// occurrences of it than the backend baseline supplied. Returns `None` when
    /// nothing gateway-authored remains, so the caller drops the field rather
    /// than crossing backend data onto the deadline response.
    ///
    /// Runs in a single linear pass over both sides. The backend baseline is
    /// folded into an occurrence BUDGET keyed by element, and each live element
    /// either consumes one unit of that budget (a backend-supplied occurrence,
    /// dropped) or is surplus (gateway-authored, kept). The earlier formulation
    /// re-split the live value once per element to recount how often the element
    /// appeared before it, which is O(n^2) in the element count — and the
    /// element count is backend-controlled, since a backend can return a
    /// comma-list header with arbitrarily many elements and any gateway append
    /// to that field then forces the scan. The budget is exactly equivalent:
    /// consuming one unit per occurrence drops the first `k` copies for a
    /// baseline count of `k` and keeps the rest, which is what the recount's
    /// `seen_before >= k` test computed.
    fn gateway_surplus_value<'a>(
        value: &str,
        separator: &str,
        backend_elements: impl Iterator<Item = &'a str>,
    ) -> Option<String> {
        let mut backend_budget: HashMap<&str, usize> = HashMap::new();
        for element in backend_elements {
            *backend_budget.entry(element).or_insert(0) += 1;
        }
        let mut gateway_elements = Vec::new();
        for element in value.split(separator) {
            match backend_budget.get_mut(element) {
                // Still covered by the backend baseline: this occurrence came
                // from the backend and must not cross onto the deadline response.
                Some(remaining) if *remaining > 0 => *remaining -= 1,
                _ => gateway_elements.push(element),
            }
        }
        (!gateway_elements.is_empty()).then(|| gateway_elements.join(separator))
    }

    /// Retire, from a list-valued field's backend baseline, ONE occurrence of
    /// each element a completed trusted hook authored itself.
    ///
    /// This is the element-granular counterpart of the whole-field baseline
    /// retirement performed by the owned branch of
    /// [`Self::record_gateway_mutations`], for hooks that APPEND a known,
    /// gateway-configured element set onto a value the backend may also have
    /// supplied (`grpc_web` writing `access-control-expose-headers` from its
    /// configured `expose_headers`).
    ///
    /// Such a hook cannot declare whole-field ownership: that would credit the
    /// backend-only tokens sharing the field. Nor can it rely on mutation
    /// tracking alone: a backend that pre-populates the identical combined list
    /// makes the write invisible, and the deadline rebuild then drops the
    /// operator-configured tokens. Reducing the BASELINE instead keeps the
    /// ordinary occurrence partition in charge — the authored elements become
    /// surplus and are credited, backend-only elements keep their baseline
    /// occurrence and are dropped — and it stays correct for every later append,
    /// which continues to partition against a baseline that still describes the
    /// backend-only remainder.
    ///
    /// One occurrence per authored element is retired, never all of them, so a
    /// backend that repeated a token cannot launder the extra copies. Comparison
    /// is trimmed and, for ordinary headers, ASCII-case-insensitive per RFC 9110
    /// token rules; `set-cookie` lines are compared exactly (cookie values are
    /// case-sensitive). Retiring an element the backend also sent is safe: the
    /// gateway writes that element on this request regardless, so it is
    /// gateway-authored output either way.
    fn retire_backend_authored_elements(&mut self, name: &str, authored: &[&str]) {
        if name == "set-cookie" {
            for element in authored {
                let element = element.trim();
                if let Some(index) = self
                    .backend_set_cookie_lines
                    .iter()
                    .position(|line| line.trim() == element)
                {
                    self.backend_set_cookie_lines.remove(index);
                }
            }
        }
        let separator = if name == "set-cookie" { "\n" } else { "," };
        // Scoped so the baseline borrow ends before `backend_headers` is mutated.
        let rebuilt = {
            let Some(baseline) = self.backend_headers.get(name) else {
                return;
            };
            let mut remaining = baseline.split(separator).collect::<Vec<_>>();
            for element in authored {
                let element = element.trim();
                let found = remaining.iter().position(|candidate| {
                    let candidate = candidate.trim();
                    if name == "set-cookie" {
                        candidate == element
                    } else {
                        candidate.eq_ignore_ascii_case(element)
                    }
                });
                if let Some(index) = found {
                    remaining.remove(index);
                }
            }
            (!remaining.is_empty()).then(|| remaining.join(separator))
        };
        match rebuilt {
            Some(baseline) => {
                self.backend_headers.insert(name.to_string(), baseline);
            }
            None => {
                self.backend_headers.remove(name);
            }
        }
    }

    fn canonical_snapshot(headers: &HashMap<String, String>) -> HashMap<String, String> {
        let mut entries = headers.iter().collect::<Vec<_>>();
        entries.sort_unstable_by_key(|(left, _)| *left);
        let mut canonical = HashMap::with_capacity(entries.len());
        for (name, value) in entries {
            let lowercase = name.to_ascii_lowercase();
            if name == &lowercase || !canonical.contains_key(&lowercase) {
                canonical.insert(lowercase, value.clone());
            }
        }
        canonical
    }

    /// `is_owned` is consulted per canonical (lowercase) field name and reports
    /// whether the completed hook authoritatively wrote that field. It is a
    /// predicate rather than a name slice so callers can answer from data they
    /// already hold — no owned-name `Vec`/`String` is materialized on the hot
    /// path (see [`RequestContext::record_deadline_owned_response_headers`]).
    fn record_gateway_mutations(
        &mut self,
        is_owned: impl Fn(&str) -> bool,
        headers: &HashMap<String, String>,
    ) {
        self.record_gateway_mutations_with_repartition(is_owned, |_| false, headers);
    }

    /// As [`Self::record_gateway_mutations`], plus `needs_repartition`: fields
    /// whose backend baseline this same recording just narrowed
    /// ([`Self::retire_backend_authored_elements`]) and which therefore must be
    /// re-partitioned even though their live value is byte-identical to what was
    /// last observed.
    ///
    /// The plain net-diff short-circuit is exactly the case the element
    /// recorder exists to defend: a backend that pre-populates the identical
    /// combined list leaves the gateway's write invisible, so without this the
    /// retired baseline is never consulted and the configured elements are
    /// dropped from the synthesized deadline response. A repartitioned field
    /// takes the occurrence-partition branch, never the owned branch, so
    /// backend-only elements sharing the field still cannot cross over.
    fn record_gateway_mutations_with_repartition(
        &mut self,
        is_owned: impl Fn(&str) -> bool,
        needs_repartition: impl Fn(&str) -> bool,
        headers: &HashMap<String, String>,
    ) {
        let current = Self::canonical_snapshot(headers);
        for (name, value) in &current {
            let owned = is_owned(name.as_str());
            let changed = self.observed_headers.get(name) != Some(value)
                || owned
                || needs_repartition(name.as_str());
            if !changed {
                continue;
            }
            if name == "set-cookie" && owned {
                // Ownership is declared ONLY for whole-value REPLACEMENT writes
                // (`response_transformer` `update` to `set-cookie`, a `rename`
                // whose destination is `set-cookie`, or an `add` that
                // re-inserted `set-cookie` into a slot a `remove` had cleared).
                // Appending sites — sticky-affinity injection — deliberately do
                // NOT declare ownership; they record through
                // `record_deadline_response_header_mutations` and stay on the
                // occurrence-partition branch below, so the backend's cookie can
                // never ride an append into gateway output.
                //
                // A replacement overwrites the entire field, so NO backend line
                // survives underneath it: the replacement's own value plus any
                // gateway append that follows it is wholly gateway-authored.
                // The baseline must therefore be retired unconditionally rather
                // than only when the surplus happens to be empty. Gating on
                // "zero surplus" inferred replacement-ness from the value shape,
                // which misreads a replacement FOLLOWED BY an append recorded
                // under one provenance record: the surplus branch credited only
                // the appended line, dropped the operator-configured replacement
                // cookie, and left a stale backend baseline that then filtered
                // later gateway appends matching the overwritten backend value.
                // Same rationale as `adopt_gateway_rejection`: once the backend
                // bytes are gone from the tracked map, the baseline no longer
                // describes it.
                self.gateway_headers.insert(name.clone(), value.clone());
                self.backend_set_cookie_lines = Vec::new();
                self.backend_headers.remove(name);
            } else if name == "set-cookie" {
                // `Set-Cookie` is line-granular: record only the gateway-authored
                // cookie lines so a hook that appends its cookie onto the
                // backend's existing value never drags the backend cookie into
                // gateway-owned output. When only backend lines remain, drop the
                // header from gateway output entirely.
                match self.gateway_set_cookie_value(value) {
                    Some(gateway_value) => {
                        self.gateway_headers.insert(name.clone(), gateway_value);
                    }
                    None => {
                        self.gateway_headers.remove(name);
                    }
                }
            } else if owned {
                // Ownership of an ordinary header is only ever declared for
                // WHOLE-VALUE gateway writes: unconditional replacements
                // (`update` rules and fired `rename` destinations) and `add`
                // rules that actually INSERTED into an absent slot (the
                // add-after-remove sequence, where the final map can be
                // byte-identical to the backend's). An `add` that appended onto
                // an existing value is deliberately NOT declared owned — it
                // stays on the append-partition branch below. So the whole
                // configured value is gateway output. Retire this field's
                // backend baseline for the same reason as the `set-cookie`
                // branch above — the backend value was overwritten, and leaving
                // a stale baseline would make a later append partition against
                // data no longer in the response.
                self.gateway_headers.insert(name.clone(), value.clone());
                self.backend_headers.remove(name);
            } else {
                // A mutation-detected change may be an append rather than a
                // replacement (a route-level `add` rule appends onto the
                // existing backend value with a comma). Credit only the
                // appended elements so the backend portion never crosses onto a
                // synthesized DEADLINE_EXCEEDED response.
                match self.gateway_appended_value(name, value) {
                    Some(gateway_value) => {
                        self.gateway_headers.insert(name.clone(), gateway_value);
                    }
                    None => {
                        self.gateway_headers.remove(name);
                    }
                }
            }
        }
        for name in self.observed_headers.keys() {
            if !current.contains_key(name) {
                self.gateway_headers.remove(name);
            }
        }
        self.observed_headers = current;
    }

    fn retain_gateway_output(&mut self, headers: &mut HashMap<String, String>) {
        let preserve_origin_vary = headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("vary")
                && value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("origin"))
        });

        // `gateway_headers` already holds only gateway-authored output, so this
        // strip governs gateway-produced values, not backend leakage. It removes
        // transport/framing fields and stale cache/representation metadata that
        // must never ride a synthesized DEADLINE_EXCEEDED response. `set-cookie`
        // is deliberately absent: a trusted hook (e.g. `oidc_relying_party`'s
        // refreshed session cookie or sticky-affinity injection) authors it
        // precisely so the client applies the update. Every backend-supplied
        // cookie OCCURRENCE is dropped before a value reaches `gateway_headers`,
        // even when a hook APPENDS its cookie onto the backend value —
        // `record_gateway_mutations` keeps only the surplus beyond the backend
        // baseline (see `gateway_set_cookie_value`) — so retaining
        // gateway-authored `set-cookie` cannot re-open backend cookie leakage.
        // The one deliberate exception is documented there: a trusted hook that
        // re-appends a byte-identical copy of a backend line is credited with
        // authoring that copy, because the alternative destroys deterministic
        // gateway cookies. The other way a cookie reaches `gateway_headers` is an
        // owned whole-value REPLACEMENT, which by definition left no backend line
        // underneath and retires the baseline; the appending proxy-core sites do
        // not declare ownership, so they cannot reach that branch.
        // Ordinary list-valued headers get the same treatment through
        // `gateway_appended_value`: a route-level `add` rule appends onto the
        // backend value with a comma, so only the appended elements reach
        // `gateway_headers` and the backend portion never crosses here either.
        // `x-grpc-web` is gRPC-Web framing regenerated by the deadline error
        // response; a completed hook must not overwrite the canonical
        // `x-grpc-web: 1` (the buffered replacement extends the generated error
        // headers with this retained map before finalization captures the
        // value), so it is stripped here like the other framing fields.
        *headers = self.gateway_headers.clone();
        headers.retain(|name, _| {
            ![
                "accept-ranges",
                "age",
                "authorization",
                "cache-control",
                "cdn-cache-control",
                "connection",
                "content-digest",
                "content-encoding",
                "content-language",
                "content-length",
                "content-location",
                "content-md5",
                "content-range",
                "content-type",
                "cookie",
                "digest",
                "etag",
                "expires",
                "grpc-accept-encoding",
                "grpc-encoding",
                "grpc-message",
                "grpc-previous-rpc-attempts",
                "grpc-retry-pushback-ms",
                "grpc-status",
                "grpc-status-details-bin",
                "keep-alive",
                "last-modified",
                "pragma",
                "proxy-authenticate",
                "proxy-authorization",
                "proxy-connection",
                "proxy-status",
                "repr-digest",
                "retry-after",
                "surrogate-control",
                "te",
                "trailer",
                "transfer-encoding",
                "upgrade",
                "www-authenticate",
                "x-grpc-web",
                "vary",
                "warning",
            ]
            .contains(&name.as_str())
        });
        if preserve_origin_vary {
            headers.insert("vary".to_string(), "Origin".to_string());
        }
        self.observed_headers = Self::canonical_snapshot(headers);
    }

    /// Transition an in-flight buffered-response provenance into a gateway
    /// rejection without discarding decorations that completed hooks already
    /// recorded. The rejection headers are freshly generated gateway output, so
    /// they join `gateway_headers`, while previously recorded gateway output
    /// (correlation, CORS, ...) is preserved for a terminal deadline rebuild.
    /// The observed baseline resets to the rejection headers so any non-replacing
    /// reject hook that runs next is tracked by mutation. When no gateway output
    /// was recorded yet, `gateway_headers` is empty and this is identical to
    /// starting a fresh [`Self::gateway_rejection`].
    ///
    /// # Why the backend baselines are retired here
    ///
    /// (The reasoning below is written for `backend_set_cookie_lines`; it
    /// applies verbatim to the `backend_headers` append baseline, which is
    /// captured from the same discarded backend map.)
    ///
    /// `headers` is a gateway-authored REPLACEMENT map, never the mutated
    /// backend response map. Every caller of
    /// [`RequestContext::begin_rejection_deadline_response_header_provenance`]
    /// reaches it with either a freshly constructed map, a
    /// `PluginResult::Reject{,Binary}` header map lifted out by
    /// `plugin_result_into_reject_parts`, or gateway-synthesized error headers.
    /// The two sites whose caller-supplied map has backend lineage
    /// (`apply_plugin_rejection_response` and
    /// `apply_reject_after_proxy_and_synthetic_body_hooks`) both run
    /// `rebuild_plugin_rejection_response_headers` first, which does
    /// `response_headers.clear()` before re-populating from the rejection parts.
    /// So no backend-sent header survives into this transition.
    ///
    /// That makes `backend_set_cookie_lines` — the baseline captured from the
    /// BACKEND response map in [`Self::backend_response`] — no longer a
    /// description of the map being tracked. Continuing to filter against it
    /// misattributed authorship: a rejection that intentionally sets
    /// `Set-Cookie: X` while the discarded backend response happened to have
    /// sent a byte-identical `Set-Cookie: X` scored zero surplus occurrences and
    /// was dropped, so a later gRPC-deadline rebuild silently discarded an
    /// authored rejection/session cookie.
    ///
    /// Retiring the baseline does not weaken the leak boundary. It is the
    /// buffered path's [`Self::record_gateway_mutations`] that defends against
    /// backend cookies, and it still holds the baseline for as long as the
    /// backend map is the response. A backend-only `Set-Cookie` can only reach a
    /// deadline response by being present in some map, and after this transition
    /// the backend map is gone — the response is rebuilt from the rejection.
    /// Keeping a stale baseline could therefore only produce further false
    /// drops, never prevent a real leak.
    fn adopt_gateway_rejection(&mut self, headers: &HashMap<String, String>) {
        let rejection = Self::canonical_snapshot(headers);
        for (name, value) in &rejection {
            self.gateway_headers.insert(name.clone(), value.clone());
        }
        // The backend response map has been replaced wholesale by gateway
        // output, so neither the backend cookie baseline nor the backend
        // header baseline describes what is being tracked. Retire both,
        // matching [`Self::gateway_rejection`], so hooks that run after this
        // transition are credited for what they actually author on the
        // rejection map.
        self.backend_set_cookie_lines = Vec::new();
        self.backend_headers = HashMap::new();
        self.observed_headers = rejection;
    }

    fn sync_terminal_headers(&mut self, headers: &HashMap<String, String>) {
        self.observed_headers = Self::canonical_snapshot(headers);
    }
}

impl BufferedInitialResponseHeaderPolicyState {
    /// Build state from cache-prefiltered policy names. Returns `None` when no
    /// initial-response policy is configured, leaving ordinary buffered paths
    /// allocation-free.
    pub fn new(
        header_names: Arc<Vec<String>>,
        initial_headers: &HashMap<String, String>,
        merged_headers: &HashMap<String, String>,
    ) -> Option<Self> {
        if header_names.is_empty() {
            return None;
        }
        Some(Self {
            desired_headers: Self::select_headers(&header_names, initial_headers),
            observed_headers: Self::select_headers(&header_names, merged_headers),
            pre_policy_application_trailers: HashMap::new(),
            header_names,
        })
    }

    fn select_headers(
        header_names: &[String],
        source: &HashMap<String, String>,
    ) -> HashMap<String, String> {
        let mut selected = HashMap::with_capacity(header_names.len());
        for name in header_names {
            if let Some(value) = Self::header_value_ci(source, name) {
                selected.insert(name.clone(), value.clone());
            }
        }
        selected
    }

    fn header_value_ci<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a String> {
        headers.get(name).or_else(|| {
            headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value)
        })
    }

    fn remove_header_ci(headers: &mut HashMap<String, String>, name: &str) {
        headers.retain(|key, _| !key.eq_ignore_ascii_case(name));
    }

    /// Select the effective value after one hook and canonicalize every
    /// case-insensitive spelling to the cache-owned lowercase name. If a later
    /// plugin inserted a differently-cased duplicate alongside the previously
    /// observed canonical entry, the changed value is the mutation that wins.
    fn canonicalize_header_after_mutation(
        headers: &mut HashMap<String, String>,
        name: &str,
        observed: Option<&str>,
    ) -> Option<String> {
        let current = headers
            .get(name)
            .filter(|value| observed != Some(value.as_str()))
            .cloned()
            .or_else(|| {
                headers
                    .iter()
                    .filter(|(key, value)| {
                        key.as_str() != name
                            && key.eq_ignore_ascii_case(name)
                            && observed != Some(value.as_str())
                    })
                    .min_by(|(left, _), (right, _)| left.cmp(right))
                    .map(|(_, value)| value.clone())
            })
            .or_else(|| Self::header_value_ci(headers, name).cloned());

        Self::remove_header_ci(headers, name);
        if let Some(value) = current.as_ref() {
            headers.insert(name.to_string(), value.clone());
        }
        current
    }

    /// Advance the genuine-initial-header outcome after one real hook has run.
    /// Values are cloned only when a hook actually changes a policy-owned name.
    pub fn record_after_proxy_plugin(
        &mut self,
        plugin: &dyn Plugin,
        response_headers: &mut HashMap<String, String>,
    ) {
        if plugin.is_initial_response_header_policy() {
            plugin.apply_initial_response_header_policy(&mut self.desired_headers);
            for name in self.header_names.iter() {
                let previous_value = self.observed_headers.get(name).cloned();
                let desired_value = self.desired_headers.get(name).cloned();
                if previous_value != desired_value {
                    self.pre_policy_application_trailers
                        .entry(name.clone())
                        .or_insert(previous_value.clone());
                    Self::remove_header_ci(response_headers, name);
                    if let Some(value) = desired_value.as_ref() {
                        response_headers.insert(name.clone(), value.clone());
                    }
                }
                let current = Self::canonicalize_header_after_mutation(
                    response_headers,
                    name,
                    previous_value.as_deref(),
                );
                match current {
                    Some(value) => {
                        self.observed_headers.insert(name.clone(), value);
                    }
                    None => {
                        self.observed_headers.remove(name);
                    }
                }
            }
            return;
        }

        self.record_later_response_header_mutations(response_headers);
    }

    /// Advance policy-owned initial-header state after a later response phase
    /// changes representation metadata. Body transforms run after the ordered
    /// `after_proxy` chain, so their final edits and removals must remain
    /// authoritative when the buffered response is split back onto the wire.
    pub fn record_later_response_header_mutations(
        &mut self,
        response_headers: &mut HashMap<String, String>,
    ) {
        for name in self.header_names.iter() {
            let observed = self.observed_headers.get(name).cloned();
            let current = Self::canonicalize_header_after_mutation(
                response_headers,
                name,
                observed.as_deref(),
            );
            if observed == current {
                continue;
            }
            match current {
                Some(value) => {
                    self.desired_headers.insert(name.clone(), value.clone());
                    self.observed_headers.insert(name.clone(), value);
                    self.pre_policy_application_trailers.remove(name);
                }
                None => {
                    self.desired_headers.remove(name);
                    self.observed_headers.remove(name);
                    self.pre_policy_application_trailers.remove(name);
                }
            }
        }
    }

    /// Return the pre-policy application-trailer outcome and whether the final
    /// policy keeps this name in genuine initial headers. Reconciliation uses
    /// the presence flag to distinguish a final set/override from a removal;
    /// `None` leaves the ordinary merged-view outcome authoritative.
    pub fn application_trailer_initial_response_policy_outcome(
        &self,
        name: &str,
    ) -> Option<(Option<&str>, bool)> {
        let pre_policy_value = self.pre_policy_application_trailers.get(name)?;
        Some((
            pre_policy_value.as_deref(),
            self.desired_headers.contains_key(name),
        ))
    }

    /// Apply the final ordered policy-owned fields to genuine initial HEADERS.
    pub fn apply_to_initial_headers(&self, response_headers: &mut HashMap<String, String>) {
        for name in self.header_names.iter() {
            Self::remove_header_ci(response_headers, name);
            if let Some(value) = self.desired_headers.get(name) {
                response_headers.insert(name.clone(), value.clone());
            }
        }
    }
}

/// How plugin construction or validation failures affect cache publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginFailurePolicy {
    /// Reject startup/reload instead of serving without the configured plugin.
    FailClosed,
    /// Reject reload publication so callers continue serving the last cache.
    /// Startup also rejects because there is no previous cache to keep.
    KeepLastKnownGood,
    /// Log the construction failure and omit the plugin from the published cache.
    OptionalFailOpen,
}

/// Cold-path plugin registration metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PluginRegistration {
    pub name: &'static str,
    pub failure_policy: PluginFailurePolicy,
}

const fn builtin_plugin(
    name: &'static str,
    failure_policy: PluginFailurePolicy,
) -> PluginRegistration {
    PluginRegistration {
        name,
        failure_policy,
    }
}

/// Direction of a UDP datagram being proxied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpDatagramDirection {
    ClientToBackend,
    BackendToClient,
}

/// Context for per-datagram UDP plugin hooks.
///
/// Passed to `on_udp_datagram` for every datagram when at least one plugin
/// on the proxy opts in via `requires_udp_datagram_hooks()`. Fired in both
/// directions: client→backend (before forwarding) and backend→client (before
/// relaying the response to the client).
#[allow(dead_code)]
pub struct UdpDatagramContext<'a> {
    /// Canonical client IP identity. IPv4-mapped IPv6 is normalized once when
    /// the UDP/DTLS session is created so per-datagram hooks only clone this Arc.
    pub client_ip: Arc<str>,
    pub proxy_id: Arc<str>,
    pub proxy_name: Option<Arc<str>>,
    pub listen_port: u16,
    pub datagram_size: usize,
    pub direction: UdpDatagramDirection,
    /// Datagram payload bytes, borrowed for the duration of the hook call so
    /// there is no per-datagram allocation. For plain UDP these are the raw
    /// wire bytes; for DTLS-terminated sessions they are the decrypted
    /// application plaintext; for passthrough they are the encrypted wire
    /// bytes. `payload_kind` disambiguates so content-inspecting plugins know
    /// whether L7 scanning is meaningful.
    pub payload: &'a [u8],
    /// Nature of `payload`.
    pub payload_kind: StreamBytesKind,
    /// Optional sink for recording session-scoped metadata (e.g. WAF signature
    /// hits) onto the UDP/DTLS stream transaction summary. The per-datagram
    /// context is immutable and short-lived, so a plugin that wants its findings
    /// logged writes them here; the proxy backs it with the session metadata map
    /// that `build_udp_stream_summary` / `build_dtls_stream_summary` read at
    /// disconnect. `None` when there is no session map to attach to (or in tests).
    pub metadata_sink: Option<UdpMetadataSink<'a>>,
}

/// Sink for recording session-scoped metadata from the per-datagram UDP/DTLS
/// hook (see [`UdpDatagramContext::metadata_sink`]).
///
/// `on_udp_datagram` receives an immutable, per-datagram context, so unlike the
/// TCP `on_stream_connect` path it cannot mutate a `StreamConnectionContext` to
/// attach `waf.*` fields. This sink bridges that gap: the proxy backs it with the
/// session's metadata map, so a recorded field rides the stream transaction
/// summary out to every logging sink at disconnect — independent of
/// `log_to_stdout`, matching the TCP behavior.
#[derive(Clone, Copy)]
pub struct UdpMetadataSink<'a> {
    map: &'a std::sync::Mutex<HashMap<String, String>>,
}

impl<'a> UdpMetadataSink<'a> {
    /// Wrap a session metadata map as a sink.
    pub fn new(map: &'a std::sync::Mutex<HashMap<String, String>>) -> Self {
        Self { map }
    }

    /// Atomically read-modify-write the session metadata map under one lock.
    ///
    /// Inspecting plugins use this to *merge* per-datagram findings across a
    /// session rather than overwrite them — e.g. union the matched rule ids and
    /// keep the highest severity seen — so a later, lower-severity datagram
    /// cannot erase earlier hits (last-write-wins). Holding the lock across the
    /// whole read-modify-write also keeps the concurrent bidirectional datagram
    /// tasks from racing on the same key.
    pub fn update<F: FnOnce(&mut HashMap<String, String>)>(&self, f: F) {
        let mut map = self
            .map
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        f(&mut map);
    }
}

/// Verdict from a per-datagram UDP plugin hook.
///
/// Unlike HTTP plugins which return status codes and bodies, UDP datagrams
/// are silently dropped when rate limited — standard UDP behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpDatagramVerdict {
    /// Forward the datagram to its destination.
    Forward,
    /// Silently drop the datagram (standard UDP flood mitigation).
    Drop,
}

/// Nature of the opening stream bytes (TCP) or datagram payload (UDP) handed to
/// a stream-aware inspection plugin such as the WAF.
///
/// Content inspection (L7 signature scanning) is only meaningful on plaintext
/// application bytes — either raw plaintext on the wire, or bytes the proxy
/// recovered after terminating TLS/DTLS. Passthrough proxies forward ciphertext
/// the gateway never decrypts, so only transport-shape checks (e.g. validating a
/// TLS ClientHello) are possible there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamBytesKind {
    /// Plaintext application bytes observed directly on the wire (plain TCP /
    /// plain UDP). Both L7-inspectable and representative of the raw client
    /// bytes, so transport-shape checks also apply.
    PlaintextWire,
    /// Encrypted wire bytes from a passthrough (non-terminating) proxy. Suitable
    /// only for transport-shape checks (e.g. TLS/DTLS ClientHello), never L7.
    EncryptedWire,
    /// Application bytes recovered after the proxy terminated TLS/DTLS. These are
    /// L7-inspectable; the transport was already proven to be TLS/DTLS by the
    /// completed handshake.
    DecryptedApp,
}

impl StreamBytesKind {
    /// Whether L7 signature scanning of these bytes is meaningful.
    pub fn is_l7_inspectable(self) -> bool {
        matches!(self, Self::PlaintextWire | Self::DecryptedApp)
    }
}

/// Direction of a WebSocket frame being proxied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocketFrameDirection {
    ClientToBackend,
    BackendToClient,
}

/// Precomputed, allocation-light observation for a frame that will be emitted
/// only after the destination sink accepts the final post-plugin message.
///
/// The shared H1/H2/H3 relay prepares these **before** `send()` moves the
/// message (so large payloads are never cloned solely for logging) and emits
/// them only on the same success boundary as the per-direction frame/byte
/// counters. Cancelled or failed sends discard the prepared observation.
#[derive(Debug, Clone)]
pub struct WsFrameDeliveryObservation {
    /// Stable frame-type label (`text`, `binary`, `ping`, `pong`, `close`, `frame`).
    pub frame_type: &'static str,
    /// Operator-visible size. For Close frames with a status code this is
    /// `2 + reason.len()` (status code bytes plus reason); Close without a
    /// code is `0`. Application Close reasons are never logged in the clear.
    pub size_bytes: usize,
    /// Optional keyed payload fingerprint for Text/Binary only.
    pub preview: Option<String>,
    /// RFC 6455 close status code when `frame_type == "close"` and a code was
    /// present. Never accompanied by the raw reason string.
    pub close_code: Option<u16>,
    /// UTF-8 reason byte length when a Close code was present.
    pub close_reason_len: Option<usize>,
}

/// Context passed to `on_ws_disconnect` when a WebSocket session ends.
///
/// Mirrors the information made available on `StreamTransactionSummary`
/// for TCP/UDP streams so logging/metrics plugins have parity across all
/// three protocols. `direction` identifies which half of the frame relay
/// terminated first and `io_side` identifies whether that half failed while
/// reading from its source or writing to its destination. `None` for both
/// indicates a clean close initiated by either peer or an upgrade that never
/// established frame flow.
///
/// Populated once per accepted WebSocket upgrade, including H2 Extended
/// CONNECT (RFC 8441) sessions. The frame relay code should construct
/// this at session teardown and dispatch it to any plugin whose
/// `requires_ws_disconnect_hooks()` returns true.
#[derive(Debug, Clone)]
pub struct WsDisconnectContext {
    pub namespace: String,
    pub proxy_id: String,
    pub proxy_name: Option<String>,
    pub client_ip: String,
    /// Backend target URL (scheme://host:port/path) — matches the
    /// `backend_target` field from the original upgrade request.
    pub backend_target: String,
    /// Listener port on the gateway that accepted the upgrade.
    pub listen_port: u16,
    /// Process-local accepted WebSocket session ID allocated at upgrade
    /// admission (`ProxyState.ws_connection_counter`).
    ///
    /// Identical to the `connection_id` passed to every `on_ws_frame` call for
    /// this session, including H1/H2/H3 relay teardown, peer close/error,
    /// plugin cancellation, idle/drain timeout, and H1/H2 upgrade-handoff
    /// failure. The value is **not** globally unique across gateway processes;
    /// operators aggregating logs from multiple instances must join on
    /// `(gateway_instance_id, proxy_id, connection_id)` (or an equivalent
    /// host/process identity + `proxy_id` + `connection_id` tuple).
    pub connection_id: u64,
    /// Total session lifetime in milliseconds (upgrade → close).
    pub duration_ms: f64,
    /// Number of frames proxied from client toward backend.
    /// Success-only: incremented after the destination sink accepts a forward
    /// (including successfully forwarded peer Close frames). Cancelled or
    /// failed writes and plugin policy Closes that never complete a counted
    /// forward are omitted.
    pub frames_client_to_backend: u64,
    /// Number of frames proxied from backend toward client.
    /// Success-only; see [`Self::frames_client_to_backend`].
    pub frames_backend_to_client: u64,
    /// Total payload bytes proxied from client toward backend over the
    /// lifetime of this WebSocket session.
    /// Success-only and aligned with `ws_frame_logging` `size_bytes` (Close
    /// frames with a status code contribute `2 + reason.len()`).
    pub bytes_client_to_backend: u64,
    /// Total payload bytes proxied from backend toward client over the
    /// lifetime of this WebSocket session.
    /// Success-only; see [`Self::bytes_client_to_backend`].
    pub bytes_backend_to_client: u64,
    /// Wall-clock session start (RFC3339). Captured at upgrade and carried
    /// through delayed `ws_logging` delivery so collectors do not depend on
    /// receipt time for event ordering.
    pub timestamp_connected: String,
    /// Wall-clock session end (RFC3339). Sampled once at teardown alongside
    /// `duration_ms` so disconnect records remain self-contained under batch
    /// flush, retry, and reconnect delay.
    pub timestamp_disconnected: String,
    /// Which direction observed the first terminating error. `None` for
    /// clean close initiated by either peer.
    pub direction: Option<Direction>,
    /// Which I/O side inside the failing direction observed the error. This
    /// disambiguates `BackendToClient` reads from the backend versus writes to
    /// a disconnected client.
    pub io_side: Option<crate::proxy::tcp_proxy::StreamIoSide>,
    /// Classification of the terminating error, if any.
    pub error_class: Option<crate::retry::ErrorClass>,
    /// Consumer identity associated with the upgrade (copied from
    /// the originating `RequestContext`).
    pub consumer_username: Option<String>,
    /// Authentication mechanism that succeeded for the upgrade request.
    pub auth_method: Option<&'static str>,
    /// Correlation ID / tracing metadata inherited from the upgrade request.
    pub metadata: HashMap<String, String>,
    /// Ownership generation captured at WebSocket upgrade admission. Not
    /// serialized; used by `proxy_alerts` to reject stale disconnect samples
    /// after delete→recreate of the same proxy ID.
    #[doc(hidden)]
    pub proxy_lifecycle_generation: Option<u64>,
}

/// One-request/session cache for the authoritative, canonical client IP.
///
/// Client-IP resolution is complete before policy hooks run. The first policy
/// that needs a typed address parses that final string, canonicalizes
/// IPv4-mapped IPv6, and publishes the result here. Every later plugin instance
/// performs only the lock-free `OnceLock::get_or_init` fast path. `None` is
/// cached as well, preserving fail-closed behavior for malformed identities.
/// When embedded privately in [`RequestContext`], the same typed state also
/// retains authoritative HTTP correlation values. Stream contexts keep their
/// correlation lifecycle state separately so replacing this public cache to
/// reparse a changed client IP cannot erase stream correlation ownership.
#[derive(Debug, Clone, Default)]
pub struct CanonicalClientIpCache {
    value: OnceLock<Option<IpAddr>>,
    correlation_ids: CorrelationIdState,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct CorrelationIdState {
    canonical: Option<String>,
    instances: HashMap<String, String>,
}

impl CorrelationIdState {
    fn publish_correlation_id(&mut self, instance_key: &str, request_id: String) -> bool {
        let publish_canonical = self.canonical.is_none();
        self.instances
            .insert(instance_key.to_string(), request_id.clone());
        if publish_canonical {
            self.canonical = Some(request_id);
        }
        publish_canonical
    }

    fn correlation_id(&self, instance_key: &str) -> Option<&str> {
        self.instances.get(instance_key).map(String::as_str)
    }

    fn canonical_correlation_id(&self) -> Option<&str> {
        self.canonical.as_deref()
    }

    pub(crate) fn project_correlation_ids(&self, metadata: &mut HashMap<String, String>) {
        for (key, value) in &self.instances {
            metadata.insert(key.clone(), value.clone());
        }
        if let Some(request_id) = &self.canonical {
            metadata.insert(REQUEST_ID_METADATA_KEY.to_string(), request_id.clone());
        }
    }
}

impl CanonicalClientIpCache {
    fn get_or_parse(&self, client_ip: &str) -> Option<IpAddr> {
        *self
            .value
            .get_or_init(|| parse_canonical_client_ip(client_ip))
    }

    /// Whether a policy has already resolved the typed address.
    ///
    /// This is exposed for external regression tests that verify multiple
    /// plugin instances share one parse. Runtime policy should call the context
    /// accessors instead.
    #[doc(hidden)]
    pub fn is_initialized(&self) -> bool {
        self.value.get().is_some()
    }

    fn publish_correlation_id(&mut self, instance_key: &str, request_id: String) -> bool {
        self.correlation_ids
            .publish_correlation_id(instance_key, request_id)
    }

    fn correlation_id(&self, instance_key: &str) -> Option<&str> {
        self.correlation_ids.correlation_id(instance_key)
    }

    fn canonical_correlation_id(&self) -> Option<&str> {
        self.correlation_ids.canonical_correlation_id()
    }

    fn project_correlation_ids(&self, metadata: &mut HashMap<String, String>) {
        self.correlation_ids.project_correlation_ids(metadata);
    }
}

fn parse_canonical_client_ip(client_ip: &str) -> Option<IpAddr> {
    parse_client_ip_literal(client_ip).map(|ip| ip.to_canonical())
}

/// Parse the legacy client/rule literal forms without allocation.
///
/// IPv4 uses the standard library's strict literal grammar. Brackets and zone
/// identifiers remain IPv6-only; accepting them on IPv4 would broaden the
/// established policy grammar.
fn parse_client_ip_literal(client_ip: &str) -> Option<IpAddr> {
    if let Ok(ipv4) = client_ip.parse() {
        return Some(IpAddr::V4(ipv4));
    }

    let unbracketed = client_ip
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(client_ip);
    let without_zone = unbracketed
        .find('%')
        .map_or(unbracketed, |index| &unbracketed[..index]);
    without_zone.parse::<Ipv6Addr>().ok().map(IpAddr::V6)
}

/// AI usage that was produced by a built-in accounting path.
///
/// This is deliberately carried outside [`RequestContext::metadata`]. Backend
/// responses and operator-configured metadata writers can populate arbitrary
/// public metadata keys, so those keys are not authoritative provenance for
/// Prometheus token or cost export.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiCost {
    /// Whole micro-units of configured currency.
    pub microunits: u64,
    /// Fractional micro-units at 10^-12 precision. Kept separate so the full
    /// supported whole-cost range still fits in `u64`.
    pub submicrounits: u64,
}

/// Number of fixed-point remainder units in one micro-unit.
pub(crate) const AI_COST_SUBMICRO_SCALE: u64 = 1_000_000_000_000;

impl AiCost {
    pub(crate) fn from_currency_units(value: f64) -> Option<Self> {
        if !value.is_finite() || value < 0.0 {
            return None;
        }

        let scaled = value * 1_000_000.0;
        if !scaled.is_finite() || scaled > u64::MAX as f64 {
            return None;
        }

        let whole_microunits = scaled.floor();
        let mut microunits = whole_microunits as u64;
        let mut submicrounits =
            ((scaled - whole_microunits) * AI_COST_SUBMICRO_SCALE as f64).round() as u64;
        if submicrounits >= AI_COST_SUBMICRO_SCALE {
            microunits = microunits.checked_add(1)?;
            submicrounits -= AI_COST_SUBMICRO_SCALE;
        }
        Some(Self {
            microunits,
            submicrounits,
        })
    }
}

#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiUsageExport {
    pub prefix: Arc<str>,
    pub provider: &'static str,
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
    pub cost: Option<AiCost>,
}

impl AiUsageExport {
    fn token_completeness(&self) -> usize {
        usize::from(self.prompt_tokens.is_some())
            + usize::from(self.completion_tokens.is_some())
            + usize::from(self.total_tokens.is_some())
    }

    fn completeness(&self) -> usize {
        self.token_completeness() + usize::from(self.cost.is_some())
    }
}

/// Per-instance WAF anomaly accumulator for one request.
///
/// `identity` is the stable validated plugin-config id used in transaction
/// metadata. `score` accumulates only that instance's rule contributions across
/// request/response phases.
#[derive(Debug, Clone)]
pub(crate) struct WafInstanceScoreState {
    pub(crate) identity: std::sync::Arc<str>,
    pub(crate) score: u32,
}

/// Exclusive compression response-buffer permit held on a request context.
///
/// Clones are empty so `RequestContext`'s derived `Clone` stays valid: the
/// permit is unique and must be transferred with `take()` / `mem::take` when a
/// compatibility clone needs to own the reserved slot.
#[derive(Default)]
struct HeldResponseBufferPermit(Option<tokio::sync::OwnedSemaphorePermit>);

impl std::fmt::Debug for HeldResponseBufferPermit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("HeldResponseBufferPermit")
            .field(&self.0.is_some())
            .finish()
    }
}

impl Clone for HeldResponseBufferPermit {
    fn clone(&self) -> Self {
        Self(None)
    }
}

impl HeldResponseBufferPermit {
    fn set(&mut self, permit: tokio::sync::OwnedSemaphorePermit) {
        self.0 = Some(permit);
    }

    fn take(&mut self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.0.take()
    }
}

/// Complete provenance of the response-side presentation policy a finalized
/// replay (`RequestContext::finalized_response_replay`) intentionally skips.
///
/// A retained representation may replay only while it is provably compatible
/// with *every* such policy, which needs two independent halves:
///
/// - `gate` — content digest of the published RTDS response-side gate map.
///   Gates flip at any moment with no config reload and no new plugin instance,
///   so nothing else can witness them. Being content-derived rather than a
///   pointer identity, it means the same thing in every process, which is what
///   a representation retained in a shared store has to be compared against.
/// - `presentation` — content digest of the effective *static* rules of every
///   plugin whose response-body transform the replay skips, folded in
///   configured execution order (see [`Plugin::response_presentation_policy`]
///   for the enrolled set and the audited exclusions). Static rules cannot
///   change under one live instance, but a representation persisted to Redis
///   outlives the instance, the generation, and the process, so an unchanged
///   gate map says nothing about whether the redaction/header/body rules still
///   match. `None` means the effective presentation policy could not be
///   established for this request — either no plugin-cache view was attached,
///   or the proxy carries a plugin whose response-body rewrite is derived from
///   live runtime state that no construction-time digest can describe
///   ([`ResponsePresentationPolicy::Dynamic`]). Both are "unprovable", never
///   "no policy".
///
/// Provability, then equality, is the whole security decision: replay is
/// admitted only when both sides are complete *and* equal, so a change to
/// either half — or the inability to establish either half — retires every
/// representation captured under the old policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResponsePolicyProvenance {
    gate: [u8; 32],
    presentation: Option<[u8; 32]>,
}

impl ResponsePolicyProvenance {
    /// The two halves, or `None` when the presentation policy could not be
    /// established and the provenance is therefore incomplete.
    ///
    /// Only a complete value may be retained for replay at all — in Redis,
    /// which outlives this process, or in the local map, where a later request
    /// under the same live policy would otherwise be served bytes whose
    /// producing policy was never witnessed.
    pub(crate) fn complete(&self) -> Option<([u8; 32], [u8; 32])> {
        let presentation = self.presentation?;
        Some((self.gate, presentation))
    }

    /// Whether this (live) provenance admits replaying a representation stored
    /// under `stored`.
    ///
    /// An incomplete value matches nothing — including another incomplete
    /// value. Two requests that both failed to establish the presentation
    /// policy have not thereby proven they share one: "unknown" is not
    /// evidence, and deriving `PartialEq` alone would have made
    /// `None == None` silently admit exactly the replay this guard exists to
    /// stop.
    pub(crate) fn admits_replay_of(&self, stored: &Self) -> bool {
        match (self.complete(), stored.complete()) {
            (Some(live), Some(stored)) => live == stored,
            _ => false,
        }
    }

    /// Rebuild a value from a persisted record. Both halves are required, so a
    /// payload that carried no provenance cannot be reconstructed at all.
    pub(crate) fn from_persisted(gate: [u8; 32], presentation: [u8; 32]) -> Self {
        Self {
            gate,
            presentation: Some(presentation),
        }
    }
}

/// How completely a plugin's response-side *presentation* policy can be
/// described to a representation that will be replayed later.
///
/// See [`Plugin::response_presentation_policy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponsePresentationPolicy {
    /// The client-visible rewrite is a pure function of accepted static
    /// configuration, captured by this content digest. Two processes loading
    /// equivalent configuration derive the same value, so a retained
    /// representation can be proven compatible anywhere.
    Static([u8; 32]),
    /// The client-visible rewrite is derived from live runtime state — data
    /// this gateway refreshes from upstream on its own schedule, per session,
    /// after the plugin was constructed — so no digest computed at construction
    /// describes it, and no digest of *any* fixed size could without persisting
    /// the runtime state itself.
    ///
    /// A proxy carrying such a plugin has no provable presentation policy at
    /// all: the per-proxy fold collapses to `None` and every consumer that
    /// would retain a finalized representation must fail closed. Config
    /// admission rejects the composition outright
    /// (`request_deduplication::validate_composition`); this variant is the
    /// runtime backstop for the paths that only warn.
    Dynamic,
}

/// Context passed through the plugin pipeline for a single request.
///
/// Headers and query parameters are lazily materialized to avoid per-request
/// allocations on the hot path. The raw `http::HeaderMap` and query string are
/// stored at request init time; the `HashMap<String, String>` representations
/// are only built when a plugin phase actually needs them (via
/// `materialize_headers()` / `materialize_query_params()`). Query
/// materialization preserves the raw query string so security plugins can still
/// inspect duplicate pairs that collapse in the parsed `HashMap`.
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// Gateway-resolved client IP used for request accounting and legacy
    /// plugins. This may be rewritten from trusted forwarding headers after
    /// the context is created.
    pub client_ip: String,
    /// Immediate downstream socket peer IP captured before trusted-proxy
    /// resolution. Mesh authz uses this for Istio `source.ip` so forwarded
    /// `remote.ip` cannot masquerade as the direct peer.
    pub direct_client_ip: String,
    canonical_client_ip: CanonicalClientIpCache,
    pub method: String,
    /// Canonical policy path (`crate::policy_path`). Every security decision —
    /// routing, WAF, `openapi_validator`, `request_termination`, authorization,
    /// cache/replay keys, rewrites, and the assembled backend request line —
    /// must read this field so none of them can act on a different semantic
    /// path than the backend executes (advisory `GHSA-69xf-42xm-4w4f`).
    pub path: String,
    /// The client's request target exactly as received, retained only when
    /// canonicalization changed it. This private field is accessible only to
    /// the descendant `hmac_auth` module through an opaque, debug-redacted
    /// wrapper. Its wire signature binds the literal bytes the client signed.
    /// Never route, authorize, or log this value.
    raw_path: Option<hmac_auth::HmacWirePath>,
    /// Canonical client-request authority for authentication mechanisms that
    /// bind signatures to the selected virtual host. Hostnames are
    /// ASCII-lowercased with a trailing DNS dot removed; an explicit
    /// non-default port is retained. HTTP frontends populate this after
    /// Host/`:authority` validation and before authentication.
    pub request_authority: Option<String>,
    /// Whether the browser-facing request used a cryptographic transport.
    /// HTTP/1.1, HTTP/2, and HTTP/3 initialize this from the accepted frontend
    /// transport, then a direct peer in `FERRUM_TRUSTED_PROXIES` may override it
    /// with a valid singleton overwrite or XFF-correlated appended
    /// `X-Forwarded-Proto: http` or `https` value. Cookie storage checks combine
    /// this with `request_authority` because browsers also trust HTTP localhost
    /// and loopback origins.
    pub request_is_secure: bool,
    /// Frontend listener port that accepted this HTTP-family request.
    /// HTTP proxy resources do not carry `listen_port`, so mesh authorization
    /// uses this to evaluate Istio `to.ports` matches for HTTP traffic.
    pub frontend_listen_port: Option<u16>,
    /// SNI hostname from the frontend TLS/QUIC handshake for HTTP-family
    /// requests. Populated only when the downstream client supplied SNI.
    pub frontend_sni_hostname: Option<String>,
    /// Load-balancer snapshot generation pinned by this request. Backend
    /// admission uses it to reject a retired service-discovery target view
    /// after a structural target-set publication.
    pub lb_generation: u64,
    /// Per-proxy lifecycle ownership generation captured at routing/admission
    /// from the published plugin-cache generation. Carried into transaction
    /// summaries so `proxy_alerts` can reject samples from a prior
    /// delete→recreate incarnation of the same proxy ID. `None` when no proxy
    /// matched.
    pub proxy_lifecycle_generation: Option<u64>,
    /// Raw HTTP headers from the request. Stored at init time and retained
    /// after `materialize_headers()` so security plugins can evaluate
    /// multi-value / non-UTF-8 field lines without the lossy folded map.
    /// Core proxy lookups (IP resolution, host extraction) read from this
    /// directly via `raw_header_get()` to avoid eagerly converting every
    /// header to an owned `String`.
    raw_headers: Option<HeaderMap>,
    /// Materialized headers HashMap. Empty until `materialize_headers()` is
    /// called. Plugin code and backend dispatch read from this field.
    pub headers: HashMap<String, String>,
    /// Whether [`Self::materialize_headers`] has already populated `headers`
    /// from `raw_headers`. Keeps materialization one-shot while preserving the
    /// raw map for policy evaluation (mirrors query-param materialization).
    headers_materialized: bool,
    /// Raw query string stored for lazy parsing. `None` when empty. Preserved
    /// after query-param materialization so security plugins can inspect raw
    /// duplicate pairs.
    raw_query_string: Option<String>,
    /// Whether either decoded or raw query-param materialization has already
    /// populated `query_params`. Keeps materialization one-shot while preserving
    /// `raw_query_string` for inspection.
    query_params_materialized: bool,
    /// Parsed query parameters. Empty until `materialize_query_params()` or
    /// `materialize_query_params_raw()` is called.
    ///
    /// HTTP/1.1 and HTTP/2 materialize percent-decoded query params for
    /// historical compatibility. HTTP/3 materializes raw query params unless
    /// an active plugin explicitly requires the decoded representation.
    pub query_params: HashMap<String, String>,
    pub matched_proxy: Option<Arc<Proxy>>,
    pub identified_consumer: Option<Arc<Consumer>>,
    /// Identity string set by external auth plugins (e.g., `jwks_auth`) when no
    /// matching `Consumer` exists in the gateway. Used as the rate-limit key and
    /// for `consumer_username` in transaction logs.
    pub authenticated_identity: Option<String>,
    /// Human-readable identity for the `X-Consumer-Username` header sent to the
    /// backend. Falls back to `authenticated_identity` when not set separately.
    pub authenticated_identity_header: Option<String>,
    /// Authoritative GeoIP country assertion staged by `geo_restriction` for
    /// backend dispatch. Kept outside the mutable plugin header map and public
    /// metadata so later request hooks cannot replace or log a forged value.
    backend_geo_country: Option<[u8; 2]>,
    /// Authentication mechanism that succeeded (e.g., `"jwt_auth"`, `"key_auth"`).
    /// `&'static str` because every `AuthMechanism::mechanism_name()` returns a
    /// compiled-in literal — zero allocation on the hot path.
    pub auth_method: Option<&'static str>,
    pub timestamp_received: DateTime<Utc>,
    /// Whether the request's gRPC deadline state has been initialized from the
    /// inbound `grpc-timeout` value. Initialization happens once, immediately
    /// after routing and before any request-plugin or body-buffering await.
    pub(crate) grpc_deadline_initialized: bool,
    /// Whether the inbound request supplied a valid positive `grpc-timeout`.
    /// Keep this source fact separate from the effective budget so an earlier
    /// default policy cannot satisfy a later `reject_no_deadline` policy.
    pub(crate) grpc_deadline_had_valid_client_timeout: bool,
    /// Monotonic receipt instant captured with the request context. Effective
    /// budgets are added to this exact anchor, independent of wall-clock jumps.
    pub(crate) grpc_deadline_received_at: tokio::time::Instant,
    /// Whether the gateway's full ordered deadline-policy preflight completed.
    /// Direct plugin callers that skip the preflight still apply each instance
    /// from `before_proxy` for backward-compatible composition.
    pub(crate) grpc_deadline_preflight_complete: bool,
    /// Effective receipt-anchored gRPC budget after every `grpc_deadline`
    /// policy has applied its default/cap decision. Kept separate from the
    /// relative header forwarded upstream so retries never re-arm the budget.
    pub(crate) grpc_deadline_budget_ms: Option<u64>,
    /// Single monotonic absolute deadline shared by request phases, backend
    /// attempts, retry backoff, and streaming response bodies.
    pub(crate) grpc_deadline_at: Option<tokio::time::Instant>,
    /// Once any `grpc_deadline` instance requests gateway-time subtraction,
    /// every later instance forwards the same remaining budget instead of
    /// subtracting receipt-to-hook elapsed time again.
    pub(crate) grpc_deadline_header_is_remaining: bool,
    /// Whether the gateway selected the canonical client-visible deadline
    /// response for this request. Keep this typed provenance out of metadata:
    /// backend or plugin-controlled `grpc-status`/`grpc-message` text must not
    /// unlock the write-biased terminal H3 completion path.
    gateway_deadline_response_selected: bool,
    /// Monotonic request-global proof that at least one response-caching
    /// instance served a HIT or REVALIDATED response. Kept outside public
    /// metadata so sibling/custom plugins cannot clear or forge the signal
    /// consumed by fail-closed response negotiation.
    response_cache_hit: bool,
    /// Extra metadata plugins can attach
    pub metadata: HashMap<String, String>,
    /// Most complete built-in AI usage snapshot for Prometheus export.
    /// Kept outside public metadata so backend/operator metadata cannot mint or
    /// overwrite trusted token and cost series.
    pub(crate) ai_usage_export: Option<AiUsageExport>,
    /// Prefix that supplied the selected token fields. Cost is selected
    /// independently, so its provenance cannot distort later token tie-breaks.
    ai_usage_export_token_prefix: Option<Arc<str>>,
    /// Prefix that supplied the selected trusted cost. This remains private so
    /// public metadata cannot influence deterministic multi-instance pricing.
    ai_usage_export_cost_prefix: Option<Arc<str>>,
    /// Aggregate CORS policy state staged across every attached CORS instance
    /// and consumed by the cache-inserted CORS finalizer. Kept outside public
    /// metadata so policy details never enter transaction logs.
    pub(crate) cors_state: cors::CorsRequestState,
    /// Claim-derived upstream headers committed by the first accepted
    /// authentication attempt and held until `before_proxy`. Kept out of
    /// `metadata` so authorization-phase rejection logging can never serialize
    /// raw claim values.
    pub(crate) pending_claim_headers: HashMap<String, String>,
    /// Lowercase `claim_headers` destinations already sanitized for this
    /// request. Gateway-owned destinations are stripped exactly once, by the
    /// first plugin instance that owns them, so a later instance sharing a
    /// destination can never erase a verified value an earlier instance already
    /// installed. Empty (and non-allocating) unless a `claim_headers` mapping is
    /// configured.
    pub(crate) sanitized_claim_header_destinations: HashSet<String>,
    /// Credential header names precomputed by the plugin cache for safe
    /// diagnostics and policy calls. Kept outside public metadata so plugin
    /// configuration details do not enter transaction logs.
    request_headers_to_redact: Option<Arc<Vec<String>>>,
    /// Buffered response policy provenance, present only while the ordered
    /// `after_proxy` chain is processing a merged gRPC header+trailer view.
    /// Shared through `Arc` so the rare hook-preflight context clone remains
    /// cheap; the live request uses `Arc::make_mut` after the clone is dropped.
    buffered_initial_response_header_policy_state:
        Option<Arc<BufferedInitialResponseHeaderPolicyState>>,
    /// Backend/gateway response-header provenance used only when an absolute
    /// gRPC deadline can replace an uncommitted buffered response.
    buffered_deadline_response_header_provenance:
        Option<Arc<BufferedDeadlineResponseHeaderProvenance>>,
    /// Client-visible HTTP flavor classified before any plugin hook can mutate
    /// request headers. Fault rejection shaping consults this fixed value so a
    /// transformer cannot add or remove native-gRPC semantics mid-pipeline.
    request_http_flavor: HttpFlavor,
    /// The client's original `Accept-Encoding` field value, captured with the
    /// raw wire headers before any `before_proxy` hook runs.
    ///
    /// The representation gate decides whether it may publish decoded identity
    /// bytes from what the CLIENT negotiated, and by the time it runs the
    /// header map no longer describes that: `request_transformer` (priority
    /// 3000) can remove or rewrite `Accept-Encoding` before `compression`
    /// (priority 4050) ever takes its own snapshot, and `compression` itself
    /// strips the header for the backend request. Both would erase an explicit
    /// `identity;q=0` and let a protected encoded response be decoded and served
    /// as a representation the client refused.
    ///
    /// Kept as a private write-once field rather than in `ctx.metadata` so no
    /// plugin can rewrite or delete the evidence it records. Set exactly once,
    /// at request init, by [`crate::proxy::stamp_original_request_metadata`].
    original_accept_encoding: Option<String>,
    /// Whether client-visible rejection responses for this request cross a
    /// WebSocket handshake boundary. Set once after request-flavor detection so
    /// the shared reject finalizer can remove transport-owned handshake fields
    /// after every ordered response hook without reclassifying or allocating.
    websocket_response_boundary: bool,
    /// Per-`ai_semantic_cache`-instance embedding vectors staged between
    /// `before_proxy` and `on_final_response_body`. Kept out of `metadata` so
    /// high-dimensional vectors cannot enter transaction logs. The outer key is
    /// a process-unique cache instance ID so sibling instances on one proxy
    /// cannot overwrite or consume each other's staged vectors.
    pub(crate) ai_semantic_cache_embeddings: HashMap<u64, Vec<f32>>,
    /// Per-instance semantic-cache scope keys paired with
    /// `ai_semantic_cache_embeddings`.
    pub(crate) ai_semantic_cache_scope_keys: HashMap<u64, String>,
    /// OpenAPI validator operation matches staged between `before_proxy` and
    /// final body hooks. Kept out of public metadata so per-instance state does
    /// not leak into transaction logs.
    pub(crate) openapi_validator_matches: HashMap<usize, (String, String)>,
    /// Per-`ai_tool_governor`-instance internal correlation markers staged between
    /// `on_response_body` / `transform_response_body` and the
    /// `on_final_response_body` re-check. Kept out of public `metadata` so this
    /// per-request bookkeeping — the governed-body hash and the per-call
    /// identity multiset, both DERIVED FROM RAW TOOL ARGUMENTS — never reaches
    /// transaction logs (an operator who disabled `observability.hash_arguments`
    /// must not get an arg-derived hash logged via a correlation marker).
    /// The outer key is a process-unique governor instance ID. Multiple
    /// instances may coexist on one proxy and must never consume each other's
    /// dedup state.
    pub(crate) ai_tool_governor_response_hashes: HashMap<u64, String>,
    /// `ai_response_guard` instances that inspected an already-finalized
    /// deduplication replay and found content requiring a current-policy
    /// redaction transform. Kept outside public metadata so response data or a
    /// custom plugin cannot opt a replay into or out of mandatory rewriting.
    pub(crate) ai_response_guard_replay_redactions: HashSet<u64>,
    /// `ai_tool_governor` equivalent of
    /// `ai_response_guard_replay_redactions`. Instance scoping prevents one
    /// governor from consuming another instance's transform requirement.
    pub(crate) ai_tool_governor_replay_redactions: HashSet<u64>,
    /// Per-instance governed-call identity multisets (identity hash -> count),
    /// the one-for-one skip ledgers final re-checks consume. Kept off
    /// `metadata` for the same reason as the response hashes.
    pub(crate) ai_tool_governor_call_hashes: HashMap<u64, HashMap<String, usize>>,
    /// Per-instance governed-request-body hashes, staged in `before_proxy` for
    /// the `on_final_request_body` re-check. Same leak class as the response
    /// markers (a hash over the raw request body including tool-call arguments),
    /// so they remain off `metadata` too.
    pub(crate) ai_tool_governor_request_hashes: HashMap<u64, String>,
    /// Per-instance buffered `redact_args` rewrites computed during governance
    /// amplification preflight and consumed by the response-body transform.
    /// Keys are digests of `(tool name, raw args)`; aggregate value bytes are
    /// capped at the plugin's 4 MiB inspectable window, and at most one plugin
    /// instance may stage a memo set at once, so multiple configured governors
    /// cannot multiply that retained window between hooks.
    pub(crate) ai_tool_governor_redaction_memos: HashMap<u64, HashMap<String, String>>,
    /// Per-`ai_semantic_firewall`-instance hashes of request bodies already
    /// inspected before request transforms. Kept outside serialized metadata so
    /// prompt-derived digests never enter transaction logs.
    pub(crate) ai_semantic_firewall_request_hashes: HashMap<u64, String>,
    /// Per-instance response-body hashes used to skip unchanged final bodies and
    /// re-evaluate transformed client-visible representations. Also private for
    /// the same prompt/response confidentiality reason.
    pub(crate) ai_semantic_firewall_response_hashes: HashMap<u64, String>,
    /// Per-`request_deduplication`-instance completion state acquired during
    /// `before_proxy`. Keeping this out of public metadata prevents internal
    /// cache keys and lock tokens from entering transaction logs. The map is
    /// bounded by the configured deduplication instances on the matched proxy.
    pub(crate) request_deduplication_states:
        HashMap<u64, request_deduplication::RequestDeduplicationRequestState>,
    /// Whether this request is replaying an already-finalized client
    /// representation — a `response_caching` HIT/REVALIDATED or a
    /// `request_deduplication` idempotent replay. The shared synthetic
    /// rejection path must not run ordinary presentation transforms (body or
    /// response-header rewrite rules) over it again. Inspection and final-body
    /// validation still run over the replayed client representation, and a
    /// current redaction decision can require its own transform or fail closed.
    /// Kept private so request metadata cannot suppress transforms or inspection,
    /// and unrelated synthetic short-circuits cannot opt into the skip.
    pub(crate) finalized_response_replay: bool,
    /// Response-side runtime-overlay gate provenance, pinned once for this
    /// request (see [`GatePolicyStamp`]).
    ///
    /// Plugins that persist a client-visible representation across requests
    /// (today `response_caching`) stamp this value onto the stored entry and
    /// refuse to replay an entry stamped with a different policy, so a
    /// representation produced under one runtime-overlay policy can never be
    /// replayed under another. Pinning once per request — rather than reading
    /// the gates again at storage time — is what makes the stamp provenance
    /// rather than a guess. Kept private so request metadata cannot forge one.
    pub(crate) response_policy_stamp: Option<GatePolicyStamp>,
    /// Content digest of the effective *static* response-side presentation
    /// policy for this request's proxy and protocol: every enrolled instance's
    /// accepted config ([`Plugin::response_presentation_policy`]), folded in
    /// configured execution order.
    ///
    /// Copied once from the request's plugin-cache view, so it describes
    /// exactly the instances that will run on this request's response path.
    /// `None` means the effective policy could not be established — either no
    /// view was attached, or the proxy carries a
    /// [`ResponsePresentationPolicy::Dynamic`] plugin whose rewrite comes from
    /// live runtime state. A plugin that retains a representation for later
    /// replay must fail closed on `None` rather than claim provenance it cannot
    /// substantiate. Kept private so request metadata cannot forge one.
    pub(crate) response_presentation_policy_digest: Option<[u8; 32]>,
    /// Deduplication instances whose in-flight ownership can be released after
    /// a serverless rejection proven to occur before external invocation. Each
    /// committed hook consumes only its own entry, preserving exactly-once
    /// cleanup without weakening uncertain-side-effect retention.
    pub(crate) serverless_pre_invocation_rejection_owners: HashSet<u64>,
    /// Deduplication instances that own protection for a terminal serverless
    /// invocation. Each committed/stream-terminal hook consumes or observes
    /// only its own entry, so one instance cannot publish into another cache or
    /// release another instance's in-flight marker. This set is bounded by the
    /// completion-state map above.
    pub(crate) serverless_external_side_effect_owners: HashSet<u64>,
    /// Whether a successful terminate-mode serverless invocation produced the
    /// current synthetic response. Unlike ordinary plugin rejections, every
    /// final 2xx-5xx function response is application-owned content and must run
    /// through the buffered response-body lifecycle when configured. Kept out
    /// of public metadata so a custom plugin cannot opt an unrelated rejection
    /// into that contract.
    pub(crate) serverless_terminate_response: bool,
    /// Deduplication instance currently publishing an owned terminal response
    /// from the observe-only committed hook. This transient private marker lets
    /// the ordinary publication path retain in-flight protection when no replay
    /// can be stored. Committed hooks run sequentially, so at most one instance
    /// occupies the slot.
    pub(crate) serverless_owned_dedup_publication: Option<u64>,
    /// Per-`ai_prompt_compressor`-instance source digest, transformed bytes, and
    /// stats staged by `before_proxy`. Kept out of public metadata so a staged
    /// prompt copy and prompt-derived digest cannot enter transaction logs.
    pub(crate) ai_prompt_compressor_staged: HashMap<u64, ai_prompt_compressor::StagedCompression>,
    /// Incoming request path captured once by the first auto-family compressor
    /// before backend routing can rewrite `path`. All compressor instances share
    /// this single bounded snapshot, and public metadata cannot spoof it.
    pub(crate) ai_prompt_compressor_classification_path: Option<String>,
    /// Whether the authoritative wire transform has reset provisional
    /// `before_proxy` compressor counters for this request.
    pub(crate) ai_prompt_compressor_wire_stats_started: bool,
    /// Final-hook rejection staged when configured preserve-marker sanitation
    /// cannot safely produce bounded provider-visible bytes. Kept private so
    /// request metadata cannot spoof or clear the fail-closed decision.
    pub(crate) ai_prompt_compressor_marker_reject_status: Option<u16>,
    /// Encoding selected by the built-in compression plugin for the response it
    /// will create at the gateway. This is authoritative ownership state for
    /// distinguishing planned gateway compression from an already-encoded
    /// origin response; public plugin metadata is not trusted for that security
    /// decision.
    gateway_response_compression_algorithm: Option<&'static str>,
    /// Process-local compression instance that owns the one-shot request-body
    /// decode. Kept out of public metadata so sibling/custom plugins cannot
    /// spoof ownership, and stored as a scalar to avoid a per-request String
    /// allocation on the body-transform hot path.
    compression_request_decode_owner: Option<u64>,
    /// Process-local compression instance that owns the one-shot response-body
    /// encode. This remains private for the same ownership and allocation
    /// reasons as `compression_request_decode_owner`.
    compression_response_encode_owner: Option<u64>,
    /// Process-local compression instance that reserved response-buffer admission
    /// in `before_proxy`, before the response-buffer decision. First-wins across
    /// sibling instances so at most one response permit is held per request. The
    /// reservation is what bounds the population of response bodies admitted onto
    /// the compression-only buffered path; `after_proxy` consumes this instance's
    /// reserved permit rather than acquiring a fresh one on the hot path.
    compression_response_admission_owner: Option<u64>,
    /// Set when `before_proxy` negotiated a compressible coding but could not
    /// obtain bounded response-buffer admission. The response then streams identity (or
    /// fails closed with 406 when identity is prohibited) instead of buffering
    /// for a compression it cannot run; `after_proxy` must not reacquire.
    compression_response_admission_declined: bool,
    /// Reserved response-buffer admission permit for gateway compression.
    /// Codec CPU admission is acquired separately, immediately before the
    /// blocking transform, and this permit is held across that transform so the
    /// retained-body population never exceeds the response-buffer budget. Drop
    /// releases this slot on cancellation; clones do not duplicate the
    /// exclusive permit.
    compression_response_buffer_permit: HeldResponseBufferPermit,
    /// Validated plaintext staged by the rare buffered request-decode fallback
    /// (headers stripped in `before_proxy` without a mutable body view). The
    /// owning transform must emit these bytes so the backend never sees a
    /// compressed body without `Content-Encoding`.
    compression_staged_request_plaintext: Option<Vec<u8>>,
    /// Set when the response-encode owner cannot produce bytes that match a
    /// previously committed gateway `Content-Encoding`. Shared transform loops
    /// must restore an identity representation (or otherwise fail closed)
    /// instead of forwarding plaintext under a coded header.
    compression_response_encode_aborted: bool,
    /// Process-unique id for an attached response-stream inspector chain.
    /// Assigned only after at least one configured plugin opts into streaming
    /// hooks for the response, and cleared again when every factory returns
    /// `None`. Stateful plugins use it to correlate inspector-owned results
    /// with [`Plugin::on_response_stream_terminated`] without putting internal
    /// correlation keys in transaction metadata.
    pub(crate) response_stream_id: Option<u64>,
    /// Completion signal paired with `response_stream_id`. The detached H1/H2
    /// inspector task may still be finishing an async decision after the
    /// downstream body is dropped; terminal logging waits on this signal before
    /// draining plugin write-back state.
    response_stream_completion: Option<Arc<ResponseStreamCompletion>>,
    /// A2A gateway detection state staged between request and response hooks.
    /// Kept out of public metadata so Agent Card rewriting can work even when
    /// `observability.emit_metadata` is disabled.
    pub(crate) a2a_gateway_detected: bool,
    pub(crate) a2a_gateway_binding: Option<&'static str>,
    pub(crate) a2a_gateway_is_agent_card: bool,
    pub(crate) a2a_gateway_streaming: bool,
    /// Exact upstream/public resource URI pair used to route an MCP
    /// `resources/read` request. Kept out of public metadata so upstream URI
    /// details cannot enter transaction logs, while the response hook can
    /// preserve the public URI spelling the client actually requested.
    pub(crate) mcp_response_resource_binding: Option<(String, String)>,
    /// Gateway-authenticated public→upstream tool-name rewrite staged by
    /// `mcp_gateway` aggregate routing for a `tools/call`. Kept out of public
    /// metadata so forgeable `mcp.*` keys cannot mint policy identity, while
    /// `ai_tool_governor`'s final-body recheck can evaluate the routed call
    /// under the public name only when the final wire name exactly matches
    /// this trusted upstream alias.
    pub(crate) mcp_trusted_tool_name_rewrite: Option<(String, String)>,
    /// Whether reserved `waf.*` metadata has been cleared for this request.
    ///
    /// `metadata` is intentionally public plugin scratch space. WAF-owned log
    /// fields are mirrored there for compatibility, but the authoritative
    /// copy lives in `waf_owned_metadata` so other plugins or inbound request
    /// data cannot spoof WAF transaction-log fields.
    pub(crate) waf_metadata_initialized: bool,
    pub(crate) waf_owned_metadata: HashMap<String, String>,
    /// Per-WAF-instance anomaly scores for the current request.
    ///
    /// Keyed by the process-unique runtime id of each `waf` plugin instance so
    /// sibling policies on the same proxy accumulate and threshold-check in
    /// isolation. Bounded by the number of attached WAF instances (operator
    /// configuration), never by request content.
    pub(crate) waf_instance_scores: HashMap<u64, WafInstanceScoreState>,
    /// JWT audiences emitted by mesh `jwks_auth` for Istio
    /// `request.auth.audiences` conditions. Kept out of `metadata` so JWT
    /// claim material does not flow into transaction logs.
    pub mesh_request_auth_audiences: Vec<String>,
    /// JWT scalar/string-array claims emitted by mesh `jwks_auth` for Istio
    /// `request.auth.claims[...]` conditions. Kept structured so list claims
    /// retain item boundaries and are not serialized into transaction logs.
    pub mesh_request_auth_claims: HashMap<String, JwtAuthAttributeValue>,
    /// DER-encoded client certificate from mTLS handshake (first cert in chain).
    /// Populated when the connection used TLS with client certificate verification.
    /// Shared via Arc to avoid cloning cert bytes for each request on HTTP/2 connections.
    pub tls_client_cert_der: Option<Arc<Vec<u8>>>,
    /// DER-encoded CA/intermediate certificates from the client's TLS certificate chain.
    /// Contains all certificates after the peer cert (index 1+) sent during the handshake.
    /// Used by the mtls_auth plugin for per-proxy CA fingerprint verification.
    pub tls_client_cert_chain_der: Option<Arc<Vec<Vec<u8>>>>,
    /// Connection-local cache of `mtls_auth` certificate-derived decisions.
    /// Shared by all HTTP/2 or HTTP/3 requests on the same TLS connection so
    /// X.509 parsing and issuer-chain cryptography run once per plugin policy.
    #[doc(hidden)]
    pub mtls_auth_connection_cache: Option<Arc<crate::plugins::mtls_auth::MtlsAuthConnectionCache>>,
    /// Connection-local cache of the peer-cert SPIFFE extraction outcome.
    /// Shared by all HTTP/2 or HTTP/3 requests on the same TLS connection so
    /// the `spiffe_identity` plugin parses the peer certificate DER once per
    /// connection rather than once per multiplexed request.
    #[doc(hidden)]
    pub peer_spiffe_extraction_cache:
        Option<Arc<crate::plugins::mesh::spiffe_identity::SpiffeIdentityConnectionCache>>,
    /// Peer SPIFFE identity, populated by the `spiffe_identity` plugin when the
    /// client certificate carries a `spiffe://` URI SAN. `None` for non-mesh
    /// deployments and for clients that present a non-SPIFFE certificate.
    /// Plugins downstream of `spiffe_identity` may read this for identity-aware
    /// authorization (e.g. mesh policy evaluation in Phase C).
    pub peer_spiffe_id: Option<crate::identity::SpiffeId>,
    /// Cumulative nanoseconds spent by plugins making external HTTP calls
    /// (via `PluginHttpClient::execute_tracked`). Shared across all plugin
    /// invocations for this request — clone-safe via Arc.
    pub plugin_http_call_ns: Arc<std::sync::atomic::AtomicU64>,
    /// Cumulative nanoseconds spent running the reject-path `after_proxy` and
    /// synthetic response-body hooks inside
    /// `finalize_reject_response_with_after_proxy_hooks` (H1/H2/HBONE reject
    /// path). Those H1/H2/HBONE call sites add their phase `plugin_execution_ns`
    /// *before* invoking the finalizer, so without this the (potentially
    /// expensive — e.g. `ai_response_guard`/`ai_semantic_firewall` over a
    /// synthetic AI body) hook time would be misattributed to gateway overhead.
    /// `log_rejected_request_with_path` folds this into
    /// `latency_plugin_execution_ms`, matching the H3 reject path, which already
    /// times these hooks inline. Clone-safe via Arc; stays 0 on the H3 path
    /// (which never calls the finalizer), so it never double-counts there.
    pub reject_hook_execution_ns: Arc<std::sync::atomic::AtomicU64>,
    /// Receivers for mirror response metadata from every dispatched
    /// `request_mirror` instance on this request.
    ///
    /// Each enabled instance that actually selects work (sampling hit, including
    /// saturated concurrency drops) pushes one watch receiver. Sampled-out
    /// instances leave no slot. Bounded by the number of configured instances
    /// that dispatch on this request — never a singleton last-writer slot.
    /// Collected by detached mirror logging so each destination emits its own
    /// `mirror: true` summary.
    pub mirror_result_rxs: Vec<tokio::sync::watch::Receiver<Option<MirrorResponseMeta>>>,
    /// One-shot HMAC work staged before request-body collection and consumed
    /// at authentication. This is private rather than transaction metadata so
    /// credential/signature/Consumer secret data cannot be forwarded or
    /// logged. Its custom `Clone` intentionally clears the staged value.
    hmac_prebuffer_state: hmac_auth::HmacPrebufferState,
    /// Binary-safe request body bytes, populated when a plugin requires the
    /// body before `before_proxy` (e.g., `request_mirror`). Unlike the
    /// `"request_body"` metadata key (UTF-8 only), this preserves non-UTF-8
    /// payloads such as gRPC protobuf.
    pub request_body_bytes: Option<bytes::Bytes>,
    /// Precomputed body hashes for integrity-verifying authentication plugins.
    /// Keeping fixed-size hashes avoids retaining a second full body while the
    /// sole buffered representation continues to the backend.
    pub request_body_sha256: Option<[u8; 32]>,
    pub request_body_sha512: Option<[u8; 64]>,
    /// The operator's configured response-body ceiling
    /// (`FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES`), `0` meaning unlimited.
    ///
    /// Carried on the context because the buffered representation gate
    /// ([`crate::plugins::response_representation`]) decompresses on the
    /// response path and must not let a decode exceed the same bound the wire
    /// path enforces: a small compressed body that passes the wire check could
    /// otherwise inflate past the operator's limit and be forwarded as the
    /// larger identity representation. Set from `ProxyState` by the H1/H2 and
    /// H3 request handlers; a default-constructed context leaves it `0`, which
    /// falls back to the gate's own hard ceiling.
    pub max_response_body_size_bytes: usize,
    /// Shared counter for request body bytes received from the client,
    /// populated by proxy body handlers and read by the summary builders.
    ///
    /// Populated at four points in the request path:
    /// 1. Buffered-collect sites (`Incoming::collect().await`): written once
    ///    with the final `body_bytes.len()` after collection completes.
    /// 2. Streaming forward with size limit (`SizeLimitedIncoming`): written
    ///    once after the backend request completes, from the cloned counter
    ///    handle obtained via `SizeLimitedIncoming::bytes_seen_handle()`.
    /// 3. Streaming forward without size limit (`CountingIncoming` wrapping
    ///    the `Incoming` body): same handle-capture pattern.
    /// 4. Prebuffered bodies (populated earlier by plugins like
    ///    `request_mirror`): copied from the buffered `Bytes::len()`.
    ///
    /// Summary builders read this via `load(Ordering::Acquire)` and populate
    /// `TransactionSummary.bytes_sent`. A zero value is skipped at
    /// serialization time, so empty/GET/HEAD requests do not inflate logs.
    ///
    /// Clone-safe via `Arc` — all proxy paths share one counter per request.
    pub bytes_sent_observed: Arc<std::sync::atomic::AtomicU64>,
    /// Whether this request arrived via TLS 1.3 0-RTT early data.
    /// Set on HTTP/3 via quinn's `into_0rtt()` detection, and on HTTPS via the
    /// `Early-Data: 1` header (RFC 8470) from upstream proxies/CDNs.
    pub is_early_data: bool,
    /// Aggregate fail-closed decision staged by cache-managed
    /// `mesh_route_dispatch` instances. The cache inserts a finalizer directly
    /// after the last instance so disjoint rules can all participate before a
    /// 404 is emitted. Kept out of public metadata and transaction logs.
    pub(crate) mesh_route_dispatch_reject_unmatched: bool,
    /// Whether any cache-managed `mesh_route_dispatch` instance matched.
    /// Kept separate from route overrides because rewrite-only and transform-
    /// only rules are successful matches too.
    pub(crate) mesh_route_dispatch_matched: bool,
    /// Plugin-set override for the proxy's `upstream_id`. When `Some`, the
    /// dispatch path uses this instead of `proxy.upstream_id`. Used by
    /// `mesh_route_dispatch` to implement Istio `VirtualService` header/method
    /// route matching without per-match `Proxy` materialization.
    ///
    /// **Pool-key invariant**: every connection-pool key that mentions
    /// upstream identity MUST derive from this override when set. See
    /// `RequestContext::effective_upstream_id`.
    pub route_override_upstream_id: Option<String>,
    /// Plugin-set override for the proxy's `backend_host`. Same contract as
    /// `route_override_upstream_id`; the dispatch path falls back to
    /// `proxy.backend_host` when this is `None`.
    pub route_override_backend_host: Option<String>,
    /// Plugin-set override for the proxy's HTTP-family backend wire scheme.
    ///
    /// Used by body-aware routers such as `mcp_gateway` when a request-selected
    /// direct upstream URL carries a different `http`/`https` scheme than the
    /// placeholder proxy. Stream schemes are intentionally not accepted here.
    pub route_override_backend_scheme: Option<BackendScheme>,
    /// Plugin-set override for the proxy's `backend_port`. Same contract as
    /// `route_override_upstream_id`.
    pub route_override_backend_port: Option<u16>,
    /// Plugin-set override for the proxy's resolved backend TLS identity.
    ///
    /// When `route_override_upstream_id` points at another upstream, dispatch
    /// re-resolves this from the upstream snapshot automatically. Plugins that
    /// override a direct backend host/port can set this field explicitly when
    /// the destination uses different mTLS materials.
    pub route_override_resolved_tls: Option<BackendTlsConfig>,
    /// Plugin-set override for the proxy's backend response/read timeout.
    /// Used by mesh L7 route dispatch so route-local policy follows the
    /// matched predicate even when the hot router selected a later fallback
    /// proxy for the same public path.
    pub route_override_backend_read_timeout_ms: Option<u64>,
    /// Plugin-set override for the proxy's retry policy. Outer `None` means
    /// no override; `Some(None)` intentionally clears the selected proxy's
    /// retry policy for this route.
    pub route_override_retry: Option<Option<RetryConfig>>,
    /// Per-rule request header transforms published by `mesh_route_dispatch`
    /// when a matching rule carries `request_transform` rules (Istio
    /// `VirtualService.http[].headers.request.{set,add,remove}`). The
    /// `request_transformer` plugin applies these after its own static
    /// header rules. Shared via `Arc` so the dispatch hot path clones a
    /// pointer rather than the rule list.
    pub route_override_request_transform:
        Option<Arc<Vec<utils::route_header_transform::RouteHeaderTransformRule>>>,
    /// Per-rule response header transforms; counterpart to
    /// `route_override_request_transform`. Applied by `response_transformer`
    /// after its own static header rules.
    pub route_override_response_transform:
        Option<Arc<Vec<utils::route_header_transform::RouteHeaderTransformRule>>>,
    /// Plugin-set override for the request path forwarded to the backend.
    /// Set by `mesh_route_dispatch` when a matching rule carries an Istio
    /// `VirtualService.http[].rewrite.uri`. The proxy dispatch path rebases the
    /// outgoing request line / backend URL to this value AFTER the
    /// `before_proxy` phase (the original `ctx.path` stays intact for logging
    /// and route selection, which already happened). `None` keeps the
    /// request's own path. Honored on the H1/H2/gRPC/reqwest backend dispatch
    /// path; VS-derived proxies never set `strip_listen_path`, so the override
    /// is the literal forwarded path.
    pub route_override_path: Option<String>,
    /// Backend-effective path that successfully passed the final route policy
    /// boundary. Not exposed through the public plugin API, so custom plugins
    /// cannot forge the path consumed by security-sensitive deferred work such
    /// as request mirroring.
    authorized_backend_path: Option<String>,
    /// Treat `route_override_path` as an absolute backend path by disabling
    /// `strip_listen_path` on the effective proxy. Used by direct upstream
    /// routers when the override is already the final upstream URL path rather
    /// than a virtual-service rewrite relative to the selected public route.
    pub route_override_path_is_absolute: bool,
    /// Plugin-set override for the `Host` / `:authority` forwarded to the
    /// backend. Set by `mesh_route_dispatch` for an Istio
    /// `VirtualService.http[].rewrite.authority`. The proxy dispatch path
    /// rewrites the forwarded `host` header to this value after `before_proxy`.
    /// `None` preserves the request's own authority.
    pub route_override_authority: Option<String>,
    /// In node-waypoint mesh topology, the Kubernetes pod UID resolved from
    /// the eBPF socket-cookie record at accept time. Set by the connection
    /// admit path alongside `peer_spiffe_id`; `None` for non-mesh
    /// deployments and for mesh topologies other than `NodeWaypoint`.
    ///
    /// Plugins use this to disambiguate source-pod identity when one
    /// listener serves many pods. Pair with `node_waypoint_policy_scope`
    /// for the pre-resolved per-pod scope cache.
    pub node_waypoint_pod_uid: Option<[u8; 16]>,
    /// Pre-resolved per-pod policy scope for node-waypoint mode.
    ///
    /// Populated by the connection admit path by looking up the source
    /// pod's `PolicyScopeCache` from the `NodeWaypointIdentityResolver`.
    /// `mesh_authz` consults this when filtering policies whose
    /// `PolicyScope` is namespace- or workload-selector-bound, because
    /// the shared listener carries no single proxy identity that fits
    /// the slice-level filter that other topologies use.
    pub node_waypoint_policy_scope: Option<Arc<crate::modes::mesh::runtime::PolicyScopeCache>>,
    /// Mesh traffic direction stamped by the listener that accepted this
    /// request. `Some(Inbound)` for mesh inbound mTLS / HBONE termination
    /// listeners; `Some(Outbound)` for the outbound capture listener;
    /// `None` for non-mesh listeners (file/db/cp/dp HTTP entrypoints).
    ///
    /// Mesh-aware plugins (e.g., `workload_metrics`) gate span emission
    /// on this so a single plugin instance can serve both directions and
    /// CLIENT vs SERVER span kinds reflect which side of the hop the
    /// listener represents.
    pub mesh_direction: Option<MeshTrafficDirection>,
    /// Pre-NAT original destination of an iptables-REDIRECTed connection,
    /// read once per accepted connection on mesh outbound capture listeners
    /// (`SO_ORIGINAL_DST`) and shared by every request on the connection.
    /// `None` on non-capture listeners, non-Linux platforms, and
    /// non-redirected (direct-dial) traffic. Mesh outbound routing uses the
    /// port to disambiguate multi-port services; the address is reserved for
    /// the raw-TCP egress follow-up.
    pub orig_dst: Option<std::net::SocketAddr>,
    /// Mesh outbound service port selected by the router after host/path
    /// routing and optional original-destination disambiguation. Used by
    /// `mesh_authz` for Istio `destination.port` when an outbound request has
    /// no captured original destination, such as direct dials to a single-port
    /// service in dev/non-Linux setups. `None` outside mesh outbound routes.
    pub mesh_outbound_destination_authz_port: Option<u16>,
    /// Authorization destination port for a matched Sidecar `ingress[]` route
    /// (F6 §6.2): the operator-declared LISTENER port (e.g. `8443`), stamped by
    /// the request handler from `select_mesh_inbound_port_route` when the matched
    /// route is an ingress group. `mesh_authz` uses this so an
    /// `AuthorizationPolicy` `port` / `destination.port` rule scoped to the
    /// listener port matches — the route forwards to a different
    /// `defaultEndpoint` backend port, and authorizing on that backend port
    /// would let a DENY on the listener port fail OPEN. `None` for service-port
    /// default inbound routes (which authorize on the container/backend port,
    /// matching Istio inbound authz) and for all non-ingress traffic.
    pub mesh_inbound_listener_authz_port: Option<u16>,
}

/// Return an identity only when it contains a meaningful non-whitespace value.
/// Security identities are preserved byte-for-byte; this helper rejects blank
/// principals rather than silently canonicalizing signed claim content.
pub(crate) fn meaningful_identity(identity: Option<&str>) -> Option<&str> {
    identity.filter(|identity| !identity.trim().is_empty())
}

fn merge_metadata_value(metadata: &mut HashMap<String, String>, key: &str, value: &str) {
    metadata
        .entry(key.to_string())
        .and_modify(|existing| {
            if !existing.is_empty() {
                existing.push(',');
            }
            existing.push_str(value);
        })
        .or_insert_with(|| value.to_string());
}

impl RequestContext {
    pub fn new(client_ip: String, method: String, path: String) -> Self {
        Self {
            direct_client_ip: client_ip.clone(),
            client_ip,
            canonical_client_ip: CanonicalClientIpCache::default(),
            method,
            path,
            raw_path: None,
            request_authority: None,
            request_is_secure: false,
            frontend_listen_port: None,
            frontend_sni_hostname: None,
            lb_generation: 1,
            proxy_lifecycle_generation: None,
            raw_headers: None,
            headers: HashMap::new(),
            headers_materialized: false,
            raw_query_string: None,
            query_params_materialized: false,
            query_params: HashMap::new(),
            matched_proxy: None,
            identified_consumer: None,
            authenticated_identity: None,
            authenticated_identity_header: None,
            backend_geo_country: None,
            auth_method: None,
            timestamp_received: Utc::now(),
            grpc_deadline_initialized: false,
            grpc_deadline_had_valid_client_timeout: false,
            grpc_deadline_received_at: tokio::time::Instant::now(),
            grpc_deadline_preflight_complete: false,
            grpc_deadline_budget_ms: None,
            grpc_deadline_at: None,
            grpc_deadline_header_is_remaining: false,
            gateway_deadline_response_selected: false,
            response_cache_hit: false,
            metadata: HashMap::new(),
            ai_usage_export: None,
            ai_usage_export_token_prefix: None,
            ai_usage_export_cost_prefix: None,
            cors_state: cors::CorsRequestState::default(),
            pending_claim_headers: HashMap::new(),
            sanitized_claim_header_destinations: HashSet::new(),
            request_headers_to_redact: None,
            buffered_initial_response_header_policy_state: None,
            buffered_deadline_response_header_provenance: None,
            request_http_flavor: HttpFlavor::Plain,
            original_accept_encoding: None,
            websocket_response_boundary: false,
            ai_semantic_cache_embeddings: HashMap::new(),
            ai_semantic_cache_scope_keys: HashMap::new(),
            openapi_validator_matches: HashMap::new(),
            ai_tool_governor_response_hashes: HashMap::new(),
            ai_response_guard_replay_redactions: HashSet::new(),
            ai_tool_governor_replay_redactions: HashSet::new(),
            ai_tool_governor_call_hashes: HashMap::new(),
            ai_tool_governor_request_hashes: HashMap::new(),
            ai_tool_governor_redaction_memos: HashMap::new(),
            ai_semantic_firewall_request_hashes: HashMap::new(),
            ai_semantic_firewall_response_hashes: HashMap::new(),
            request_deduplication_states: HashMap::new(),
            finalized_response_replay: false,
            response_policy_stamp: None,
            response_presentation_policy_digest: None,
            serverless_pre_invocation_rejection_owners: HashSet::new(),
            serverless_external_side_effect_owners: HashSet::new(),
            serverless_terminate_response: false,
            serverless_owned_dedup_publication: None,
            ai_prompt_compressor_staged: HashMap::new(),
            ai_prompt_compressor_classification_path: None,
            ai_prompt_compressor_wire_stats_started: false,
            ai_prompt_compressor_marker_reject_status: None,
            gateway_response_compression_algorithm: None,
            compression_request_decode_owner: None,
            compression_response_encode_owner: None,
            compression_response_admission_owner: None,
            compression_response_admission_declined: false,
            compression_response_buffer_permit: HeldResponseBufferPermit::default(),
            compression_staged_request_plaintext: None,
            compression_response_encode_aborted: false,
            response_stream_id: None,
            response_stream_completion: None,
            a2a_gateway_detected: false,
            a2a_gateway_binding: None,
            a2a_gateway_is_agent_card: false,
            a2a_gateway_streaming: false,
            mcp_response_resource_binding: None,
            mcp_trusted_tool_name_rewrite: None,
            waf_metadata_initialized: false,
            waf_owned_metadata: HashMap::new(),
            waf_instance_scores: HashMap::new(),
            mesh_request_auth_audiences: Vec::new(),
            mesh_request_auth_claims: HashMap::new(),
            tls_client_cert_der: None,
            tls_client_cert_chain_der: None,
            mtls_auth_connection_cache: None,
            peer_spiffe_extraction_cache: None,
            peer_spiffe_id: None,
            plugin_http_call_ns: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            reject_hook_execution_ns: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            mirror_result_rxs: Vec::new(),
            hmac_prebuffer_state: hmac_auth::HmacPrebufferState::default(),
            request_body_bytes: None,
            request_body_sha256: None,
            request_body_sha512: None,
            max_response_body_size_bytes: 0,
            bytes_sent_observed: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            is_early_data: false,
            mesh_route_dispatch_reject_unmatched: false,
            mesh_route_dispatch_matched: false,
            route_override_upstream_id: None,
            route_override_backend_host: None,
            route_override_backend_scheme: None,
            route_override_backend_port: None,
            route_override_resolved_tls: None,
            route_override_backend_read_timeout_ms: None,
            route_override_retry: None,
            route_override_request_transform: None,
            route_override_response_transform: None,
            route_override_path: None,
            authorized_backend_path: None,
            route_override_path_is_absolute: false,
            route_override_authority: None,
            node_waypoint_pod_uid: None,
            node_waypoint_policy_scope: None,
            mesh_direction: None,
            orig_dst: None,
            mesh_outbound_destination_authz_port: None,
            mesh_inbound_listener_authz_port: None,
        }
    }

    pub(crate) fn publish_correlation_id(&mut self, instance_key: &str, request_id: String) {
        let publish_canonical = self
            .canonical_client_ip
            .publish_correlation_id(instance_key, request_id.clone());
        self.metadata
            .insert(instance_key.to_string(), request_id.clone());
        if publish_canonical {
            self.metadata
                .insert(REQUEST_ID_METADATA_KEY.to_string(), request_id);
        }
    }

    pub(crate) fn correlation_id(&self, instance_key: &str) -> Option<&str> {
        self.canonical_client_ip.correlation_id(instance_key)
    }

    pub(crate) fn canonical_correlation_id(&self) -> Option<&str> {
        self.canonical_client_ip.canonical_correlation_id()
    }

    pub(crate) fn project_correlation_ids(&self, metadata: &mut HashMap<String, String>) {
        self.canonical_client_ip.project_correlation_ids(metadata);
    }

    fn replace_ai_usage_export(&mut self, candidate: AiUsageExport) {
        self.ai_usage_export_token_prefix =
            (candidate.token_completeness() != 0).then(|| Arc::clone(&candidate.prefix));
        self.ai_usage_export_cost_prefix = candidate
            .cost
            .as_ref()
            .map(|_| Arc::clone(&candidate.prefix));
        self.ai_usage_export = Some(candidate);
    }

    pub(crate) fn stage_ai_usage_export(&mut self, candidate: AiUsageExport) {
        if candidate.completeness() == 0 {
            return;
        }
        let Some(mut current) = self.ai_usage_export.take() else {
            self.replace_ai_usage_export(candidate);
            return;
        };

        // Different providers must never be combined. Preserve the existing
        // whole-snapshot selection rule for that defensive edge case.
        if candidate.provider != current.provider {
            let replace = candidate.completeness() > current.completeness()
                || (candidate.completeness() == current.completeness()
                    && candidate.prefix.as_ref() < current.prefix.as_ref());
            if replace {
                self.replace_ai_usage_export(candidate);
            } else {
                self.ai_usage_export = Some(current);
            }
            return;
        }

        // Token detail and trusted cost are independent dimensions. A detailed
        // unpriced instance must not discard a cost from a less-detailed priced
        // instance, and neither dimension may be counted more than once.
        let candidate_token_completeness = candidate.token_completeness();
        let current_token_completeness = current.token_completeness();
        let current_token_prefix = self
            .ai_usage_export_token_prefix
            .as_deref()
            .unwrap_or(current.prefix.as_ref());
        let replace_tokens = candidate_token_completeness > current_token_completeness
            || (candidate_token_completeness != 0
                && candidate_token_completeness == current_token_completeness
                && candidate.prefix.as_ref() < current_token_prefix);
        if replace_tokens {
            current.prompt_tokens = candidate.prompt_tokens;
            current.completion_tokens = candidate.completion_tokens;
            current.total_tokens = candidate.total_tokens;
            self.ai_usage_export_token_prefix = Some(Arc::clone(&candidate.prefix));
        }

        if let Some(candidate_cost) = candidate.cost {
            let replace_cost = self
                .ai_usage_export_cost_prefix
                .as_ref()
                .is_none_or(|prefix| candidate.prefix.as_ref() < prefix.as_ref());
            if replace_cost {
                current.cost = Some(candidate_cost);
                self.ai_usage_export_cost_prefix = Some(Arc::clone(&candidate.prefix));
            }
        }

        if let Some(prefix) = self
            .ai_usage_export_cost_prefix
            .as_ref()
            .or(self.ai_usage_export_token_prefix.as_ref())
        {
            current.prefix = Arc::clone(prefix);
        }
        self.ai_usage_export = Some(current);
    }

    /// Return the typed built-in usage snapshot carried to transaction logs.
    /// Public only for external contract tests; runtime metadata producers
    /// cannot access or populate this path.
    #[doc(hidden)]
    pub fn authoritative_ai_usage_export(&self) -> Option<AiUsageExport> {
        self.ai_usage_export.clone()
    }

    /// Return the one absolute gRPC deadline established for this request.
    /// The instant is monotonic and must be reused rather than reconstructed
    /// from the relative `grpc-timeout` header on later backend attempts.
    pub fn grpc_deadline_at(&self) -> Option<tokio::time::Instant> {
        self.grpc_deadline_at
    }

    pub(crate) fn mark_gateway_deadline_response_selected(&mut self) {
        self.gateway_deadline_response_selected = true;
    }

    pub(crate) fn gateway_deadline_response_selected(&self) -> bool {
        self.gateway_deadline_response_selected
    }

    /// Remaining whole-millisecond gRPC budget, rounded up so a positive
    /// sub-millisecond remainder can never become the invalid wire value `0m`.
    pub fn grpc_deadline_remaining_ms(&self) -> Option<u64> {
        let remaining = self
            .grpc_deadline_at?
            .saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Some(0);
        }
        grpc_deadline::duration_millis_ceil_saturating(remaining)
    }

    pub(crate) fn initialize_grpc_deadline_budget(&mut self, budget_ms: Option<u64>) {
        if self.grpc_deadline_initialized {
            return;
        }
        self.grpc_deadline_initialized = true;
        self.grpc_deadline_had_valid_client_timeout = budget_ms.is_some();
        self.set_grpc_deadline_budget(budget_ms);
    }

    pub(crate) fn set_grpc_deadline_budget(&mut self, budget_ms: Option<u64>) {
        self.grpc_deadline_budget_ms = budget_ms;
        self.grpc_deadline_at = budget_ms.and_then(|budget| {
            self.grpc_deadline_received_at
                .checked_add(Duration::from_millis(budget))
        });
    }

    /// Correlation id for the concrete response-stream inspector chain, when
    /// one attached to this request. Streaming plugins can key bounded shared
    /// state by this id in `response_stream_inspector`, then remove and fold it
    /// into `ctx.metadata` from `on_response_stream_terminated`.
    pub fn response_stream_id(&self) -> Option<u64> {
        self.response_stream_id
    }

    /// Request-owned handoff used by inspector tasks to publish terminal state
    /// before the completion signal wakes [`Plugin::on_response_stream_terminated`].
    ///
    /// State placed here is bounded by this response's configured inspector
    /// chain plus a hard per-request ceiling, and drops with the request
    /// context if terminal processing itself is cancelled; it is never a
    /// process-global tombstone.
    pub fn response_stream_handoff(&self) -> Option<ResponseStreamHandoff> {
        self.response_stream_completion
            .as_ref()
            .map(|completion| ResponseStreamHandoff {
                completion: Arc::clone(completion),
            })
    }

    /// Return the authoritative client IP as a canonical typed address.
    ///
    /// The value is parsed at most once after trusted-forwarding resolution and
    /// reused by every policy instance attached to this request.
    pub fn canonical_client_ip(&self) -> Option<IpAddr> {
        self.canonical_client_ip.get_or_parse(&self.client_ip)
    }

    /// Whether [`Self::canonical_client_ip`] has initialized the shared cache.
    #[doc(hidden)]
    pub fn canonical_client_ip_is_initialized(&self) -> bool {
        self.canonical_client_ip.is_initialized()
    }

    pub(crate) fn mark_gateway_response_compression(&mut self, algorithm: &'static str) {
        self.gateway_response_compression_algorithm = Some(algorithm);
    }

    pub(crate) fn gateway_response_compression_algorithm(&self) -> Option<&'static str> {
        self.gateway_response_compression_algorithm
    }

    pub(crate) fn has_compression_request_decode_owner(&self) -> bool {
        self.compression_request_decode_owner.is_some()
    }

    pub(crate) fn claim_compression_request_decode(&mut self, owner: u64) -> bool {
        if self.compression_request_decode_owner.is_some() {
            return false;
        }
        self.compression_request_decode_owner = Some(owner);
        true
    }

    pub(crate) fn owns_compression_request_decode(&self, owner: u64) -> bool {
        self.compression_request_decode_owner == Some(owner)
    }

    pub(crate) fn has_compression_response_encode_owner(&self) -> bool {
        self.compression_response_encode_owner.is_some()
    }

    pub(crate) fn claim_compression_response_encode(&mut self, owner: u64) -> bool {
        if self.compression_response_encode_owner.is_some() {
            return false;
        }
        self.compression_response_encode_owner = Some(owner);
        true
    }

    pub(crate) fn owns_compression_response_encode(&self, owner: u64) -> bool {
        self.compression_response_encode_owner == Some(owner)
    }

    pub(crate) fn has_compression_response_admission_owner(&self) -> bool {
        self.compression_response_admission_owner.is_some()
    }

    pub(crate) fn claim_compression_response_admission(&mut self, owner: u64) -> bool {
        if self.compression_response_admission_owner.is_some() {
            return false;
        }
        self.compression_response_admission_owner = Some(owner);
        // A held permit supersedes any earlier sibling's decline: the request now
        // has bounded admission, so the response is no longer stream-only. (Once
        // an owner exists, siblings skip reservation, so `declined` cannot be set
        // again afterward, which keeps `owner.is_some()` implying `!declined`.)
        self.compression_response_admission_declined = false;
        true
    }

    pub(crate) fn owns_compression_response_admission(&self, owner: u64) -> bool {
        self.compression_response_admission_owner == Some(owner)
    }

    pub(crate) fn mark_compression_response_admission_declined(&mut self) {
        self.compression_response_admission_declined = true;
    }

    pub(crate) fn compression_response_admission_declined(&self) -> bool {
        self.compression_response_admission_declined
    }

    /// Drop this request's reserved response-buffer admission (permit + owner)
    /// when `instance_id` is the reserving instance. A no-op for siblings so a
    /// non-owner declining to compress never releases another instance's slot.
    pub(crate) fn release_compression_response_admission_if_owner(&mut self, instance_id: u64) {
        if self.compression_response_admission_owner == Some(instance_id) {
            self.compression_response_admission_owner = None;
            let _ = self.compression_response_buffer_permit.take();
        }
    }

    /// Clear admission ownership for `instance_id` while leaving the reserved
    /// buffer permit on the context. Used when this instance will not encode but
    /// the body was already admitted onto the compression buffered path: a later
    /// sibling with a broader config can take the same slot instead of briefly
    /// leaving a retained body unaccounted for (or racing a fresh acquire).
    pub(crate) fn relinquish_compression_response_admission_ownership_if_owner(
        &mut self,
        instance_id: u64,
    ) {
        if self.compression_response_admission_owner == Some(instance_id) {
            self.compression_response_admission_owner = None;
        }
    }

    pub(crate) fn set_compression_response_buffer_permit(
        &mut self,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) {
        self.compression_response_buffer_permit.set(permit);
    }

    pub(crate) fn take_compression_response_buffer_permit(
        &mut self,
    ) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.compression_response_buffer_permit.take()
    }

    pub(crate) fn set_compression_staged_request_plaintext(&mut self, plaintext: Vec<u8>) {
        self.compression_staged_request_plaintext = Some(plaintext);
    }

    pub(crate) fn take_compression_staged_request_plaintext(&mut self) -> Option<Vec<u8>> {
        self.compression_staged_request_plaintext.take()
    }

    pub(crate) fn mark_compression_response_encode_aborted(&mut self) {
        self.compression_response_encode_aborted = true;
    }

    pub(crate) fn take_compression_response_encode_aborted(&mut self) -> bool {
        std::mem::take(&mut self.compression_response_encode_aborted)
    }

    pub(crate) fn clear_gateway_response_compression(&mut self) {
        self.gateway_response_compression_algorithm = None;
        self.compression_response_encode_owner = None;
        self.compression_response_admission_owner = None;
        let _ = self.compression_response_buffer_permit.take();
    }

    #[allow(dead_code)] // Used by external tests; dead code in the separately compiled bin target.
    pub(crate) fn compression_ownership_for_test(&self) -> (Option<u64>, Option<u64>) {
        (
            self.compression_request_decode_owner,
            self.compression_response_encode_owner,
        )
    }

    pub(crate) fn mark_response_cache_hit(&mut self) {
        self.response_cache_hit = true;
    }

    pub(crate) fn response_cache_hit(&self) -> bool {
        self.response_cache_hit
    }

    pub(crate) fn bind_authorized_backend_path(&mut self, path: String) {
        self.authorized_backend_path = Some(path);
    }

    pub(crate) fn authorized_backend_path(&self) -> Option<&str> {
        self.authorized_backend_path.as_deref()
    }

    /// Begin tracking initial-response policy against genuine initial headers
    /// while hooks operate on a merged buffered gRPC compatibility view.
    pub(crate) fn begin_buffered_initial_response_header_policy(
        &mut self,
        header_names: Arc<Vec<String>>,
        initial_headers: &HashMap<String, String>,
        merged_headers: &HashMap<String, String>,
    ) {
        self.buffered_initial_response_header_policy_state =
            BufferedInitialResponseHeaderPolicyState::new(
                header_names,
                initial_headers,
                merged_headers,
            )
            .map(Arc::new);
    }

    pub(crate) fn record_buffered_initial_response_header_plugin(
        &mut self,
        plugin: &dyn Plugin,
        response_headers: &mut HashMap<String, String>,
    ) {
        if let Some(state) = self.buffered_initial_response_header_policy_state.as_mut() {
            Arc::make_mut(state).record_after_proxy_plugin(plugin, response_headers);
        }
    }

    /// Advance policy-owned initial-header state after a later response phase
    /// mutates representation metadata (normalize / body transform).
    pub(crate) fn record_buffered_initial_response_header_later_mutations(
        &mut self,
        response_headers: &mut HashMap<String, String>,
    ) {
        if let Some(state) = self.buffered_initial_response_header_policy_state.as_mut() {
            Arc::make_mut(state).record_later_response_header_mutations(response_headers);
        }
    }

    pub(crate) fn take_buffered_initial_response_header_policy(
        &mut self,
    ) -> Option<Arc<BufferedInitialResponseHeaderPolicyState>> {
        self.buffered_initial_response_header_policy_state.take()
    }

    /// Borrow the buffered initial-response policy state while response body
    /// transforms still need [`BufferedInitialResponseHeaderPolicyState`]
    /// semantics (gRPC-Web trailer framing).
    pub(crate) fn buffered_initial_response_header_policy(
        &self,
    ) -> Option<&BufferedInitialResponseHeaderPolicyState> {
        self.buffered_initial_response_header_policy_state
            .as_deref()
    }

    /// Capture the pristine backend header map before trusted response hooks
    /// execute. No state is allocated for requests without an absolute RPC
    /// deadline.
    pub(crate) fn begin_buffered_deadline_response_header_provenance(
        &mut self,
        response_headers: &HashMap<String, String>,
    ) {
        self.buffered_deadline_response_header_provenance = (self.grpc_deadline_at.is_some()
            || self.gateway_deadline_response_selected)
            .then(|| {
                Arc::new(BufferedDeadlineResponseHeaderProvenance::backend_response(
                    response_headers,
                ))
            });
    }

    /// Capture pristine backend headers for any later gateway-authored
    /// replacement, even when the request has no RPC deadline.
    ///
    /// Representation-policy rejection is the non-deadline caller: it must
    /// shed backend representation metadata while retaining only mutations
    /// made by completed trusted response hooks. This is deliberately separate
    /// from [`Self::begin_buffered_deadline_response_header_provenance`] so the
    /// ordinary deadline allocation gate remains unchanged.
    pub(crate) fn begin_buffered_replacement_response_header_provenance(
        &mut self,
        response_headers: &HashMap<String, String>,
    ) {
        self.buffered_deadline_response_header_provenance = Some(Arc::new(
            BufferedDeadlineResponseHeaderProvenance::backend_response(response_headers),
        ));
    }

    pub(crate) fn ensure_buffered_deadline_response_header_provenance(
        &mut self,
        response_headers: &HashMap<String, String>,
    ) {
        if self.buffered_deadline_response_header_provenance.is_none() {
            self.begin_buffered_deadline_response_header_provenance(response_headers);
        }
    }

    /// Start a rejection response at the gateway provenance boundary. The
    /// response did not come from a backend, so its plugin-produced fields are
    /// provenance-known gateway output.
    ///
    /// # Contract
    ///
    /// `response_headers` MUST be a gateway-authored REPLACEMENT map: a freshly
    /// built map, a `PluginResult::Reject{,Binary}` header map, or
    /// gateway-synthesized error headers. It must not be a backend response map,
    /// nor a map that still carries backend-sent headers — callers whose map has
    /// backend lineage clear it first (see
    /// `rebuild_plugin_rejection_response_headers`). This transition declares
    /// the whole map gateway-owned and retires the backend `Set-Cookie`
    /// baseline (see `adopt_gateway_rejection`), so handing it a mixed map would
    /// credit backend lines as gateway-authored. A future caller that cannot
    /// satisfy this must clear or partition its map rather than relaxing the
    /// transition.
    pub(crate) fn begin_rejection_deadline_response_header_provenance(
        &mut self,
        response_headers: &HashMap<String, String>,
    ) {
        if !(self.grpc_deadline_at.is_some() || self.gateway_deadline_response_selected) {
            self.buffered_deadline_response_header_provenance = None;
            return;
        }
        match self.buffered_deadline_response_header_provenance.as_mut() {
            // A rejection generated after the buffered-response path already ran
            // trusted `after_proxy` hooks — for example a later hook exhausting
            // the RPC deadline, which converts into a fresh
            // `grpc_deadline_exceeded_plugin_result()` — must not throw away the
            // gateway decorations those completed hooks recorded. Fold the new
            // rejection headers into the existing gateway-owned set instead of
            // restarting provenance from the rejection headers alone.
            Some(state) => Arc::make_mut(state).adopt_gateway_rejection(response_headers),
            None => {
                self.buffered_deadline_response_header_provenance = Some(Arc::new(
                    BufferedDeadlineResponseHeaderProvenance::gateway_rejection(response_headers),
                ));
            }
        }
    }

    /// Record the header result of one completed trusted gateway phase.
    pub(crate) fn record_deadline_response_header_mutations(
        &mut self,
        response_headers: &HashMap<String, String>,
    ) {
        if let Some(state) = self.buffered_deadline_response_header_provenance.as_mut() {
            Arc::make_mut(state).record_gateway_mutations(|_| false, response_headers);
        }
    }

    pub(crate) fn record_deadline_response_header_plugin(
        &mut self,
        plugin: &dyn Plugin,
        response_headers: &HashMap<String, String>,
    ) {
        if self.buffered_deadline_response_header_provenance.is_none() {
            return;
        }
        // Owned names are BORROWED from the response map and matched
        // case-insensitively against the canonical (lowercase) snapshot, rather
        // than being lowercased into fresh `String`s. Most plugins own nothing,
        // so the common case is an empty collect with no per-name allocation at
        // all; a declaring plugin allocates one small `Vec<&str>` instead of one
        // `String` per response header. Same matching helper as
        // `record_deadline_owned_response_headers`, so the two cannot diverge.
        let plugin_owned_headers = response_headers
            .keys()
            .filter(|name| plugin.owns_deadline_response_header(self, name))
            .map(String::as_str)
            .collect::<Vec<_>>();
        if let Some(state) = self.buffered_deadline_response_header_provenance.as_mut() {
            Arc::make_mut(state).record_gateway_mutations(
                |name| header_name_is_declared(&plugin_owned_headers, name),
                response_headers,
            );
        }
    }

    /// Whether backend/gateway terminal-replacement provenance is being tracked
    /// for this request. Trusted response hooks whose owned-name set must be
    /// COMPUTED (e.g. `response_transformer` accumulating fired `update` /
    /// `rename` / `add` keys) consult this first so that work is skipped
    /// entirely on the common path with neither an absolute RPC deadline nor a
    /// configured body policy that may reject. Hooks that
    /// own a fixed name can call
    /// [`Self::record_deadline_owned_response_headers`] with a borrowed static
    /// slice unconditionally — it allocates nothing and returns immediately
    /// when provenance is absent.
    pub(crate) fn has_buffered_deadline_response_header_provenance(&self) -> bool {
        self.buffered_deadline_response_header_provenance.is_some()
    }

    /// Record response-header keys a completed trusted hook authoritatively
    /// wrote even when the value matches what the backend already supplied
    /// (e.g. a `response_transformer` `update` rule or route override). Mutation
    /// tracking alone drops such a write, so a backend that pre-populates the
    /// identical key/value could otherwise suppress the gateway decoration on a
    /// terminal deadline rebuild. Declaring the keys owned keeps them in
    /// `gateway_headers`.
    ///
    /// # Ownership means REPLACEMENT
    ///
    /// Declaring a name here asserts that the hook wrote the field's WHOLE
    /// value, so nothing backend-authored remains underneath it and the
    /// field's backend baseline is retired. A hook that only APPENDS onto a
    /// value the backend may also have supplied must NOT be declared here — it
    /// records through [`Self::record_deadline_response_header_mutations`] and
    /// stays on the occurrence-partition branch (sticky-affinity cookie
    /// injection), or, when it appends a known configured element set that an
    /// exact backend spoof could hide, through
    /// [`Self::record_deadline_authored_response_header_elements`].
    ///
    /// Names are matched case-insensitively against the canonical (lowercase)
    /// snapshot rather than being lowercased into a fresh `Vec<String>`, so
    /// callers can pass borrowed static names (`&["set-cookie"]`) and pay no
    /// per-request allocation for provenance bookkeeping, whether or not a
    /// deadline is being tracked.
    pub(crate) fn record_deadline_owned_response_headers(
        &mut self,
        owned_header_names: &[&str],
        response_headers: &HashMap<String, String>,
    ) {
        if let Some(state) = self.buffered_deadline_response_header_provenance.as_mut() {
            Arc::make_mut(state).record_gateway_mutations(
                |name| header_name_is_declared(owned_header_names, name),
                response_headers,
            );
        }
    }

    /// Record a completed trusted hook that APPENDED a known, gateway-configured
    /// element set onto a list-valued response header the backend may also have
    /// supplied.
    ///
    /// Whole-field ownership ([`Self::record_deadline_owned_response_headers`])
    /// is wrong for such a hook — it would credit the backend-only elements
    /// sharing the field onto the synthesized deadline response. Plain mutation
    /// tracking is also insufficient — a backend that pre-populates the
    /// identical combined list hides the write entirely, so the deadline rebuild
    /// silently drops the operator-configured elements. This retires one backend
    /// baseline occurrence per authored element and then re-partitions the field
    /// even when its live value is unchanged, so the ordinary occurrence
    /// partition credits exactly the gateway's contribution and no backend-only
    /// element ever crosses over. See
    /// [`BufferedDeadlineResponseHeaderProvenance::retire_backend_authored_elements`].
    ///
    /// `name` must already be canonical (lowercase). Like the sibling recorders
    /// this returns immediately when no terminal-replacement provenance is
    /// being tracked, and it borrows the authored elements rather than cloning
    /// them.
    pub(crate) fn record_deadline_authored_response_header_elements(
        &mut self,
        name: &str,
        authored_elements: &[&str],
        response_headers: &HashMap<String, String>,
    ) {
        if let Some(state) = self.buffered_deadline_response_header_provenance.as_mut() {
            let state = Arc::make_mut(state);
            state.retire_backend_authored_elements(name, authored_elements);
            // Re-partition this field unconditionally: the exact-spoof case this
            // recorder exists for leaves the live value byte-identical to the
            // last observation, so the plain net-diff short-circuit would skip
            // the field and the baseline just retired would never be consulted.
            state.record_gateway_mutations_with_repartition(
                |_| false,
                |candidate| candidate == name,
                response_headers,
            );
        }
    }

    /// Rebuild a terminal deadline header map from provenance-known gateway
    /// output plus the narrow `Vary: Origin` compatibility contract.
    pub(crate) fn retain_deadline_response_gateway_headers(
        &mut self,
        response_headers: &mut HashMap<String, String>,
    ) {
        if let Some(state) = self.buffered_deadline_response_header_provenance.as_mut() {
            Arc::make_mut(state).retain_gateway_output(response_headers);
            return;
        }
        let preserve_origin_vary = response_headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("vary")
                && value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("origin"))
        });
        response_headers.clear();
        if preserve_origin_vary {
            response_headers.insert("vary".to_string(), "Origin".to_string());
        }
    }

    pub(crate) fn sync_deadline_response_terminal_headers(
        &mut self,
        response_headers: &HashMap<String, String>,
    ) {
        if let Some(state) = self.buffered_deadline_response_header_provenance.as_mut() {
            Arc::make_mut(state).sync_terminal_headers(response_headers);
        }
    }

    /// Build the lightweight compatibility context used by final request-body
    /// hooks when the active plugin needs request metadata after body
    /// transforms. The compressor's private staged representation and incoming
    /// classification path are moved into this context so the authoritative
    /// wire transform can consume them without recomputing or retaining a
    /// prompt-sized copy on the real context. Only `metadata` and selected
    /// policy state are copied back by the proxy caller, so this deliberately
    /// skips raw headers, raw query strings, parsed query maps, prebuffered body
    /// bytes, and mirror receivers.
    pub(crate) fn clone_for_final_request_body_hooks(&mut self) -> Self {
        Self {
            client_ip: self.client_ip.clone(),
            direct_client_ip: self.direct_client_ip.clone(),
            canonical_client_ip: self.canonical_client_ip.clone(),
            method: self.method.clone(),
            path: self.path.clone(),
            raw_path: self.raw_path.clone(),
            request_authority: self.request_authority.clone(),
            request_is_secure: self.request_is_secure,
            frontend_listen_port: self.frontend_listen_port,
            frontend_sni_hostname: self.frontend_sni_hostname.clone(),
            lb_generation: self.lb_generation,
            proxy_lifecycle_generation: self.proxy_lifecycle_generation,
            raw_headers: None,
            headers: self.headers.clone(),
            headers_materialized: true,
            raw_query_string: None,
            query_params_materialized: false,
            query_params: HashMap::new(),
            matched_proxy: self.matched_proxy.clone(),
            identified_consumer: self.identified_consumer.clone(),
            authenticated_identity: self.authenticated_identity.clone(),
            authenticated_identity_header: self.authenticated_identity_header.clone(),
            backend_geo_country: self.backend_geo_country,
            auth_method: self.auth_method,
            timestamp_received: self.timestamp_received,
            grpc_deadline_initialized: self.grpc_deadline_initialized,
            grpc_deadline_had_valid_client_timeout: self.grpc_deadline_had_valid_client_timeout,
            grpc_deadline_received_at: self.grpc_deadline_received_at,
            grpc_deadline_preflight_complete: self.grpc_deadline_preflight_complete,
            grpc_deadline_budget_ms: self.grpc_deadline_budget_ms,
            grpc_deadline_at: self.grpc_deadline_at,
            grpc_deadline_header_is_remaining: self.grpc_deadline_header_is_remaining,
            gateway_deadline_response_selected: self.gateway_deadline_response_selected,
            response_cache_hit: self.response_cache_hit,
            // Omit `request_body` (the full buffered prompt): no
            // `on_final_request_body` hook reads it from the context — they all
            // take the body as a `&[u8]` parameter — so copying it here would burn
            // memory bandwidth on every buffered request for nothing. The handler
            // carries the original `request_body` across the metadata swap when it
            // writes the hook context back.
            metadata: self
                .metadata
                .iter()
                .filter(|(k, _)| k.as_str() != "request_body")
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            ai_usage_export: self.ai_usage_export.clone(),
            ai_usage_export_token_prefix: self.ai_usage_export_token_prefix.clone(),
            ai_usage_export_cost_prefix: self.ai_usage_export_cost_prefix.clone(),
            // Final request-body hooks cannot observe or mutate the real CORS
            // aggregate. CORS has no body hook, and only metadata is copied
            // back from this compatibility context.
            cors_state: cors::CorsRequestState::default(),
            // Claim-header staging stays on the real request context. Final
            // body hooks never consume it, and copying raw claim values into a
            // compatibility clone would extend their lifetime unnecessarily.
            pending_claim_headers: HashMap::new(),
            sanitized_claim_header_destinations: HashSet::new(),
            request_headers_to_redact: self.request_headers_to_redact.clone(),
            buffered_initial_response_header_policy_state: None,
            buffered_deadline_response_header_provenance: None,
            request_http_flavor: self.request_http_flavor,
            original_accept_encoding: self.original_accept_encoding.clone(),
            websocket_response_boundary: self.websocket_response_boundary,
            ai_semantic_cache_embeddings: self.ai_semantic_cache_embeddings.clone(),
            ai_semantic_cache_scope_keys: self.ai_semantic_cache_scope_keys.clone(),
            openapi_validator_matches: self.openapi_validator_matches.clone(),
            ai_tool_governor_response_hashes: self.ai_tool_governor_response_hashes.clone(),
            ai_response_guard_replay_redactions: self.ai_response_guard_replay_redactions.clone(),
            ai_tool_governor_replay_redactions: self.ai_tool_governor_replay_redactions.clone(),
            ai_tool_governor_call_hashes: self.ai_tool_governor_call_hashes.clone(),
            ai_tool_governor_request_hashes: self.ai_tool_governor_request_hashes.clone(),
            ai_tool_governor_redaction_memos: self.ai_tool_governor_redaction_memos.clone(),
            ai_semantic_firewall_request_hashes: self.ai_semantic_firewall_request_hashes.clone(),
            ai_semantic_firewall_response_hashes: self.ai_semantic_firewall_response_hashes.clone(),
            request_deduplication_states: self.request_deduplication_states.clone(),
            finalized_response_replay: self.finalized_response_replay,
            response_policy_stamp: self.response_policy_stamp.clone(),
            response_presentation_policy_digest: self.response_presentation_policy_digest,
            serverless_pre_invocation_rejection_owners: self
                .serverless_pre_invocation_rejection_owners
                .clone(),
            serverless_external_side_effect_owners: self
                .serverless_external_side_effect_owners
                .clone(),
            serverless_terminate_response: self.serverless_terminate_response,
            serverless_owned_dedup_publication: self.serverless_owned_dedup_publication,
            // Transfer rather than clone the potentially body-sized compressor
            // stage. The final wire hook consumes it from this compatibility
            // context, while the live context no longer retains a second copy.
            ai_prompt_compressor_staged: std::mem::take(&mut self.ai_prompt_compressor_staged),
            ai_prompt_compressor_classification_path: std::mem::take(
                &mut self.ai_prompt_compressor_classification_path,
            ),
            ai_prompt_compressor_wire_stats_started: std::mem::take(
                &mut self.ai_prompt_compressor_wire_stats_started,
            ),
            ai_prompt_compressor_marker_reject_status: std::mem::take(
                &mut self.ai_prompt_compressor_marker_reject_status,
            ),
            gateway_response_compression_algorithm: self.gateway_response_compression_algorithm,
            compression_request_decode_owner: self.compression_request_decode_owner,
            compression_response_encode_owner: self.compression_response_encode_owner,
            compression_response_admission_owner: self.compression_response_admission_owner,
            compression_response_admission_declined: self.compression_response_admission_declined,
            // The reserved response-buffer permit stays on the donor (live)
            // context: this compatibility clone runs only the request-body hooks,
            // never the response-body transform that consumes the permit. Moving
            // it here would drop the slot when this short-lived clone is dropped
            // (only `metadata`/WAF/AI state is copied back), releasing admission
            // while the live context still owns the response encode.
            compression_response_buffer_permit: HeldResponseBufferPermit::default(),
            compression_staged_request_plaintext: std::mem::take(
                &mut self.compression_staged_request_plaintext,
            ),
            compression_response_encode_aborted: std::mem::take(
                &mut self.compression_response_encode_aborted,
            ),
            response_stream_id: self.response_stream_id,
            response_stream_completion: self.response_stream_completion.clone(),
            a2a_gateway_detected: self.a2a_gateway_detected,
            a2a_gateway_binding: self.a2a_gateway_binding,
            a2a_gateway_is_agent_card: self.a2a_gateway_is_agent_card,
            a2a_gateway_streaming: self.a2a_gateway_streaming,
            mcp_response_resource_binding: self.mcp_response_resource_binding.clone(),
            mcp_trusted_tool_name_rewrite: self.mcp_trusted_tool_name_rewrite.clone(),
            waf_metadata_initialized: self.waf_metadata_initialized,
            waf_owned_metadata: self.waf_owned_metadata.clone(),
            waf_instance_scores: self.waf_instance_scores.clone(),
            mesh_request_auth_audiences: self.mesh_request_auth_audiences.clone(),
            mesh_request_auth_claims: self.mesh_request_auth_claims.clone(),
            tls_client_cert_der: self.tls_client_cert_der.clone(),
            tls_client_cert_chain_der: self.tls_client_cert_chain_der.clone(),
            mtls_auth_connection_cache: self.mtls_auth_connection_cache.clone(),
            peer_spiffe_extraction_cache: self.peer_spiffe_extraction_cache.clone(),
            peer_spiffe_id: self.peer_spiffe_id.clone(),
            plugin_http_call_ns: Arc::clone(&self.plugin_http_call_ns),
            reject_hook_execution_ns: Arc::clone(&self.reject_hook_execution_ns),
            // Watch receivers are clone-safe. Preserve them so the detached
            // gRPC-deadline logging path (which intentionally clones the
            // context before spawning cleanup) still emits every dispatched
            // mirror result.
            mirror_result_rxs: self.mirror_result_rxs.clone(),
            hmac_prebuffer_state: hmac_auth::HmacPrebufferState::default(),
            request_body_bytes: None,
            request_body_sha256: None,
            request_body_sha512: None,
            max_response_body_size_bytes: self.max_response_body_size_bytes,
            bytes_sent_observed: Arc::clone(&self.bytes_sent_observed),
            is_early_data: self.is_early_data,
            mesh_route_dispatch_reject_unmatched: self.mesh_route_dispatch_reject_unmatched,
            mesh_route_dispatch_matched: self.mesh_route_dispatch_matched,
            route_override_upstream_id: self.route_override_upstream_id.clone(),
            route_override_backend_host: self.route_override_backend_host.clone(),
            route_override_backend_scheme: self.route_override_backend_scheme,
            route_override_backend_port: self.route_override_backend_port,
            route_override_resolved_tls: self.route_override_resolved_tls.clone(),
            route_override_backend_read_timeout_ms: self.route_override_backend_read_timeout_ms,
            route_override_retry: self.route_override_retry.clone(),
            route_override_request_transform: self.route_override_request_transform.clone(),
            route_override_response_transform: self.route_override_response_transform.clone(),
            route_override_path: self.route_override_path.clone(),
            authorized_backend_path: self.authorized_backend_path.clone(),
            route_override_path_is_absolute: self.route_override_path_is_absolute,
            route_override_authority: self.route_override_authority.clone(),
            node_waypoint_pod_uid: self.node_waypoint_pod_uid,
            node_waypoint_policy_scope: self.node_waypoint_policy_scope.clone(),
            mesh_direction: self.mesh_direction,
            orig_dst: self.orig_dst,
            mesh_outbound_destination_authz_port: self.mesh_outbound_destination_authz_port,
            mesh_inbound_listener_authz_port: self.mesh_inbound_listener_authz_port,
        }
    }

    /// Pin (once) and return this request's response-side policy stamp.
    ///
    /// One ArcSwap load on first call, then a memoized opaque identity. Callers
    /// pin as early as possible on the request path so the pinned value covers
    /// every gate read the response pipeline will later perform.
    pub(crate) fn pin_response_policy_stamp(&mut self) -> &GatePolicyStamp {
        self.response_policy_stamp
            .get_or_insert_with(response_transformer::runtime_overlay::policy_stamp)
    }

    /// Whether no response-side gate publication happened since this request
    /// pinned its stamp.
    ///
    /// A `false` result means some gate read during this request may have used
    /// a different policy than the pinned stamp describes, so any
    /// representation produced by this request has unprovable provenance and
    /// must not be persisted for later replay.
    pub(crate) fn response_policy_stamp_stable(&mut self) -> bool {
        let current = response_transformer::runtime_overlay::policy_stamp();
        self.pin_response_policy_stamp() == &current
    }

    /// Record the effective static response-presentation policy digest for this
    /// request, taken from its plugin-cache view.
    ///
    /// Called once per request on the protocol entry paths, before any plugin
    /// runs, so it always describes the same cache generation whose instances
    /// will shape the response.
    pub(crate) fn set_response_presentation_policy_digest(&mut self, digest: Option<[u8; 32]>) {
        self.response_presentation_policy_digest = digest;
    }

    /// Complete replay provenance for this request's response-side presentation
    /// policy: the pinned RTDS gate content plus the effective static rules.
    ///
    /// See `ResponsePolicyProvenance` for what each half proves and why both
    /// are required.
    pub(crate) fn response_policy_provenance(&mut self) -> ResponsePolicyProvenance {
        let gate = self.pin_response_policy_stamp().fingerprint();
        ResponsePolicyProvenance {
            gate,
            presentation: self.response_presentation_policy_digest,
        }
    }

    pub(crate) fn ensure_waf_metadata_initialized(&mut self) {
        if self.waf_metadata_initialized {
            return;
        }
        self.metadata.retain(|key, _| !key.starts_with("waf."));
        self.waf_owned_metadata.clear();
        self.waf_metadata_initialized = true;
    }

    pub(crate) fn set_request_headers_to_redact(&mut self, headers: Arc<Vec<String>>) {
        if !headers.is_empty() {
            self.request_headers_to_redact = Some(headers);
        }
    }

    pub(crate) fn set_websocket_response_boundary(&mut self, enabled: bool) {
        self.websocket_response_boundary = enabled;
    }

    pub(crate) fn set_request_http_flavor(&mut self, flavor: HttpFlavor) {
        self.request_http_flavor = flavor;
        self.set_websocket_response_boundary(matches!(flavor, HttpFlavor::WebSocket));
    }

    pub(crate) fn is_native_grpc_request(&self) -> bool {
        matches!(self.request_http_flavor, HttpFlavor::Grpc)
    }

    /// Record the client's original `Accept-Encoding` once, at request init.
    ///
    /// Write-once by construction: a later caller — a plugin reaching this
    /// through any in-crate path, or a second stamp on a retried dispatch —
    /// cannot replace the value the client actually sent. An absent header is
    /// left absent, because "the client sent nothing" and "the client sent an
    /// empty field" are different negotiations (RFC 9110 §12.5.3).
    pub(crate) fn set_original_accept_encoding(&mut self, value: String) {
        if self.original_accept_encoding.is_none() {
            self.original_accept_encoding = Some(value);
        }
    }

    /// The client's original `Accept-Encoding`, or `None` when the request
    /// carried none (or reached a direct plugin caller that never stamped).
    pub(crate) fn original_accept_encoding(&self) -> Option<&str> {
        self.original_accept_encoding.as_deref()
    }

    pub(crate) fn has_websocket_response_boundary(&self) -> bool {
        self.websocket_response_boundary
    }

    pub(crate) fn request_header_requires_redaction(&self, header_name: &str) -> bool {
        self.request_headers_to_redact
            .as_ref()
            .is_some_and(|headers| {
                headers
                    .iter()
                    .any(|header| header_name.eq_ignore_ascii_case(header))
            })
    }

    pub(crate) fn set_waf_metadata(&mut self, key: &str, value: impl Into<String>) {
        self.ensure_waf_metadata_initialized();
        let value = value.into();
        self.waf_owned_metadata
            .insert(key.to_string(), value.clone());
        self.metadata.insert(key.to_string(), value);
    }

    pub(crate) fn clear_waf_metadata(&mut self, key: &str) {
        self.ensure_waf_metadata_initialized();
        self.waf_owned_metadata.remove(key);
        self.metadata.remove(key);
    }

    pub(crate) fn set_waf_metadata_if_absent(&mut self, key: &str, value: impl Into<String>) {
        self.ensure_waf_metadata_initialized();
        if self.waf_owned_metadata.contains_key(key) {
            return;
        }
        self.set_waf_metadata(key, value);
    }

    /// Accumulate anomaly score for one WAF instance and return its new total.
    /// A never-seen zero contribution remains absent so a noncontributing
    /// sibling cannot turn single-instance metadata into a multi-instance view.
    pub(crate) fn accumulate_waf_instance_score(
        &mut self,
        instance_id: u64,
        identity: &std::sync::Arc<str>,
        contribution: u32,
    ) -> Option<u32> {
        if contribution == 0 && !self.waf_instance_scores.contains_key(&instance_id) {
            return None;
        }
        let entry = self
            .waf_instance_scores
            .entry(instance_id)
            .or_insert_with(|| WafInstanceScoreState {
                identity: std::sync::Arc::clone(identity),
                score: 0,
            });
        entry.score = entry.score.saturating_add(contribution);
        Some(entry.score)
    }

    pub(crate) fn merge_waf_metadata(&mut self, key: &str, value: &str) {
        if value.is_empty() {
            return;
        }
        self.ensure_waf_metadata_initialized();
        merge_metadata_value(&mut self.waf_owned_metadata, key, value);
        // `merge_metadata_value` always inserts or modifies the entry, so
        // `get(key)` is guaranteed `Some` here; no fallback branch needed.
        if let Some(owned_value) = self.waf_owned_metadata.get(key) {
            self.metadata.insert(key.to_string(), owned_value.clone());
        }
    }

    pub(crate) fn waf_metadata_value(&self, key: &str) -> Option<&str> {
        self.waf_owned_metadata.get(key).map(String::as_str)
    }

    pub(crate) fn apply_waf_owned_log_metadata(&self, metadata: &mut HashMap<String, String>) {
        metadata.retain(|key, _| !key.starts_with("waf."));
        metadata.extend(
            self.waf_owned_metadata
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
    }

    /// Effective upstream id for routing: plugin upstream override >
    /// direct-backend override (clears upstream) > proxy.upstream_id.
    /// Pool keys mentioning upstream identity must derive from this.
    #[inline]
    pub fn effective_upstream_id<'a>(&'a self, proxy: &'a Proxy) -> Option<&'a str> {
        if let Some(upstream_id) = self.route_override_upstream_id.as_deref() {
            return Some(upstream_id);
        }
        if self.route_override_backend_host.is_some() || self.route_override_backend_port.is_some()
        {
            return None;
        }
        proxy.upstream_id.as_deref()
    }

    /// Effective backend host for routing: plugin override > proxy.backend_host.
    #[inline]
    pub fn effective_backend_host<'a>(&'a self, proxy: &'a Proxy) -> &'a str {
        self.route_override_backend_host
            .as_deref()
            .unwrap_or(proxy.backend_host.as_str())
    }

    /// Effective backend port for routing: plugin override > proxy.backend_port.
    #[inline]
    pub fn effective_backend_port(&self, proxy: &Proxy) -> u16 {
        self.route_override_backend_port
            .unwrap_or(proxy.backend_port)
    }

    /// True when any of the route-override fields are set by a plugin.
    /// Used at dispatch entry to decide whether to clone the matched
    /// `Proxy` and bake in the overrides.
    #[inline]
    pub fn has_route_overrides(&self) -> bool {
        self.route_override_upstream_id.is_some()
            || self.route_override_backend_host.is_some()
            || self.route_override_backend_scheme.is_some()
            || self.route_override_backend_port.is_some()
            || self.route_override_resolved_tls.is_some()
            || self.route_override_backend_read_timeout_ms.is_some()
            || self.route_override_retry.is_some()
    }

    /// Build a `Proxy` Arc with any plugin-set route overrides applied. If no
    /// effective override is set, returns the original `Arc` (no struct alloc).
    /// When overrides change the proxy, allocates one `Proxy` struct + `Arc`.
    ///
    /// Downstream dispatch reads `proxy.upstream_id` / `proxy.backend_host` /
    /// `proxy.backend_port` / `proxy.resolved_tls` directly; using the
    /// returned `Arc<Proxy>` makes direct-backend overrides transparent to
    /// dispatch sites that already accept `&Proxy` (pool keys, capability
    /// registry, URL construction, backend TLS, etc.).
    ///
    /// Upstream-id overrides still need a later load-balancer target
    /// selection before `backend_host` / `backend_port` can be rebased. Any
    /// backend pool that keys or dials from those proxy fields must bake the
    /// selected target into its per-dispatch proxy after LB selection.
    ///
    /// This convenience helper cannot re-resolve `resolved_tls` when
    /// `route_override_upstream_id` points at a different upstream because it
    /// has no upstream snapshot. Custom dispatch paths that allow upstream
    /// overrides should call [`RequestContext::apply_route_overrides_with_upstreams`]
    /// instead, or they can silently keep the original proxy's backend TLS
    /// client certificate / CA / verify policy.
    pub fn apply_route_overrides(&self, proxy: Arc<Proxy>) -> Arc<Proxy> {
        self.apply_route_overrides_inner(proxy, None)
    }

    /// Build a `Proxy` Arc with plugin-set route overrides applied, re-resolving
    /// backend TLS from the supplied upstream snapshot when
    /// `route_override_upstream_id` changes the effective upstream.
    ///
    /// Use this variant for dispatch paths that might honor upstream-id
    /// overrides. It preserves the upstream-id / TLS / per-port-policy
    /// portion of the effective routing target. Pool-backed transports that
    /// read `proxy.backend_host` / `proxy.backend_port` directly must still
    /// rebase those fields after load-balancer target selection.
    pub fn apply_route_overrides_with_upstreams(
        &self,
        proxy: Arc<Proxy>,
        upstreams: &HashMap<String, Arc<Upstream>>,
    ) -> Arc<Proxy> {
        self.apply_route_overrides_inner(proxy, Some(upstreams))
    }

    fn apply_route_overrides_inner(
        &self,
        proxy: Arc<Proxy>,
        upstreams: Option<&HashMap<String, Arc<Upstream>>>,
    ) -> Arc<Proxy> {
        let direct_backend_override = self.route_override_upstream_id.is_none()
            && (self.route_override_backend_host.is_some()
                || self.route_override_backend_scheme.is_some()
                || self.route_override_backend_port.is_some());
        let upstream_id_changed = if direct_backend_override {
            proxy.upstream_id.is_some()
        } else {
            self.route_override_upstream_id
                .as_deref()
                .is_some_and(|id| proxy.upstream_id.as_deref() != Some(id))
        };
        let backend_host_changed = self
            .route_override_backend_host
            .as_deref()
            .is_some_and(|host| proxy.backend_host != host);
        let backend_scheme_changed = self
            .route_override_backend_scheme
            .is_some_and(|scheme| proxy.effective_scheme() != scheme);
        let backend_port_changed = self
            .route_override_backend_port
            .is_some_and(|port| proxy.backend_port != port);
        let dns_override_changed =
            direct_backend_override && backend_host_changed && proxy.dns_override.is_some();

        let upstream_tls_override = if upstream_id_changed {
            self.route_override_upstream_id
                .as_deref()
                .and_then(|id| upstreams.and_then(|map| map.get(id)))
                .map(|upstream| BackendTlsConfig::from_upstream(upstream))
        } else {
            None
        };
        let direct_backend_tls_override =
            if direct_backend_override && (proxy.upstream_id.is_some() || backend_scheme_changed) {
                Some(BackendTlsConfig::from_proxy(&proxy))
            } else {
                None
            };
        let resolved_tls_override = self
            .route_override_resolved_tls
            .clone()
            .or(upstream_tls_override)
            .or(direct_backend_tls_override);
        let resolved_tls_changed = resolved_tls_override
            .as_ref()
            .is_some_and(|tls| *tls != proxy.resolved_tls);
        let dispatch_port_overrides_override = if upstream_id_changed {
            if direct_backend_override {
                Some(None)
            } else {
                Some(
                    self.route_override_upstream_id
                        .as_deref()
                        .and_then(|id| upstreams.and_then(|map| map.get(id)))
                        .and_then(|upstream| dispatch_port_overrides_from_upstream(upstream)),
                )
            }
        } else {
            None
        };
        let dispatch_port_overrides_changed = dispatch_port_overrides_override
            .as_ref()
            .is_some_and(|overrides| *overrides != proxy.dispatch_port_overrides);
        // Recompute the service-discovery top-level `connectionPool.http`
        // fallback for the override's destination, exactly mirroring
        // `dispatch_port_overrides` above: a direct-backend override clears it
        // (no upstream → no overlay), an upstream-id override recomputes it from
        // the NEW upstream. Without this, a route from an SD upstream LEAKS its
        // top-level fallback onto a different destination, and a route TO an SD
        // upstream LOSES that destination's fallback (see #1806 codex r1).
        let dispatch_port_override_fallback_override = if upstream_id_changed {
            if direct_backend_override {
                Some(None)
            } else {
                Some(
                    self.route_override_upstream_id
                        .as_deref()
                        .and_then(|id| upstreams.and_then(|map| map.get(id)))
                        .and_then(|upstream| {
                            crate::config::types::dispatch_port_override_fallback_from_upstream(
                                upstream,
                            )
                        }),
                )
            }
        } else {
            None
        };
        let dispatch_port_override_fallback_changed = dispatch_port_override_fallback_override
            .as_ref()
            .is_some_and(|fallback| *fallback != proxy.dispatch_port_override_fallback);
        let backend_read_timeout_changed = self
            .route_override_backend_read_timeout_ms
            .is_some_and(|timeout| timeout != proxy.backend_read_timeout_ms);
        let retry_changed = self
            .route_override_retry
            .as_ref()
            .is_some_and(|retry| proxy.retry != *retry);
        // An Istio `rewrite.authority` rebases the `Host`/`:authority` forwarded
        // to the backend. The plugin already wrote the new authority into the
        // request `host` header; flipping `preserve_host_header` on the
        // effective proxy makes every backend-dispatch path (reqwest / H2 /
        // gRPC / H3 / HBONE) forward that header verbatim instead of clobbering
        // it with the backend's own host.
        let preserve_host_changed =
            self.route_override_authority.is_some() && !proxy.preserve_host_header;
        let strip_listen_path_changed =
            self.route_override_path_is_absolute && proxy.strip_listen_path;
        let backend_path_changed =
            self.route_override_path_is_absolute && proxy.backend_path.is_some();

        if !upstream_id_changed
            && !backend_host_changed
            && !backend_scheme_changed
            && !backend_port_changed
            && !dns_override_changed
            && !resolved_tls_changed
            && !dispatch_port_overrides_changed
            && !dispatch_port_override_fallback_changed
            && !backend_read_timeout_changed
            && !retry_changed
            && !preserve_host_changed
            && !strip_listen_path_changed
            && !backend_path_changed
        {
            return proxy;
        }

        let mut overridden = (*proxy).clone();
        if let Some(id) = &self.route_override_upstream_id {
            overridden.upstream_id = Some(id.clone());
            if upstream_id_changed {
                overridden.upstream_subset = None;
            }
        } else if direct_backend_override {
            overridden.upstream_id = None;
            overridden.upstream_subset = None;
        }
        if let Some(host) = &self.route_override_backend_host {
            overridden.backend_host = host.clone();
        }
        if let Some(scheme) = self.route_override_backend_scheme {
            overridden.backend_scheme = Some(scheme);
            overridden.dispatch_kind = DispatchKind::from(scheme);
        }
        if let Some(port) = self.route_override_backend_port {
            overridden.backend_port = port;
        }
        if dns_override_changed {
            overridden.dns_override = None;
        }
        if let Some(resolved_tls) = resolved_tls_override {
            overridden.resolved_tls = resolved_tls;
        }
        if let Some(dispatch_port_overrides) = dispatch_port_overrides_override {
            overridden.dispatch_port_overrides = dispatch_port_overrides;
        }
        if let Some(dispatch_port_override_fallback) = dispatch_port_override_fallback_override {
            overridden.dispatch_port_override_fallback = dispatch_port_override_fallback;
        }
        if let Some(timeout) = self.route_override_backend_read_timeout_ms {
            overridden.backend_read_timeout_ms = timeout;
        }
        if let Some(retry) = &self.route_override_retry {
            overridden.retry = retry.clone();
        }
        if preserve_host_changed {
            overridden.preserve_host_header = true;
        }
        if strip_listen_path_changed {
            overridden.strip_listen_path = false;
        }
        if backend_path_changed {
            overridden.backend_path = None;
        }
        Arc::new(overridden)
    }

    // -- Lazy header materialization -----------------------------------------

    /// Store the raw `http::HeaderMap` for deferred materialization. Call this
    /// once at request init time instead of eagerly converting every header to
    /// owned `String`s.
    #[inline]
    pub fn set_raw_headers(&mut self, headers: HeaderMap) {
        self.headers_materialized = false;
        self.raw_headers = Some(headers);
    }

    /// Whether the pristine wire `HeaderMap` is still available for
    /// multi-value / byte-validity policy evaluation.
    #[inline]
    pub fn has_raw_headers(&self) -> bool {
        self.raw_headers.is_some()
    }

    /// Look up a single header from the raw `HeaderMap` without materializing
    /// the full `HashMap<String, String>`. Returns `None` when no raw headers
    /// were stored.
    ///
    /// Single hash lookup for call sites that only need one field-line value.
    /// Multiple `Host` headers are rejected earlier by `check_protocol_headers()`.
    /// For list-style headers that may span multiple field-lines (for example
    /// `x-forwarded-for`), use `raw_header_values()` and fold them explicitly.
    #[inline]
    pub fn raw_header_get(&self, name: &str) -> Option<&str> {
        self.raw_headers
            .as_ref()
            .and_then(|h| h.get(name))
            .and_then(|v| v.to_str().ok())
    }

    /// Iterate all UTF-8 values for a raw header without materializing the full
    /// header map. Returns an empty iterator when raw headers were never set.
    /// Non-UTF-8 field lines are skipped here; security decisions that must see
    /// every field line should use [`Self::raw_header_value_bytes`].
    #[inline]
    pub fn raw_header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.raw_headers
            .iter()
            .flat_map(move |headers| headers.get_all(name).iter())
            .filter_map(|value| value.to_str().ok())
    }

    /// Iterate every raw field-line value as bytes, including values that are
    /// not valid UTF-8. Security decisions that depend on the final field line
    /// must use this instead of silently skipping an unparseable value.
    #[inline]
    pub fn raw_header_value_bytes<'a>(
        &'a self,
        name: &'a str,
    ) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.raw_headers
            .iter()
            .flat_map(move |headers| headers.get_all(name).iter())
            .map(|value| value.as_bytes())
    }

    /// Iterate every field-line of `name` for a trust-boundary decision,
    /// regardless of whether headers have been materialized.
    ///
    /// While the pristine wire map is held this is exactly
    /// [`Self::raw_header_value_bytes`]: every field-line, including non-UTF-8
    /// ones, so multiplicity is observable. If a caller ever reaches this
    /// without raw headers, it degrades to the single folded value from the
    /// materialized map — which joins repeated field-lines with `, ` and is
    /// therefore rejected as a comma list by the single-value contract in
    /// `client_ip::resolve_real_ip_header_field_lines`. Both states fail closed;
    /// neither can silently surface one of several competing values.
    ///
    /// Allocation-free: the returned iterator borrows in place.
    #[inline]
    pub fn header_field_lines<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        let raw = self.raw_headers.as_ref();
        let folded = match raw {
            Some(_) => None,
            None => self.headers.get(name).map(|value| value.as_bytes()),
        };
        raw.into_iter()
            .flat_map(move |headers| headers.get_all(name).iter())
            .map(|value| value.as_bytes())
            .chain(folded)
    }

    /// Whether a header name is reserved for gateway-asserted metadata and
    /// must not be trusted from client-supplied wire headers.
    #[inline]
    pub fn is_reserved_gateway_assertion_header(name: &str) -> bool {
        matches!(
            name,
            "x-consumer-username" | "x-consumer-custom-id" | "x-geo-country"
        ) || name.starts_with("x-path-param-")
    }

    /// Convert the raw `http::HeaderMap` into `self.headers` (`HashMap<String,
    /// String>`). This is a one-time operation — subsequent calls are no-ops.
    /// The raw map is retained so plugins can evaluate multi-value and
    /// non-UTF-8 field lines. Non-UTF-8 header values are still omitted from
    /// the materialized map (same as the previous eager path).
    pub fn materialize_headers(&mut self) {
        if self.headers_materialized {
            return;
        }
        self.headers_materialized = true;
        let Some(raw) = self.raw_headers.as_ref() else {
            return;
        };
        self.headers.reserve(raw.keys_len());
        for (name, value) in raw {
            if let Ok(v) = value.to_str() {
                // http::HeaderName stores names in lowercase already (HTTP/2+3
                // spec), and hyper normalizes HTTP/1.1 header names to
                // lowercase at parse time. No `to_lowercase()` needed.
                let key = name.as_str();
                // Reserved gateway-asserted headers are never trusted from
                // clients. Identity headers are injected after
                // authentication; path-param headers are injected after
                // route matching from regex captures.
                if Self::is_reserved_gateway_assertion_header(key) {
                    continue;
                }
                let separator = repeated_request_header_separator(key);
                self.headers
                    .entry(key.to_owned())
                    .and_modify(|existing| {
                        existing.push_str(separator);
                        existing.push_str(v);
                    })
                    .or_insert_with(|| v.to_owned());
            }
        }
    }

    // -- Lazy query param materialization ------------------------------------

    /// Store the raw query string for deferred parsing. Call this once at
    /// request init time instead of eagerly percent-decoding every param.
    #[inline]
    pub fn set_raw_query_string(&mut self, qs: String) {
        self.query_params.clear();
        self.query_params_materialized = false;
        self.raw_query_string = (!qs.is_empty()).then_some(qs);
    }

    /// Borrow the raw query string without materializing it.
    ///
    /// Inspection plugins use this to detect duplicate/conflicting parameter
    /// keys that would be collapsed by the parsed `HashMap`.
    #[inline]
    pub fn raw_query_string(&self) -> Option<&str> {
        self.raw_query_string.as_deref()
    }

    /// Record the client's original request target after canonicalization
    /// changed it. Frontends call this once, at the boundary, immediately
    /// before overwriting [`Self::path`] with the canonical form.
    #[inline]
    pub(crate) fn set_raw_path_for_hmac(&mut self, raw_path: String) {
        self.raw_path = Some(hmac_auth::HmacWirePath::new(raw_path));
    }

    /// Parse the raw query string into `self.query_params`. Keys and values are
    /// percent-decoded so plugins see human-readable strings. Parameters without
    /// `=` (e.g., `?flag`) are stored with an empty-string value.
    ///
    /// This is a one-time operation — subsequent calls are no-ops. The raw
    /// query string is intentionally retained for later security inspection.
    pub fn materialize_query_params(&mut self) {
        if self.query_params_materialized {
            return;
        }
        if let Some(raw) = self.raw_query_string.as_deref() {
            for pair in raw.split('&') {
                if pair.is_empty() {
                    continue;
                }
                let (k, v) = if let Some((k, v)) = pair.split_once('=') {
                    (k, v)
                } else {
                    (pair, "")
                };
                let decoded_k = percent_decode_str(k).decode_utf8_lossy();
                let decoded_v = percent_decode_str(v).decode_utf8_lossy();
                self.query_params
                    .insert(decoded_k.into_owned(), decoded_v.into_owned());
            }
        }
        self.query_params_materialized = true;
    }

    /// Materialize the raw query string into `self.query_params` without
    /// percent-decoding. Empty pairs are skipped and parameters without `=`
    /// (e.g., `?flag`) are stored with an empty-string value, matching the
    /// decoded variant so the only plugin-visible difference between the two is
    /// percent-decoding (and duplicate-pair collapse via the retained raw
    /// query string).
    ///
    /// HTTP/3 uses this by default to preserve its legacy plugin-visible query
    /// representation unless an active plugin explicitly opts into decoded
    /// query params.
    pub fn materialize_query_params_raw(&mut self) {
        if self.query_params_materialized {
            return;
        }
        if let Some(raw) = self.raw_query_string.as_deref() {
            for pair in raw.split('&') {
                if pair.is_empty() {
                    continue;
                }
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                self.query_params.insert(k.to_string(), v.to_string());
            }
        }
        self.query_params_materialized = true;
    }

    /// Collect mirror response metadata from every dispatched `request_mirror`
    /// instance on this request.
    ///
    /// Returns one entry per selected mirror attempt that completes or emits an
    /// explicit bounded failure/drop outcome. Sampled-out instances contribute
    /// nothing. Collection follows each mirror task/request lifetime and has no
    /// shorter independent cutoff. Callers on a client-visible response path
    /// must run this in a detached task.
    pub async fn collect_mirror_results(&self) -> Vec<MirrorResponseMeta> {
        let mut results = Vec::with_capacity(self.mirror_result_rxs.len());
        for rx in &self.mirror_result_rxs {
            if let Some(meta) = collect_mirror_result(rx.clone()).await {
                results.push(meta);
            }
        }
        results
    }

    /// Collect the first dispatched mirror result, if any.
    ///
    /// Prefer [`Self::collect_mirror_results`] when multiple instances may have
    /// dispatched. Kept for single-instance call sites and tests.
    pub async fn collect_mirror_result(&self) -> Option<MirrorResponseMeta> {
        collect_mirror_result(self.mirror_result_rxs.first()?.clone()).await
    }

    /// Record a mirror result receiver for one dispatched `request_mirror`
    /// instance. Does not replace earlier instance receivers.
    pub fn push_mirror_result_rx(
        &mut self,
        rx: tokio::sync::watch::Receiver<Option<MirrorResponseMeta>>,
    ) {
        self.mirror_result_rxs.push(rx);
    }

    /// Return the stable authenticated identity for downstream policy and
    /// observability. Gateway-mapped Consumers take precedence over external
    /// identities emitted by plugins like `jwks_auth`.
    pub fn effective_identity(&self) -> Option<&str> {
        self.identified_consumer
            .as_ref()
            .map(|consumer| consumer.username.as_str())
            .or_else(|| meaningful_identity(self.authenticated_identity.as_deref()))
    }

    /// Return the identity value to forward to the backend in
    /// `X-Consumer-Username`. This prefers the gateway Consumer username, then
    /// a plugin-provided display/header identity, then the raw external auth
    /// identity.
    ///
    /// Returns `None` when a plugin set the shared
    /// [`SUPPRESS_CONSUMER_IDENTITY_HEADERS_KEY`] marker (e.g.
    /// `ai_stream_router` routing to a third-party AI provider), so every
    /// backend-dispatch injection site (H1/H2, gRPC, WebSocket, native H3, H3
    /// WebSocket) skips the identity headers without leaking internal user
    /// identifiers to the external destination. The authenticated principal
    /// itself stays resolved — `effective_identity()` is unaffected, so rate
    /// limiting, logging, and policy plugins keep working.
    pub fn backend_consumer_username(&self) -> Option<&str> {
        let username = self
            .identified_consumer
            .as_ref()
            .map(|consumer| consumer.username.as_str())
            .or_else(|| meaningful_identity(self.authenticated_identity_header.as_deref()))
            .or_else(|| meaningful_identity(self.authenticated_identity.as_deref()))?;
        if self.suppresses_backend_consumer_identity_headers() {
            return None;
        }
        Some(username)
    }

    /// Return the Consumer custom ID to forward to the backend, if a gateway
    /// Consumer was resolved. Suppressed together with
    /// [`Self::backend_consumer_username`] — see that method's contract.
    pub fn backend_consumer_custom_id(&self) -> Option<&str> {
        let custom_id = self
            .identified_consumer
            .as_ref()
            .and_then(|consumer| consumer.custom_id.as_deref())?;
        if self.suppresses_backend_consumer_identity_headers() {
            return None;
        }
        Some(custom_id)
    }

    /// Return the GeoIP country value to assert at the backend boundary.
    ///
    /// `geo_restriction` records this packed value privately when header
    /// injection is enabled. Backend dispatch strips every mutable
    /// `x-geo-country` value and restores only this lookup result.
    pub fn backend_geo_country(&self) -> Option<&str> {
        self.backend_geo_country
            .as_ref()
            .and_then(|country| std::str::from_utf8(country).ok())
    }

    pub(crate) fn set_backend_geo_country(&mut self, country: [u8; 2]) {
        self.backend_geo_country = Some(country);
    }

    /// Whether a plugin opted this request out of gateway consumer-identity
    /// header injection (`x-consumer-username` / `x-consumer-custom-id`).
    /// Checked only after a principal resolved, so unauthenticated requests
    /// pay no extra metadata lookup.
    pub(crate) fn suppresses_backend_consumer_identity_headers(&self) -> bool {
        self.metadata
            .get(SUPPRESS_CONSUMER_IDENTITY_HEADERS_KEY)
            .map(String::as_str)
            == Some("true")
    }
}

/// Shared metadata key a plugin sets to `"true"` to suppress gateway
/// consumer-identity header injection (`x-consumer-username` /
/// `x-consumer-custom-id`) toward the backend for this request. Used by
/// plugins that reroute a request to an external third party (e.g.
/// `ai_stream_router` provider overrides) where internal user identifiers
/// must not leak. All injection sites consume this via
/// [`RequestContext::backend_consumer_username`] /
/// [`RequestContext::backend_consumer_custom_id`].
pub const SUPPRESS_CONSUMER_IDENTITY_HEADERS_KEY: &str =
    "suppress_backend_consumer_identity_headers";

/// Separator used when materializing repeated request header field lines.
///
/// RFC 9113 §8.2.3 requires H2/H3 cookie crumbs to be reassembled with
/// `"; "`. Other repeated request fields use the standard comma-list form so
/// materialized plugin headers, backend forwarding, and `Connection`-listed
/// stripping all see the complete value set.
pub(crate) fn repeated_request_header_separator(name: &str) -> &'static str {
    if name.eq_ignore_ascii_case("cookie") {
        "; "
    } else {
        ", "
    }
}

fn dispatch_port_overrides_from_upstream(
    upstream: &Upstream,
) -> Option<HashMap<u16, ResolvedPortOverride>> {
    let overrides: HashMap<u16, ResolvedPortOverride> = upstream
        .port_overrides
        .iter()
        .filter_map(|(port, ovr)| {
            ResolvedPortOverride::from_upstream_override(ovr).map(|resolved| (*port, resolved))
        })
        .collect();
    if overrides.is_empty() {
        None
    } else {
        Some(overrides)
    }
}

/// Strip an HTTP auth scheme prefix from a header value using ASCII
/// case-insensitive matching. Returns the remaining credentials/token when the
/// scheme matches and a non-empty payload follows.
pub(crate) fn strip_auth_scheme<'a>(value: &'a str, scheme: &str) -> Option<&'a str> {
    let boundary = value.find(|c: char| c.is_ascii_whitespace())?;
    let (prefix, remainder) = value.split_at(boundary);
    if !prefix.eq_ignore_ascii_case(scheme) {
        return None;
    }

    let payload = remainder.trim_start_matches(|c: char| c.is_ascii_whitespace());
    (!payload.is_empty()).then_some(payload)
}

/// Result of a plugin execution.
#[derive(Debug)]
pub enum PluginResult {
    /// Continue to the next plugin/phase.
    Continue,
    /// Short-circuit: immediately return this response to the client.
    Reject {
        status_code: u16,
        body: String,
        headers: HashMap<String, String>,
    },
    /// Short-circuit with an arbitrary byte body.
    RejectBinary {
        status_code: u16,
        body: bytes::Bytes,
        headers: HashMap<String, String>,
    },
}

/// Preserve whether a request plugin produced its result or exhausted the
/// client RPC deadline so protocol writers can choose terminal write bias.
pub(crate) enum RequestPluginDeadlineResult {
    Completed(PluginResult),
    DeadlineExceeded,
}

impl RequestPluginDeadlineResult {
    pub(crate) fn into_plugin_result(self, ctx: &mut RequestContext) -> PluginResult {
        match self {
            Self::Completed(result) => result,
            Self::DeadlineExceeded => {
                ctx.mark_gateway_deadline_response_selected();
                grpc_deadline_exceeded_plugin_result()
            }
        }
    }
}

/// Await one request-phase plugin hook under the RPC's absolute deadline while
/// preserving typed deadline provenance for protocol-specific finalizers.
pub(crate) async fn await_request_plugin_deadline_with_provenance<F>(
    deadline: Option<tokio::time::Instant>,
    future: F,
) -> RequestPluginDeadlineResult
where
    F: std::future::Future<Output = PluginResult>,
{
    match await_grpc_deadline(deadline, future).await {
        Ok(result) => RequestPluginDeadlineResult::Completed(result),
        Err(()) => RequestPluginDeadlineResult::DeadlineExceeded,
    }
}

pub(crate) async fn await_grpc_deadline<F, T>(
    deadline: Option<tokio::time::Instant>,
    future: F,
) -> Result<T, ()>
where
    F: std::future::Future<Output = T>,
{
    let Some(deadline) = deadline else {
        return Ok(future.await);
    };
    tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| ())
}

pub(crate) fn grpc_deadline_exceeded_plugin_result() -> PluginResult {
    PluginResult::Reject {
        status_code: 200,
        body: String::new(),
        headers: HashMap::from([
            ("content-type".to_string(), "application/grpc".to_string()),
            (
                "grpc-status".to_string(),
                GATEWAY_DEADLINE_EXCEEDED_STATUS_HEADER.to_string(),
            ),
            (
                "grpc-message".to_string(),
                GATEWAY_DEADLINE_EXCEEDED_MESSAGE.to_string(),
            ),
        ]),
    }
}

/// Action returned by a [`ResponseStreamInspector`]'s per-chunk/end hooks
/// ([`ResponseStreamInspector::on_chunk`] / [`ResponseStreamInspector::on_end`]),
/// generalizing the WebSocket [`Plugin::on_ws_frame`] model to streaming HTTP
/// response bodies (e.g. SSE) that are never buffered.
///
/// Headers are already committed by the time a body streams, so enforcement on
/// a streamed response can only **truncate** — it cannot change the status or
/// retract bytes already sent downstream.
#[derive(Debug, Clone)]
pub enum ResponseStreamAction {
    /// Release these bytes downstream now. An empty `Bytes` means "hold /
    /// accumulate": emit nothing for this chunk because the plugin is buffering
    /// a window it has not yet cleared for release.
    Forward(bytes::Bytes),
    /// Stop the response stream: emit the optional final bytes (e.g. an SSE
    /// terminal error event) and then end the body. Already-sent bytes are
    /// unrecoverable, so this truncates the response in flight.
    Terminate(Option<bytes::Bytes>),
}

/// Semantic stage for a streaming-response inspector.
///
/// Protocol/provider adapters must run before policy inspectors regardless of
/// the plugins' request-side priorities: a guardrail can only evaluate the
/// representation the client will receive after provider-native framing has
/// been normalized. Ordering remains stable inside each stage, so configured
/// plugin priority and config order still control peers with the same role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResponseStreamInspectorStage {
    /// Convert provider/protocol-native bytes into the client-visible format.
    Normalize,
    /// Inspect, enforce, audit, or otherwise consume client-visible bytes.
    Inspect,
}

/// A stateful, per-response inspector for a streaming (non-buffered) response
/// body, created by [`Plugin::response_stream_inspector`]. It **owns** its
/// window / accumulator state, so the same type works both inside the async H3
/// streaming loop and inside the detached task that drives the poll-based H1/H2
/// channel body (which cannot borrow the request `ctx`). The proxy drives it
/// chunk-by-chunk and relays the returned [`ResponseStreamAction`] bytes.
#[async_trait]
pub trait ResponseStreamInspector: Send {
    /// Stage used when composing multiple inspectors. Policy inspectors should
    /// keep the default; protocol/provider adapters override with
    /// [`ResponseStreamInspectorStage::Normalize`].
    fn stage(&self) -> ResponseStreamInspectorStage {
        ResponseStreamInspectorStage::Inspect
    }

    /// Inspect the next decoded chunk of the response body.
    async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction;

    /// Flush / inspect the trailing partial window at end of stream. The default
    /// forwards nothing.
    async fn on_end(&mut self) -> ResponseStreamAction {
        ResponseStreamAction::Forward(bytes::Bytes::new())
    }

    /// Called on inspectors that already saw bytes when a later inspector cuts
    /// the chain. Earlier inspectors can use this to discard pre-cut state that
    /// no longer represents the client-visible stream.
    fn on_downstream_terminated(&mut self) {}

    /// Called immediately before the owning stream task publishes inspector
    /// completion to terminal hooks.
    ///
    /// Inspectors that use a drop-time ownership handoff can publish it here so
    /// [`Plugin::on_response_stream_terminated`] cannot race the inspector's
    /// ordinary field drop. The default is a no-op; this is not a per-chunk
    /// hook.
    fn on_before_drop(&mut self) {}
}

/// Compose the stream inspectors of several plugins into one, so a response with
/// more than one opted-in plugin (e.g. a global and a proxy-scoped
/// `ai_semantic_firewall` with different rules) runs them ALL, not just the
/// first — matching how every other response hook runs for every plugin.
///
/// Normalizers are stably ordered before inspectors; configured plugin order is
/// preserved within each stage. `None` if the list is empty; the single
/// inspector unchanged if there is one; otherwise a
/// [`ChainedResponseStreamInspector`].
pub fn chain_response_stream_inspectors(
    mut inspectors: Vec<Box<dyn ResponseStreamInspector>>,
) -> Option<Box<dyn ResponseStreamInspector>> {
    match inspectors.len() {
        0 => None,
        1 => inspectors.pop(),
        _ => {
            inspectors.sort_by_key(|inspector| inspector.stage());
            Some(Box::new(ChainedResponseStreamInspector { inspectors }))
        }
    }
}

static NEXT_RESPONSE_STREAM_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
static NEXT_RESPONSE_STREAM_HANDOFF_ID: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(1);
const MAX_RESPONSE_STREAM_HANDOFFS_PER_REQUEST: usize = 256;

/// Allocate a process-unique key for one plugin instance's typed response
/// stream handoff.
pub fn allocate_response_stream_handoff_id() -> u64 {
    NEXT_RESPONSE_STREAM_HANDOFF_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

type ResponseStreamHandoffEntries = Vec<(u64, Arc<dyn Any + Send + Sync>)>;

struct ResponseStreamCompletion {
    completed: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
    handoffs: std::sync::Mutex<ResponseStreamHandoffEntries>,
}

impl ResponseStreamCompletion {
    fn new() -> Self {
        Self {
            completed: std::sync::atomic::AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
            handoffs: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn publish<T: Any + Send + Sync>(&self, key: u64, value: Arc<T>) {
        let Ok(mut handoffs) = self.handoffs.lock() else {
            return;
        };
        if handoffs.iter().any(|(existing, _)| *existing == key) {
            return;
        }
        if handoffs.len() >= MAX_RESPONSE_STREAM_HANDOFFS_PER_REQUEST {
            return;
        }
        handoffs.push((key, value));
    }

    fn take<T: Any + Send + Sync>(&self, key: u64) -> Option<Arc<T>> {
        let value = {
            let mut handoffs = self.handoffs.lock().ok()?;
            let index = handoffs.iter().position(|(existing, _)| *existing == key)?;
            handoffs.swap_remove(index).1
        };
        Arc::downcast::<T>(value).ok()
    }

    fn complete(&self) {
        if !self
            .completed
            .swap(true, std::sync::atomic::Ordering::Release)
        {
            self.notify.notify_waiters();
        }
    }

    async fn wait(&self) {
        loop {
            if self.completed.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            let notified = self.notify.notified();
            if self.completed.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

impl std::fmt::Debug for ResponseStreamCompletion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResponseStreamCompletion")
            .field(
                "completed",
                &self.completed.load(std::sync::atomic::Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

/// Cloneable, request-owned terminal-state handoff for response inspectors.
#[derive(Clone)]
pub struct ResponseStreamHandoff {
    completion: Arc<ResponseStreamCompletion>,
}

impl ResponseStreamHandoff {
    pub fn publish<T: Any + Send + Sync>(&self, key: u64, value: Arc<T>) {
        self.completion.publish(key, value);
    }

    pub fn take<T: Any + Send + Sync>(&self, key: u64) -> Option<Arc<T>> {
        self.completion.take(key)
    }
}

struct CompletionNotifyingInspector {
    inner: Box<dyn ResponseStreamInspector>,
    completion: Arc<ResponseStreamCompletion>,
}

#[async_trait]
impl ResponseStreamInspector for CompletionNotifyingInspector {
    fn stage(&self) -> ResponseStreamInspectorStage {
        self.inner.stage()
    }

    async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction {
        self.inner.on_chunk(chunk).await
    }

    async fn on_end(&mut self) -> ResponseStreamAction {
        self.inner.on_end().await
    }

    fn on_downstream_terminated(&mut self) {
        self.inner.on_downstream_terminated();
    }
}

impl Drop for CompletionNotifyingInspector {
    fn drop(&mut self) {
        // Publish inspector-owned terminal handoffs before waking terminal
        // hooks. Rust drops fields only after this Drop implementation returns,
        // which is too late for inspectors whose fallback correlation is
        // intentionally created at task termination.
        self.inner.on_before_drop();
        self.completion.complete();
    }
}

/// Resolve and compose the inspectors for one streaming response.
///
/// The common path is allocation-free: when no plugin opts into response
/// streaming hooks this returns immediately. The correlation id is assigned
/// only on the opted-in path, and is removed again when every plugin factory
/// declines the concrete response, so terminal hooks cannot mistake an
/// uninspected stream for one with pending write-back state.
///
/// This self-contained variant (which runs its own `requires_response_stream_hooks`
/// scan) is now used only by external test crates; every gateway hot path resolves
/// the capability through the `PluginCache` and calls
/// [`create_response_stream_inspector_for_enabled_plugins`] directly.
/// `#[allow(dead_code)]` because the binary target recompiles the source without
/// those test crates, so it sees no caller.
#[doc(hidden)]
#[allow(dead_code)] // used only by tests/, dead code in the bin target
pub fn create_response_stream_inspector(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    response_status: u16,
    content_type: Option<&str>,
) -> Option<Box<dyn ResponseStreamInspector>> {
    if !plugins
        .iter()
        .any(|plugin| plugin.requires_response_stream_hooks())
    {
        return None;
    }

    create_response_stream_inspector_for_enabled_plugins(
        plugins,
        ctx,
        response_status,
        content_type,
    )
}

/// Resolve inspectors after the caller has checked the PluginCache's
/// precomputed response-stream-hooks capability.
///
/// Unlike [`create_response_stream_inspector`], this skips the redundant
/// per-response capability scan. Request hot paths must use this entry point
/// behind `PluginCacheRequestView::requires_response_stream_hooks()`.
pub(crate) fn create_response_stream_inspector_for_enabled_plugins(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    response_status: u16,
    content_type: Option<&str>,
) -> Option<Box<dyn ResponseStreamInspector>> {
    notify_response_stream_selected(plugins, ctx, response_status, content_type);

    ctx.response_stream_id =
        Some(NEXT_RESPONSE_STREAM_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
    let completion = Arc::new(ResponseStreamCompletion::new());
    // Factories receive `&RequestContext`, so publish the request-owned handoff
    // before invoking them. It is cleared again below when every factory
    // declines the concrete response.
    ctx.response_stream_completion = Some(Arc::clone(&completion));
    let inspectors: Vec<_> = plugins
        .iter()
        .filter_map(|plugin| plugin.response_stream_inspector(ctx, response_status, content_type))
        .collect();
    let inspector = chain_response_stream_inspectors(inspectors);
    if let Some(inspector) = inspector {
        Some(Box::new(CompletionNotifyingInspector {
            inner: inspector,
            completion,
        }))
    } else {
        ctx.response_stream_id = None;
        ctx.response_stream_completion = None;
        None
    }
}

/// Notify opted-in plugins that the final response will use a streaming body,
/// even when the concrete transport cannot attach a chunk inspector.
#[doc(hidden)]
pub fn notify_response_stream_selected(
    plugins: &[Arc<dyn Plugin>],
    ctx: &RequestContext,
    response_status: u16,
    content_type: Option<&str>,
) {
    for plugin in plugins
        .iter()
        .filter(|plugin| plugin.requires_response_stream_hooks())
    {
        plugin.on_response_stream_selected(ctx, response_status, content_type);
    }
}

pub(crate) async fn wait_for_response_stream_inspector(ctx: &RequestContext) {
    if let Some(completion) = &ctx.response_stream_completion {
        completion.wait().await;
    }
}

pub(crate) fn clear_response_stream_inspector_state(ctx: &mut RequestContext) {
    ctx.response_stream_id = None;
    ctx.response_stream_completion = None;
}

/// Run buffered provider/protocol normalizers before response-body policy
/// inspection. Returns whether any plugin replaced the bytes.
///
/// This is shared by the H1/H2 and all buffered H3 bridge/native paths so a
/// frontend protocol cannot change which representation guardrails inspect.
pub async fn normalize_response_body_for_inspection(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    response_status: u16,
    response_headers: &mut HashMap<String, String>,
    response_body: &mut Vec<u8>,
    initial_response_header_policy_plugins: &[Arc<dyn Plugin>],
) -> bool {
    // Seed provenance before the rewrite gate: a status that forbids body
    // rewrites can still be replaced by the request's gRPC deadline, and an
    // unseeded provenance strips every header from that replacement.
    ctx.ensure_buffered_deadline_response_header_provenance(response_headers);
    if !response_body_rewrite_allowed(response_status) {
        return false;
    }
    let content_type = response_headers.get("content-type").cloned();
    let mut normalized = false;
    for plugin in plugins {
        let deadline = ctx.grpc_deadline_at();
        let body = match await_grpc_deadline(
            deadline,
            plugin.normalize_response_body_with_context(
                ctx,
                response_status,
                response_body,
                content_type.as_deref(),
                response_headers,
            ),
        )
        .await
        {
            Ok(body) => body,
            Err(()) => {
                let owned_grpc_web_response_content_type =
                    crate::plugins::grpc_web::retained_response_content_type(ctx)
                        .map(str::to_owned);
                let grpc_web_response_content_type =
                    owned_grpc_web_response_content_type.as_deref();
                crate::proxy::replace_buffered_grpc_response_with_deadline(
                    ctx,
                    grpc_web_response_content_type,
                    response_headers,
                    response_body,
                    initial_response_header_policy_plugins,
                );
                normalized = true;
                break;
            }
        };
        if let Some(body) = body {
            response_headers.insert("content-length".to_string(), body.len().to_string());
            *response_body = body;
            normalized = true;
        }
        ctx.record_deadline_response_header_mutations(response_headers);
    }
    normalized
}

/// Pipes each chunk through a chain of [`ResponseStreamInspector`]s: inspector
/// *i*'s `Forward` output is the input to inspector *i+1*, so each plugin sees
/// the (frame-aligned) bytes its predecessors released. Policy-inspector
/// `Terminate` actions short-circuit and cut the stream. A normalizer's terminal
/// payload is different: it is the final client-visible window, so it is passed
/// through every downstream inspector and their end-of-stream flushes before
/// the chain returns `Terminate`. Same-call clean releases from a downstream
/// policy cut are dropped, preserving the single-action contract.
struct ChainedResponseStreamInspector {
    inspectors: Vec<Box<dyn ResponseStreamInspector>>,
}

#[async_trait]
impl ResponseStreamInspector for ChainedResponseStreamInspector {
    async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction {
        let mut buf = bytes::Bytes::copy_from_slice(chunk);
        for index in 0..self.inspectors.len() {
            if buf.is_empty() {
                // An upstream inspector is holding this window; nothing yet for
                // the rest of the chain to see.
                return ResponseStreamAction::Forward(bytes::Bytes::new());
            }
            match self.inspectors[index].on_chunk(&buf).await {
                ResponseStreamAction::Forward(out) => buf = out,
                ResponseStreamAction::Terminate(final_bytes)
                    if self.inspectors[index].stage()
                        == ResponseStreamInspectorStage::Normalize =>
                {
                    return self
                        .finish_after_normalizer_termination(index, final_bytes)
                        .await;
                }
                terminate @ ResponseStreamAction::Terminate(_) => {
                    self.notify_prior_downstream_terminated(index);
                    return terminate;
                }
            }
        }
        ResponseStreamAction::Forward(buf)
    }

    async fn on_end(&mut self) -> ResponseStreamAction {
        // Flush each inspector in order; bytes flushed by inspector *i* are fed to
        // inspector *i+1* as a final chunk before *i+1* is itself flushed.
        let mut carry = bytes::Bytes::new();
        for index in 0..self.inspectors.len() {
            let mut released = bytes::BytesMut::new();
            if !carry.is_empty() {
                match self.inspectors[index].on_chunk(&carry).await {
                    ResponseStreamAction::Forward(out) => released.extend_from_slice(&out),
                    ResponseStreamAction::Terminate(final_bytes)
                        if self.inspectors[index].stage()
                            == ResponseStreamInspectorStage::Normalize =>
                    {
                        return self
                            .finish_after_normalizer_termination(index, final_bytes)
                            .await;
                    }
                    terminate @ ResponseStreamAction::Terminate(_) => {
                        self.notify_prior_downstream_terminated(index);
                        return terminate;
                    }
                }
            }
            match self.inspectors[index].on_end().await {
                ResponseStreamAction::Forward(out) => released.extend_from_slice(&out),
                ResponseStreamAction::Terminate(final_bytes)
                    if self.inspectors[index].stage()
                        == ResponseStreamInspectorStage::Normalize =>
                {
                    if let Some(final_bytes) = final_bytes {
                        released.extend_from_slice(&final_bytes);
                    }
                    return self
                        .finish_after_normalizer_termination(
                            index,
                            (!released.is_empty()).then(|| released.freeze()),
                        )
                        .await;
                }
                terminate @ ResponseStreamAction::Terminate(_) => {
                    self.notify_prior_downstream_terminated(index);
                    return terminate;
                }
            }
            carry = released.freeze();
        }
        ResponseStreamAction::Forward(carry)
    }

    fn on_before_drop(&mut self) {
        for inspector in &mut self.inspectors {
            inspector.on_before_drop();
        }
    }
}

impl ChainedResponseStreamInspector {
    async fn finish_after_normalizer_termination(
        &mut self,
        normalizer_index: usize,
        final_bytes: Option<bytes::Bytes>,
    ) -> ResponseStreamAction {
        self.notify_prior_downstream_terminated(normalizer_index);
        let mut carry = final_bytes.unwrap_or_default();
        for index in normalizer_index + 1..self.inspectors.len() {
            let stage = self.inspectors[index].stage();
            let mut released = bytes::BytesMut::new();
            if !carry.is_empty() {
                match self.inspectors[index].on_chunk(&carry).await {
                    ResponseStreamAction::Forward(out) => released.extend_from_slice(&out),
                    ResponseStreamAction::Terminate(final_bytes)
                        if stage == ResponseStreamInspectorStage::Normalize =>
                    {
                        self.notify_prior_downstream_terminated(index);
                        carry = final_bytes.unwrap_or_default();
                        continue;
                    }
                    terminate @ ResponseStreamAction::Terminate(_) => {
                        self.notify_prior_downstream_terminated(index);
                        return terminate;
                    }
                }
            }
            match self.inspectors[index].on_end().await {
                ResponseStreamAction::Forward(out) => released.extend_from_slice(&out),
                ResponseStreamAction::Terminate(final_bytes)
                    if stage == ResponseStreamInspectorStage::Normalize =>
                {
                    self.notify_prior_downstream_terminated(index);
                    if let Some(final_bytes) = final_bytes {
                        released.extend_from_slice(&final_bytes);
                    }
                    carry = released.freeze();
                    continue;
                }
                terminate @ ResponseStreamAction::Terminate(_) => {
                    self.notify_prior_downstream_terminated(index);
                    return terminate;
                }
            }
            carry = released.freeze();
        }
        if carry.is_empty() {
            ResponseStreamAction::Terminate(None)
        } else {
            ResponseStreamAction::Terminate(Some(carry))
        }
    }

    fn notify_prior_downstream_terminated(&mut self, index: usize) {
        for inspector in &mut self.inspectors[..index] {
            inspector.on_downstream_terminated();
        }
    }
}

#[cfg(test)]
mod chained_inspector_tests {
    //! Focused tests for [`ChainedResponseStreamInspector`]'s threading — the
    //! struct is private, so these stay inline. The non-trivial part is `on_end`,
    //! where one inspector's flushed bytes must pass through the next inspector's
    //! `on_chunk` AND `on_end` before being released.
    use super::*;

    /// Passes chunks through unchanged; emits `tag` once at end-of-stream.
    struct TagAtEnd {
        tag: &'static str,
    }
    #[async_trait]
    impl ResponseStreamInspector for TagAtEnd {
        async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction {
            ResponseStreamAction::Forward(bytes::Bytes::copy_from_slice(chunk))
        }
        async fn on_end(&mut self) -> ResponseStreamAction {
            ResponseStreamAction::Forward(bytes::Bytes::copy_from_slice(self.tag.as_bytes()))
        }
    }

    /// Cuts immediately on the first chunk.
    struct CutNow;
    #[async_trait]
    impl ResponseStreamInspector for CutNow {
        async fn on_chunk(&mut self, _chunk: &[u8]) -> ResponseStreamAction {
            ResponseStreamAction::Terminate(Some(bytes::Bytes::from_static(b"CUT")))
        }
    }

    /// Emits a final normalized window and asks the driver to stop upstream.
    struct NormalizeAndCut;
    #[async_trait]
    impl ResponseStreamInspector for NormalizeAndCut {
        fn stage(&self) -> ResponseStreamInspectorStage {
            ResponseStreamInspectorStage::Normalize
        }

        async fn on_chunk(&mut self, _chunk: &[u8]) -> ResponseStreamAction {
            ResponseStreamAction::Terminate(Some(bytes::Bytes::from_static(b"FINAL")))
        }
    }

    /// Holds everything (never releases) — Forward(empty).
    struct HoldAll;
    #[async_trait]
    impl ResponseStreamInspector for HoldAll {
        async fn on_chunk(&mut self, _chunk: &[u8]) -> ResponseStreamAction {
            ResponseStreamAction::Forward(bytes::Bytes::new())
        }
    }

    fn forwarded(action: ResponseStreamAction) -> bytes::Bytes {
        match action {
            ResponseStreamAction::Forward(b) => b,
            ResponseStreamAction::Terminate(_) => panic!("expected Forward, got Terminate"),
        }
    }

    #[tokio::test]
    async fn single_inspector_is_returned_unwrapped() {
        let chain = chain_response_stream_inspectors(vec![Box::new(TagAtEnd { tag: "A" })]);
        assert!(chain.is_some());
        // len 0 -> None
        assert!(chain_response_stream_inspectors(vec![]).is_none());
    }

    #[tokio::test]
    async fn on_chunk_threads_through_all_and_on_end_carries() {
        let mut chain = chain_response_stream_inspectors(vec![
            Box::new(TagAtEnd { tag: "A" }),
            Box::new(TagAtEnd { tag: "B" }),
        ])
        .expect("two inspectors chain");
        // A chunk passes through both unchanged.
        assert_eq!(&forwarded(chain.on_chunk(b"hi").await)[..], b"hi");
        // on_end: A flushes "A" -> fed through B.on_chunk ("A") -> then B flushes
        // "B"; result is "A" ++ "B".
        assert_eq!(&forwarded(chain.on_end().await)[..], b"AB");
    }

    #[tokio::test]
    async fn first_terminate_short_circuits() {
        let mut chain = chain_response_stream_inspectors(vec![
            Box::new(CutNow),
            Box::new(TagAtEnd { tag: "B" }),
        ])
        .expect("chain");
        assert!(matches!(
            chain.on_chunk(b"x").await,
            ResponseStreamAction::Terminate(Some(_))
        ));
    }

    #[tokio::test]
    async fn normalizer_terminal_window_reaches_downstream_inspector_and_flush() {
        let mut chain = chain_response_stream_inspectors(vec![
            Box::new(TagAtEnd { tag: "B" }),
            Box::new(NormalizeAndCut),
        ])
        .expect("chain");
        match chain.on_chunk(b"provider-native").await {
            ResponseStreamAction::Terminate(Some(bytes)) => {
                assert_eq!(bytes.as_ref(), b"FINALB");
            }
            other => panic!("expected terminal downstream output, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn upstream_hold_stops_the_chain() {
        let mut chain = chain_response_stream_inspectors(vec![
            Box::new(HoldAll),
            Box::new(TagAtEnd { tag: "B" }),
        ])
        .expect("chain");
        // First inspector holds → nothing reaches the second this chunk.
        assert!(forwarded(chain.on_chunk(b"x").await).is_empty());
    }
}

/// Mirror response metadata from the `request_mirror` plugin's spawned task.
///
/// Communicated via `tokio::sync::watch` channel from the spawned mirror task
/// to the proxy handler, which builds a second `TransactionSummary` (with
/// `mirror: true`) and logs it through the normal plugin pipeline. When several
/// `request_mirror` instances dispatch on one request, each produces an
/// independently attributable record (plugin config id + query-stripped
/// destination URL) rather than overwriting a singleton slot.
#[derive(Debug, Clone)]
pub struct MirrorResponseMeta {
    /// Stable plugin-config resource id of the originating `request_mirror`
    /// instance when known (never a secret). `None` for synthetic/test
    /// construction without a config id.
    pub mirror_plugin_id: Option<String>,
    /// URL the mirror request was sent to (query string stripped so credentials
    /// in the original request query cannot leak into logs).
    pub mirror_target_url: String,
    /// HTTP status code from the mirror target. `None` when the request failed
    /// before a response was received or was dropped/cancelled (DNS, connect,
    /// timeout, task, and concurrency errors).
    pub mirror_response_status_code: Option<u16>,
    /// Response body size in bytes observed after a bounded drain of the
    /// mirror response (or the truncated count when the drain cap fired).
    pub mirror_response_size_bytes: Option<u64>,
    /// Advertised `Content-Length` from the mirror response when present.
    /// Recorded independently of [`Self::mirror_response_size_bytes`] so
    /// operators can compare advertised vs observed after bounded drain.
    pub mirror_response_advertised_size_bytes: Option<u64>,
    /// Wall-clock latency of the mirror request in milliseconds.
    pub mirror_latency_ms: f64,
    /// Human-readable error message when the mirror request failed.
    pub mirror_error: Option<String>,
}

/// Which direction of a bidirectional stream experienced a failure first.
///
/// Used by TCP/UDP/WebSocket disconnect logging so operators can tell whether
/// the client or the backend initiated the disconnect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Error originated on the client→backend half of the stream.
    ClientToBackend,
    /// Error originated on the backend→client half of the stream.
    BackendToClient,
    /// Direction could not be determined (both halves failed simultaneously,
    /// or the error occurred outside the copy loop).
    Unknown,
}

/// Cause of a stream (TCP/UDP) disconnect.
///
/// Disambiguates idle-timeout expiry from read/write errors so log consumers
/// don't have to rely on `error_class: None` as an implicit timeout signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisconnectCause {
    /// Session exceeded the configured idle timeout without traffic.
    IdleTimeout,
    /// Frontend (client-side) recv/read returned an error.
    RecvError,
    /// Backend recv/read returned an error (e.g., backend closed the socket).
    BackendError,
    /// Clean shutdown initiated by either peer (e.g., FIN, graceful close frame).
    GracefulShutdown,
}

/// Shared latency sentinel for unknown or not-applicable observations.
///
/// Used for:
/// * no-backend TTFB / backend total on reject paths
/// * streaming `latency_backend_total_ms` when concurrent backend-body and
///   client-delivery lifetime cannot be separated
/// * streaming `latency_gateway_processing_ms` /
///   `latency_gateway_overhead_ms` when those fields cannot be derived
///   without inventing a backend duration (never substitute TTFB)
///
/// StatsD timers and Prometheus histograms omit samples `< 0`. JSON sinks
/// still emit the sentinel so consumers can distinguish "unknown" from
/// "zero".
pub const LATENCY_UNKNOWN_MS: f64 = -1.0;

/// Transaction summary for logging plugins.
///
/// Implements [`Default`] so call sites that build partial summaries
/// (early-return error paths, rejected requests, etc.) can use struct
/// update syntax — `..TransactionSummary::default()` — instead of
/// hardcoding every field. Future additions to this struct get an
/// automatic default value at all update-syntax call sites; old call
/// sites that enumerate every field still require a manual edit, which
/// is also fine because it flags the deliberate choice.
///
/// Prefer the update syntax when adding new log sites:
/// ```ignore
/// TransactionSummary {
///     namespace: proxy.namespace.clone(),
///     timestamp_received: ctx.timestamp_received.to_rfc3339(),
///     client_ip: ctx.client_ip.clone(),
///     http_method: method,
///     request_path: path,
///     response_status_code: status,
///     error_class: Some(class),
///     ..TransactionSummary::default()
/// }
/// ```
#[derive(Debug, Clone, Default)]
pub struct TransactionSummary {
    /// Namespace of the matched proxy.
    pub namespace: String,
    pub timestamp_received: String,
    pub client_ip: String,
    pub consumer_username: Option<String>,
    pub auth_method: Option<&'static str>,
    pub http_method: String,
    pub request_path: String,
    /// ID of the proxy that matched this request, or `None` when the request
    /// was rejected before routing (no proxy matched the host/path). Same
    /// JSON key as `StreamTransactionSummary.proxy_id` so log consumers see
    /// a single `proxy_id` field across HTTP, gRPC, WebSocket, TCP, UDP, and
    /// DTLS transactions.
    pub proxy_id: Option<String>,
    /// Human-friendly proxy name; same JSON key as
    /// `StreamTransactionSummary.proxy_name`.
    pub proxy_name: Option<String>,
    /// Backend the request was forwarded to. For HTTP this is the full URL
    /// (`scheme://host:port/path`); `None` when the request was rejected
    /// before backend selection. Same JSON key as
    /// `StreamTransactionSummary.backend_target` (which is always set and
    /// uses `host:port` form, since stream proxies have no path).
    pub backend_target: Option<String>,
    /// The DNS-resolved IP address of the backend that was connected to.
    pub backend_resolved_ip: Option<String>,
    pub response_status_code: u16,
    pub latency_total_ms: f64,
    /// Total time excluding attributed backend communication.
    ///
    /// * **Buffered / known backend total**: `total - backend_total`.
    /// * **Rejected (no backend)**: equals `latency_total_ms`.
    /// * **Streaming with unknown backend total**: [`LATENCY_UNKNOWN_MS`].
    ///   Concurrent backend-body and client-delivery lifetime must not be
    ///   reported as gateway processing by substituting TTFB.
    pub latency_gateway_processing_ms: f64,
    pub latency_backend_ttfb_ms: f64,
    /// Total backend time from connection start to the final response frame.
    ///
    /// Semantics by response type:
    /// * **Buffered responses**: exact — set synchronously when the body has
    ///   been fully received, before the summary is logged.
    /// * **Streaming responses**: [`LATENCY_UNKNOWN_MS`]. Deferred logging
    ///   refreshes `latency_total_ms` at body termination but does not invent
    ///   a backend total from TTFB; concurrent backend-body production and
    ///   client delivery cannot be separated on the default streaming path.
    ///   Prefer `latency_backend_ttfb_ms` for streaming alerting when a
    ///   guaranteed non-sentinel backend observation is required.
    pub latency_backend_total_ms: f64,
    /// Wall-clock time spent executing all plugin hooks (on_request_received
    /// through after_proxy/on_response_body/transform_response_body/
    /// on_final_response_body).
    /// Includes any external I/O that plugins performed synchronously.
    pub latency_plugin_execution_ms: f64,
    /// Subset of plugin execution time spent on external HTTP calls
    /// (via `PluginHttpClient::execute_tracked`). 0.0 when no plugin
    /// makes tracked external calls during the request lifecycle.
    pub latency_plugin_external_io_ms: f64,
    /// Pure gateway overhead: routing, header parsing, URL building,
    /// connection pool checkout, response framing, etc.
    ///
    /// * **Buffered / known backend total**:
    ///   `total - backend_total - plugin_execution`.
    /// * **Rejected (no backend call)**: `total - plugin_execution`.
    /// * **Streaming with unknown backend total**: [`LATENCY_UNKNOWN_MS`] —
    ///   never derived by treating TTFB as full backend duration.
    pub latency_gateway_overhead_ms: f64,
    pub request_user_agent: Option<String>,
    /// True when the response body was streamed (not buffered).
    /// When true and `latency_backend_total_ms` is [`LATENCY_UNKNOWN_MS`],
    /// gateway processing/overhead are also unknown (see those fields).
    pub response_streamed: bool,
    /// True when the client disconnected before receiving the full response.
    ///
    /// Semantics by response type:
    /// * **Streaming responses**: accurate — set by the deferred-logging path
    ///   when the response body wrapper (`ProxyBody`) observes a disconnect
    ///   error frame, or when the wrapper is dropped before reaching
    ///   end-of-stream (see `deferred_log::DeferredTransactionLogger`).
    /// * **Buffered responses**: best-effort. Hyper only signals client
    ///   send failures at the connection-error handler, which fires after
    ///   the handler function has already constructed and emitted the
    ///   summary. Consumers should treat `false` on a buffered response
    ///   as "not known to have disconnected," not as a positive assertion.
    pub client_disconnected: bool,
    /// Human-friendly classification of the error when the gateway itself
    /// failed to communicate with the backend. `None` for successful requests
    /// and normal HTTP error responses from the backend.
    pub error_class: Option<crate::retry::ErrorClass>,
    /// Classification of an error that occurred while streaming the response
    /// body to the client (e.g., client RST after headers were sent). `None`
    /// when the body streamed successfully or when no streaming occurred.
    ///
    /// Distinct from `error_class`, which covers errors reaching the backend.
    /// Populated by the deferred-logging path when the response body wrapper
    /// returns an error frame or is dropped before completion.
    pub body_error_class: Option<crate::retry::ErrorClass>,
    /// True when the response body finished streaming all frames successfully.
    /// False when streaming was interrupted (client disconnect, backend RST,
    /// body size limit exceeded) or when no streaming occurred.
    pub body_completed: bool,
    /// Bytes of the request body relayed from the client to the backend
    /// (gateway-perspective: bytes it sent onward on the client's behalf).
    /// Same JSON key as `StreamTransactionSummary.bytes_sent`.
    ///
    /// Accuracy by request type:
    /// * **Buffered requests** (plugins required the body, or retries were
    ///   configured): exact — populated from the collected body length after
    ///   `Incoming::collect().await` (optionally via `SizeLimitedIncoming::bytes_seen()`
    ///   when a size limit is in force).
    /// * **Streaming requests** (body forwarded frame-by-frame without
    ///   collection): exact — populated via `CountingIncoming`, which shares
    ///   an `Arc<AtomicU64>` between the forwarded body and the summary
    ///   builder so the final byte count is visible once hyper has consumed
    ///   the body.
    /// * **Empty / GET / HEAD / size-zero requests**: zero (omitted by the
    ///   transaction summary serializer).
    pub bytes_sent: u64,
    /// Bytes of the response body relayed from the backend to the client
    /// (gateway-perspective: bytes it received and forwarded back). Unified
    /// streaming + buffered counter. Same JSON key as
    /// `StreamTransactionSummary.bytes_received`.
    ///
    /// Population sites:
    /// * **Buffered responses** (`ResponseBody::Buffered`, plugin rejects,
    ///   gRPC trailers-only error, gRPC buffered-success, H3 buffered path,
    ///   WS error path): populated synchronously from the final `Bytes::len()`
    ///   before the summary is logged.
    /// * **Streaming responses**: populated at deferred-log fire time from
    ///   the body counter. On a client disconnect mid-stream this reflects
    ///   bytes actually flushed before the disconnect.
    pub bytes_received: u64,
    /// True when this summary represents a mirror (shadow) request, not the
    /// actual client-facing proxy traffic. Logged as a separate entry with the
    /// same schema so existing log queries and dashboards work without changes.
    pub mirror: bool,
    /// Plugin-injected metadata. Sensitive keys (authorization, cookie,
    /// credential/session tokens, secrets — see
    /// `plugins::utils::metadata_redaction::DEFAULT_SENSITIVE_METADATA_KEYS`
    /// plus operator extras from `FERRUM_LOG_REDACT_METADATA_KEYS`) are
    /// replaced with `[REDACTED]` at serialize time. The in-memory value is
    /// untouched so other plugin phases can still read the original.
    pub metadata: HashMap<String, String>,
    /// Built-in AI usage provenance for Prometheus. This is intentionally not
    /// serialized into transaction logs; the operator-visible usage metadata
    /// remains in `metadata` while trust stays typed and private to the request
    /// pipeline.
    #[doc(hidden)]
    pub ai_usage_export: Option<AiUsageExport>,
    /// Ownership generation captured at HTTP/gRPC/WebSocket admission. Not
    /// serialized; used by `proxy_alerts` to reject samples from a prior
    /// delete→recreate incarnation of the same proxy ID.
    #[doc(hidden)]
    pub proxy_lifecycle_generation: Option<u64>,
}

impl Serialize for TransactionSummary {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use crate::plugins::utils::metadata_redaction::RedactedMetadata;

        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("namespace", &self.namespace)?;
        map.serialize_entry("timestamp_received", &self.timestamp_received)?;
        map.serialize_entry("client_ip", &self.client_ip)?;
        map.serialize_entry("consumer_username", &self.consumer_username)?;
        if let Some(auth_method) = self.auth_method {
            map.serialize_entry("auth_method", auth_method)?;
        }
        map.serialize_entry("http_method", &self.http_method)?;
        map.serialize_entry("request_path", &self.request_path)?;
        if let Some(proxy_id) = &self.proxy_id {
            map.serialize_entry("proxy_id", proxy_id)?;
        }
        if let Some(proxy_name) = &self.proxy_name {
            map.serialize_entry("proxy_name", proxy_name)?;
        }
        map.serialize_entry("backend_target", &self.backend_target)?;
        if let Some(backend_resolved_ip) = &self.backend_resolved_ip {
            map.serialize_entry("backend_resolved_ip", backend_resolved_ip)?;
        }
        map.serialize_entry("response_status_code", &self.response_status_code)?;
        if let Some(grpc_status) = self.grpc_status() {
            map.serialize_entry("grpc_status", &grpc_status)?;
        }
        map.serialize_entry("latency_total_ms", &self.latency_total_ms)?;
        map.serialize_entry(
            "latency_gateway_processing_ms",
            &self.latency_gateway_processing_ms,
        )?;
        map.serialize_entry("latency_backend_ttfb_ms", &self.latency_backend_ttfb_ms)?;
        map.serialize_entry("latency_backend_total_ms", &self.latency_backend_total_ms)?;
        map.serialize_entry(
            "latency_plugin_execution_ms",
            &self.latency_plugin_execution_ms,
        )?;
        map.serialize_entry(
            "latency_plugin_external_io_ms",
            &self.latency_plugin_external_io_ms,
        )?;
        map.serialize_entry(
            "latency_gateway_overhead_ms",
            &self.latency_gateway_overhead_ms,
        )?;
        map.serialize_entry("request_user_agent", &self.request_user_agent)?;
        if self.response_streamed {
            map.serialize_entry("response_streamed", &true)?;
        }
        if self.client_disconnected {
            map.serialize_entry("client_disconnected", &true)?;
        }
        if let Some(error_class) = self.error_class {
            map.serialize_entry("error_class", &error_class)?;
        }
        if let Some(body_error_class) = self.body_error_class {
            map.serialize_entry("body_error_class", &body_error_class)?;
        }
        if self.body_completed {
            map.serialize_entry("body_completed", &true)?;
        }
        if self.bytes_sent != 0 {
            map.serialize_entry("bytes_sent", &self.bytes_sent)?;
        }
        if self.bytes_received != 0 {
            map.serialize_entry("bytes_received", &self.bytes_received)?;
        }
        if self.mirror {
            map.serialize_entry("mirror", &true)?;
        }
        map.serialize_entry("metadata", &RedactedMetadata(&self.metadata))?;
        map.end()
    }
}

impl TransactionSummary {
    /// Authoritative final gRPC application status, kept separate from the
    /// HTTP transport status. Missing or malformed terminal status on a known
    /// gRPC transaction remains a failure: missing is UNKNOWN (2), while
    /// malformed input uses the existing `u32::MAX` invalid-status sentinel.
    /// Translated gRPC-Web requests are stamped as `request_protocol="grpc"`
    /// by the H1/H2 and H3 dispatchers; no runtime path currently produces
    /// `request_protocol="grpc-web"` (mesh uses `mesh.request_protocol`).
    pub fn grpc_status(&self) -> Option<u32> {
        match self.metadata.get("grpc_status") {
            Some(status) => Some(crate::proxy::grpc_proxy::parse_grpc_status_value(status)),
            None if self
                .metadata
                .get("request_protocol")
                .is_some_and(|protocol| protocol == "grpc") =>
            {
                Some(crate::proxy::grpc_proxy::grpc_status::UNKNOWN)
            }
            None => None,
        }
    }

    /// One authoritative terminal-failure predicate for transaction loggers.
    ///
    /// HTTP status filters remain independent: an upstream HTTP 5xx without a
    /// gateway/terminal failure is not implicitly an `errors_only` match.
    pub fn is_terminal_failure(&self) -> bool {
        self.error_class.is_some()
            || self.body_error_class.is_some()
            || self.client_disconnected
            || (self.response_streamed && !self.body_completed)
            || self.metadata.contains_key("rejection_phase")
            || self.metadata.contains_key("mirror_error")
            || self.grpc_status().is_some_and(|status| status != 0)
    }

    /// Derive gateway processing and overhead from terminal latency observations.
    ///
    /// Terminal streaming contract:
    /// * `latency_total_ms` — wall-clock request receipt → body terminal
    /// * `latency_backend_ttfb_ms` — preserved first-byte observation
    /// * `latency_backend_total_ms` — known (`>= 0`) or [`LATENCY_UNKNOWN_MS`]
    /// * plugin execution / external I/O — preserved pre-stream observations
    /// * gateway fields — derived only when backend total is known; otherwise
    ///   [`LATENCY_UNKNOWN_MS`] so streamed body lifetime is never labeled as
    ///   pure gateway work by substituting TTFB
    ///
    /// Reject paths (`response_streamed == false`, backend total unknown)
    /// keep the historical attribution: all non-plugin time is gateway work.
    pub fn derive_gateway_latencies(
        total_ms: f64,
        backend_total_ms: f64,
        plugin_execution_ms: f64,
        response_streamed: bool,
    ) -> (f64, f64) {
        if response_streamed && backend_total_ms < 0.0 {
            return (LATENCY_UNKNOWN_MS, LATENCY_UNKNOWN_MS);
        }
        if backend_total_ms < 0.0 {
            let processing = total_ms.max(0.0);
            let overhead = (total_ms - plugin_execution_ms).max(0.0);
            return (processing, overhead);
        }
        let processing = (total_ms - backend_total_ms).max(0.0);
        let overhead = (total_ms - backend_total_ms - plugin_execution_ms).max(0.0);
        (processing, overhead)
    }

    /// Apply [`Self::derive_gateway_latencies`] onto this summary using its
    /// current total / backend-total / plugin-execution / streamed flags.
    pub fn refresh_gateway_latencies(&mut self) {
        let (processing, overhead) = Self::derive_gateway_latencies(
            self.latency_total_ms,
            self.latency_backend_total_ms,
            self.latency_plugin_execution_ms,
            self.response_streamed,
        );
        self.latency_gateway_processing_ms = processing;
        self.latency_gateway_overhead_ms = overhead;
    }

    /// Build a mirror transaction summary from this summary and a mirror result.
    ///
    /// Clones the original request context fields (client_ip, method, path, proxy,
    /// consumer) and overlays the mirror response metadata (status, latency, target
    /// URL). Response size and error details go into metadata since there are no
    /// dedicated fields for them in the standard schema.
    pub fn as_mirror_entry(&self, result: MirrorResponseMeta) -> Self {
        let mut mirror = self.clone();
        mirror.mirror = true;
        mirror.backend_target = Some(result.mirror_target_url);
        mirror.response_status_code = result.mirror_response_status_code.unwrap_or(0);
        mirror.backend_resolved_ip = None;
        mirror.latency_total_ms = result.mirror_latency_ms;
        mirror.latency_backend_ttfb_ms = result.mirror_latency_ms;
        mirror.latency_backend_total_ms = result.mirror_latency_ms;
        mirror.latency_gateway_processing_ms = 0.0;
        mirror.latency_plugin_execution_ms = 0.0;
        mirror.latency_plugin_external_io_ms = 0.0;
        mirror.latency_gateway_overhead_ms = 0.0;
        mirror.response_streamed = false;
        mirror.client_disconnected = false;
        mirror.error_class = None;
        mirror.body_error_class = None;
        mirror.body_completed = false;
        // The cloned metadata describes the primary response. Clear every
        // response-only key that participates in terminal classification or
        // mirror serialization before applying the mirror task's own outcome.
        // In particular, retaining request_protocol="grpc" without a mirror
        // grpc-status would synthesize UNKNOWN, while retaining grpc_status
        // would report and filter on the primary backend's status.
        for key in [
            "request_protocol",
            "grpc_status",
            "grpc_message",
            "rejection_phase",
            "mirror_error",
            "mirror_plugin_id",
            "response_size_bytes",
            "mirror_response_advertised_size_bytes",
        ] {
            mirror.metadata.remove(key);
        }
        // Mirror traffic is fire-and-forget from the client's perspective — body
        // byte counters from the primary transaction are not meaningful on the
        // mirror summary. Mirror response size goes into metadata instead.
        mirror.bytes_sent = 0;
        mirror.bytes_received = 0;
        if let Some(size) = result.mirror_response_size_bytes {
            mirror
                .metadata
                .insert("response_size_bytes".to_string(), size.to_string());
        }
        if let Some(advertised) = result.mirror_response_advertised_size_bytes {
            mirror.metadata.insert(
                "mirror_response_advertised_size_bytes".to_string(),
                advertised.to_string(),
            );
        }
        if let Some(err) = result.mirror_error {
            mirror.metadata.insert("mirror_error".to_string(), err);
        }
        if let Some(plugin_id) = result.mirror_plugin_id {
            mirror
                .metadata
                .insert("mirror_plugin_id".to_string(), plugin_id);
        }
        mirror
    }
}

/// Log a transaction summary through all logging plugins, then log one mirror
/// summary per dispatched `request_mirror` instance.
///
/// Mirror results are collected after the main summary is logged, giving each
/// spawned mirror task maximum time to complete. Each mirror entry uses the
/// same `TransactionSummary` schema with `mirror: true` so existing log
/// pipelines work without changes. Mixed completion order and mixed
/// success/failure across instances do not drop earlier results.
///
/// Some proxy paths call this with an empty plugin slice so runtime transaction
/// metrics still see no-plugin error and streaming-disconnect outcomes.
pub async fn log_with_mirror(
    plugins: &[Arc<dyn Plugin>],
    summary: &TransactionSummary,
    ctx: &RequestContext,
) {
    let precompute_mesh_key = plugins
        .iter()
        .any(|plugin| matches!(plugin.name(), "workload_metrics" | "prometheus_metrics"));
    let mesh_key = if precompute_mesh_key {
        crate::plugins::mesh::prometheus_helpers::mesh_request_key(summary)
    } else {
        None
    };
    for plugin in plugins {
        // Transaction logging is gateway cleanup after the client-visible
        // outcome is final. A client RPC deadline must bound request handling,
        // but it must not suppress the audit/transaction record for the
        // deadline outcome itself.
        plugin.log_with_mesh_key(summary, mesh_key.as_ref()).await;
    }
    crate::runtime_metrics::global_ref().record_transaction(summary);

    // Mirror completion and mirror-summary logging stay detached from the
    // primary transaction, but the structured delivery lifecycle owns each
    // collector through shutdown. Buffered response paths call
    // `log_with_mirror` before handing the response to hyper, so awaiting
    // mirror receivers here would make a stalled shadow target client-visible.
    // Do not clone the summary or plugin list when this request was not mirrored.
    if ctx.mirror_result_rxs.is_empty() {
        return;
    }
    let plugins: Arc<[Arc<dyn Plugin>]> = Arc::from(plugins.to_vec());
    // Register one detached collector per instance before returning so mixed
    // completion order cannot drop an earlier destination's summary.
    for mirror_result_rx in ctx.mirror_result_rxs.iter().cloned() {
        let summary = summary.clone();
        let plugins = Arc::clone(&plugins);
        let _ = crate::observability_delivery::spawn_mirror(async move {
            let Some(mirror_result) = collect_mirror_result(mirror_result_rx).await else {
                return;
            };
            let mirror_summary = summary.as_mirror_entry(mirror_result);
            let mirror_mesh_key = if precompute_mesh_key {
                crate::plugins::mesh::prometheus_helpers::mesh_request_key(&mirror_summary)
            } else {
                None
            };
            for plugin in plugins.iter() {
                plugin
                    .log_with_mesh_key(&mirror_summary, mirror_mesh_key.as_ref())
                    .await;
            }
        });
    }
}

/// Run terminal transaction logging before a buffered H1/H2 response is handed
/// to hyper without allowing logging cleanup to extend an active gRPC deadline.
///
/// Ordinary requests preserve the historical sequential, awaited logging
/// contract. Once an absolute RPC deadline is installed, the client-visible
/// response owns the deadline and logging continues on cloned state under a
/// finite cleanup bound. This keeps audit delivery best-effort without letting
/// a blocked sink suppress the terminal response.
pub async fn log_with_mirror_before_buffered_response(
    plugins: &[Arc<dyn Plugin>],
    summary: TransactionSummary,
    ctx: &RequestContext,
) {
    if ctx.grpc_deadline_at().is_none() {
        log_with_mirror(plugins, &summary, ctx).await;
        return;
    }

    let plugins = plugins.to_vec();
    let ctx = ctx.clone();
    let _ = crate::observability_delivery::spawn_deadline_cleanup(async move {
        if tokio::time::timeout(
            std::time::Duration::from_secs(5),
            log_with_mirror(&plugins, &summary, &ctx),
        )
        .await
        .is_err()
        {
            tracing::warn!(
                "Detached transaction logging exceeded the post-response cleanup timeout"
            );
        }
    });
}

async fn collect_mirror_result(
    mut rx: tokio::sync::watch::Receiver<Option<MirrorResponseMeta>>,
) -> Option<MirrorResponseMeta> {
    // The request task itself is bounded by backend_read_timeout_ms when that
    // proxy timeout is configured. Waiting here stays fully detached from the
    // client response and preserves late-but-valid results. Production mirror
    // channels are seeded with a sanitized failure outcome, so sender closure
    // (task cancellation/panic) remains observable too. Tokio runtime shutdown
    // cancels both detached tasks together rather than extending shutdown.
    let _ = rx.changed().await;
    rx.borrow().clone()
}

/// Opaque release action for state acquired by a stream admission plugin.
///
/// The constructor is crate-private so plugins can attach permits without
/// exposing their keys or counter identities through transaction metadata.
/// Each permit invokes its release action exactly once, either when the stream
/// runner releases it at rejection/teardown or when the connection context is
/// dropped as a fallback.
pub struct StreamAdmissionPermit {
    release: Option<Box<dyn FnOnce() + Send + Sync + 'static>>,
}

impl StreamAdmissionPermit {
    pub(crate) fn new(release: impl FnOnce() + Send + Sync + 'static) -> Self {
        Self {
            release: Some(Box::new(release)),
        }
    }
}

impl Drop for StreamAdmissionPermit {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            release();
        }
    }
}

/// Context for stream proxy (TCP/UDP) plugin hooks.
///
/// Fields like `proxy_id`, `proxy_name`, `listen_port`, and `backend_scheme`
/// are available for custom plugins to use in their `on_stream_connect` logic.
#[allow(dead_code)]
pub struct StreamConnectionContext {
    /// Gateway-resolved client IP. For TCP stream proxies with inbound PROXY
    /// protocol enabled and a trusted upstream peer, this is the forwarded
    /// source address reported in the PROXY header — the real originating
    /// client IP, analogous to XFF-resolved `client_ip` on the HTTP path.
    /// When PROXY protocol is disabled or the peer is not trusted, this equals
    /// `direct_client_ip` (the raw socket peer).
    pub client_ip: String,
    /// Immediate socket-peer IP captured at accept(), before any PROXY-protocol
    /// header is applied. For stream proxies without inbound PROXY protocol
    /// this is always equal to `client_ip`. For proxies behind a trusted L4
    /// load balancer using PROXY protocol, this is the LB's own IP.
    /// Mirrors `RequestContext::direct_client_ip` on the HTTP path. Used by
    /// `mesh_authz` to populate Istio's `source.ip` principal (socket peer)
    /// separately from `remote.ip` (forwarded/resolved address).
    pub direct_client_ip: String,
    /// Shared typed client-IP cache for stream policy instances.
    /// Replacing this cache after changing `client_ip` invalidates only typed
    /// client-IP parsing; authoritative correlation ownership is independent.
    #[doc(hidden)]
    pub canonical_client_ip: CanonicalClientIpCache,
    /// Authoritative per-instance and canonical stream correlation values.
    ///
    /// This must remain private and non-replaceable by custom plugins. Public
    /// metadata is only a compatibility projection of this lifecycle state.
    correlation_ids: CorrelationIdState,
    pub proxy_id: String,
    /// Namespace owning `proxy_id` for this connection/session.
    ///
    /// Proxy IDs are unique only within a namespace, so every proxy-keyed
    /// runtime lookup (plugin cache, lifecycle generation, adaptive buffer)
    /// must be qualified by this. Stamped by the TCP/UDP accept paths from the
    /// listener's exact identity, and replaced with the matched candidate's
    /// namespace when SNI resolves a shared passthrough port. Defaults to the
    /// gateway default namespace for externally constructed contexts.
    pub proxy_namespace: String,
    pub proxy_name: Option<String>,
    /// Ownership generation captured at stream admission. Carried into
    /// [`StreamTransactionSummary`] so `proxy_alerts` can reject disconnect
    /// samples from a prior delete→recreate incarnation.
    #[doc(hidden)]
    pub proxy_lifecycle_generation: Option<u64>,
    pub listen_port: u16,
    /// Wire-level scheme the proxy uses to talk to its backend.
    /// Always one of the stream variants (`Tcp`, `Tcps`, `Udp`, `Dtls`) —
    /// validation guarantees stream proxies have a scheme set before any
    /// listener is bound, so this is non-optional.
    pub backend_scheme: BackendScheme,
    /// Pre-built consumer index shared across stream connections.
    pub consumer_index: Arc<ConsumerIndex>,
    /// Gateway Consumer identified for this stream connection, if any.
    pub identified_consumer: Option<Arc<Consumer>>,
    /// Identity string set by external stream auth plugins when no gateway
    /// Consumer was mapped. Mirrors `RequestContext::authenticated_identity`.
    pub authenticated_identity: Option<String>,
    /// Authentication mechanism that succeeded for this stream connection.
    /// Mirrors `RequestContext::auth_method`.
    pub auth_method: Option<&'static str>,
    /// Plugin metadata. Lazily allocated on first write to avoid a HashMap allocation
    /// for stream connections that have no metadata-writing plugins configured.
    pub metadata: Option<HashMap<String, String>>,
    /// Core-owned admission permits. External plugins should leave this empty
    /// and use metadata for their own connection state. Built-in admission
    /// plugins attach opaque permits through `add_admission_permit()` so state
    /// release does not depend on mutable metadata keys.
    #[doc(hidden)]
    pub admission_permits: Vec<StreamAdmissionPermit>,
    /// DER-encoded client certificate from frontend TLS handshake (first cert in chain).
    /// Populated for TCP/TLS proxies after the TLS handshake completes.
    /// Used by plugins like `tcp_connection_throttle` for consumer-based throttling.
    pub tls_client_cert_der: Option<Arc<Vec<u8>>>,
    /// DER-encoded CA/intermediate certificates from the client's certificate chain.
    /// Contains all certificates after the peer cert (index 1+) sent during the handshake.
    pub tls_client_cert_chain_der: Option<Arc<Vec<Vec<u8>>>>,
    /// SNI hostname from the frontend TLS/DTLS ClientHello (passthrough peek or
    /// terminating handshake) when available. Available to plugins for logging,
    /// routing, or access control. The same value is carried into
    /// `StreamTransactionSummary.sni_hostname` on disconnect.
    pub sni_hostname: Option<String>,
    /// Mesh traffic direction stamped by the stream listener that accepted this
    /// connection. Mirrors `RequestContext::mesh_direction`; `None` for stream
    /// proxies that are not part of a mesh listener.
    pub mesh_direction: Option<MeshTrafficDirection>,
    /// Pre-resolved per-pod policy scope for node-waypoint topology.
    /// Mirrors `RequestContext::node_waypoint_policy_scope`; `None` for
    /// non-waypoint stream proxies.
    pub node_waypoint_policy_scope: Option<Arc<crate::modes::mesh::runtime::PolicyScopeCache>>,
    /// Opening client bytes captured for stream-aware inspection plugins (e.g.
    /// the WAF). Populated by the stream proxy only when some plugin opts in via
    /// `requires_stream_first_bytes()`, before `on_stream_connect` runs; `None`
    /// otherwise. `first_bytes_kind` describes whether these are plaintext,
    /// encrypted passthrough, or post-termination decrypted bytes.
    pub first_bytes: Option<bytes::Bytes>,
    /// Nature of `first_bytes`. This may be `Some` even when `first_bytes` is
    /// `None` if a timed first-byte capture observed no data: raw TCP sets the
    /// expected wire kind so enforcing plugins can fail closed on missing
    /// plaintext while still recognizing encrypted passthrough as not
    /// L7-inspectable; TLS/DTLS-terminating frontends set `DecryptedApp` to
    /// record that the transport was terminated even when no application bytes
    /// were read.
    pub first_bytes_kind: Option<StreamBytesKind>,
}

impl StreamConnectionContext {
    /// Create a stream plugin context with empty optional lifecycle state.
    ///
    /// External plugins and tests must use this constructor rather than a
    /// struct literal because authoritative correlation ownership is private.
    /// The public fields may still be populated or updated before hooks run;
    /// if `client_ip` changes, replace `canonical_client_ip` with its default
    /// value to force an independent typed-IP reparse.
    pub fn new(
        client_ip: String,
        direct_client_ip: String,
        proxy_id: String,
        proxy_name: Option<String>,
        listen_port: u16,
        backend_scheme: BackendScheme,
        consumer_index: Arc<ConsumerIndex>,
    ) -> Self {
        Self {
            client_ip,
            direct_client_ip,
            canonical_client_ip: CanonicalClientIpCache::default(),
            correlation_ids: CorrelationIdState::default(),
            proxy_id,
            proxy_namespace: crate::config::types::default_namespace(),
            proxy_name,
            proxy_lifecycle_generation: None,
            listen_port,
            backend_scheme,
            consumer_index,
            identified_consumer: None,
            authenticated_identity: None,
            auth_method: None,
            metadata: None,
            admission_permits: Vec::new(),
            tls_client_cert_der: None,
            tls_client_cert_chain_der: None,
            sni_hostname: None,
            mesh_direction: None,
            node_waypoint_policy_scope: None,
            first_bytes: None,
            first_bytes_kind: None,
        }
    }

    /// Return the authoritative stream client IP as a canonical typed address.
    ///
    /// The value is parsed at most once per TCP connection or UDP/DTLS session
    /// and reused by every attached policy instance.
    pub fn canonical_client_ip(&self) -> Option<IpAddr> {
        self.canonical_client_ip.get_or_parse(&self.client_ip)
    }

    /// Whether [`Self::canonical_client_ip`] has initialized the shared cache.
    #[doc(hidden)]
    pub fn canonical_client_ip_is_initialized(&self) -> bool {
        self.canonical_client_ip.is_initialized()
    }

    pub(crate) fn publish_correlation_id(&mut self, instance_key: &str, request_id: String) {
        let publish_canonical = self
            .correlation_ids
            .publish_correlation_id(instance_key, request_id.clone());
        let metadata = self.metadata.get_or_insert_with(HashMap::new);
        metadata.insert(instance_key.to_string(), request_id.clone());
        if publish_canonical {
            metadata.insert(REQUEST_ID_METADATA_KEY.to_string(), request_id);
        }
    }

    /// Return the stable authenticated identity for stream policies. A mapped
    /// Consumer username takes precedence over any external authenticated identity.
    pub fn effective_identity(&self) -> Option<&str> {
        self.identified_consumer
            .as_ref()
            .map(|consumer| consumer.username.as_str())
            .or_else(|| meaningful_identity(self.authenticated_identity.as_deref()))
    }

    /// Insert a metadata value, lazily allocating the map on first write.
    pub fn insert_metadata(&mut self, key: String, value: String) {
        self.metadata
            .get_or_insert_with(HashMap::new)
            .insert(key, value);
    }

    /// Take the metadata map, returning an empty map if never allocated.
    pub fn take_metadata(&mut self) -> HashMap<String, String> {
        let mut metadata = self.metadata.take().unwrap_or_default();
        self.correlation_ids.project_correlation_ids(&mut metadata);
        metadata
    }

    /// Transfer plugin-writable metadata and private correlation ownership to a
    /// session that can receive additional metadata before its terminal summary.
    ///
    /// UDP and DTLS keep the correlation state immutable after admission, then
    /// re-project it after all per-datagram metadata has been merged. This avoids
    /// cloning correlation values per datagram while preventing those hooks from
    /// replacing the authoritative terminal values.
    pub(crate) fn take_metadata_with_correlation_ids(
        &mut self,
    ) -> (HashMap<String, String>, CorrelationIdState) {
        (
            self.metadata.take().unwrap_or_default(),
            std::mem::take(&mut self.correlation_ids),
        )
    }

    pub(crate) fn add_admission_permit(&mut self, permit: StreamAdmissionPermit) {
        self.admission_permits.push(permit);
    }

    /// Release every admission permit acquired so far, in reverse plugin order.
    ///
    /// TCP runners call this immediately when a later plugin rejects and when
    /// transport teardown completes, before awaiting disconnect observers.
    /// Draining the vector is idempotent, and dropping the context remains the
    /// fallback for exceptional exit paths.
    pub fn release_admission_permits(&mut self) {
        while let Some(permit) = self.admission_permits.pop() {
            drop(permit);
        }
    }
}

/// Transaction summary for stream proxy (TCP/UDP) logging plugins.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StreamTransactionSummary {
    /// Namespace of the matched proxy.
    pub namespace: String,
    pub proxy_id: String,
    pub proxy_name: Option<String>,
    pub client_ip: String,
    /// Identified consumer username (from gateway Consumer mapping) or external
    /// authenticated identity (e.g., JWKS subject) set by stream auth plugins.
    /// `None` when no authentication plugin identified the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumer_username: Option<String>,
    /// Authentication mechanism that succeeded for this stream connection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<&'static str>,
    pub backend_target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend_resolved_ip: Option<String>,
    pub protocol: String,
    pub listen_port: u16,
    pub duration_ms: f64,
    /// Bytes relayed from the client to the backend
    /// (gateway-perspective: bytes it sent onward on the client's behalf).
    pub bytes_sent: u64,
    /// Bytes relayed from the backend to the client
    /// (gateway-perspective: bytes it received and forwarded back).
    pub bytes_received: u64,
    pub connection_error: Option<String>,
    /// Human-friendly classification of the connection error, if any.
    /// Mirrors the `ErrorClass` used for HTTP/gRPC transactions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_class: Option<crate::retry::ErrorClass>,
    /// Which direction of the bidirectional stream failed first.
    /// `None` for clean shutdowns or timeouts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disconnect_direction: Option<Direction>,
    /// Cause of the disconnect (idle timeout vs. recv error vs. graceful shutdown).
    /// Disambiguates the implicit `error_class: None` timeout convention.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disconnect_cause: Option<DisconnectCause>,
    pub timestamp_connected: String,
    pub timestamp_disconnected: String,
    /// SNI hostname from the frontend TLS/DTLS ClientHello when available.
    /// Populated for TCP TLS termination, DTLS termination, and TLS/DTLS
    /// passthrough (ClientHello peek). Omitted from JSON when null so sinks
    /// that serialize `StreamTransactionSummary` unchanged (e.g. `http_logging`,
    /// `loki_logging`) retain connect/disconnect parity for every stream path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni_hostname: Option<String>,
    /// Plugin-injected metadata (e.g., correlation ID, trace ID) carried
    /// from `on_stream_connect` to `on_stream_disconnect`. Sensitive keys
    /// (authorization, cookie, credential/session tokens, secrets — see
    /// `plugins::utils::metadata_redaction::DEFAULT_SENSITIVE_METADATA_KEYS`
    /// plus operator extras from `FERRUM_LOG_REDACT_METADATA_KEYS`) are
    /// replaced with `[REDACTED]` at serialize time.
    #[serde(
        skip_serializing_if = "HashMap::is_empty",
        serialize_with = "crate::plugins::utils::metadata_redaction::serialize_redacted_metadata"
    )]
    pub metadata: HashMap<String, String>,
    /// Ownership generation captured at stream admission. Not serialized;
    /// used by `proxy_alerts` to reject samples from a prior delete→recreate
    /// incarnation of the same proxy ID.
    #[doc(hidden)]
    #[serde(skip)]
    pub proxy_lifecycle_generation: Option<u64>,
}

/// Plugin execution priority bands.
///
/// Plugins are sorted by priority (lowest runs first) within each lifecycle
/// phase. Plugins at the same priority have no guaranteed relative order.
/// Gaps between bands leave room for future plugins to slot in.
///
/// | Band      | Range       | Purpose                                   | Plugins |
/// |-----------|-------------|-------------------------------------------|---------|
/// | Early     | 0–949       | Matched-request tracing and preflight     | otel_tracing (25), correlation_id (50), cors (100), request_termination (125), mesh_outbound_registry (130), ip_restriction (150), bot_detection (200), sse (250), grpc_web (260), grpc_method_router (275), spiffe_identity (940) |
/// | AuthN     | 950–1999    | Authentication / identity verification    | mtls_auth (950), jwks_auth (1000), oauth2_introspection (1050), oidc_relying_party (1075), jwt_auth (1100), key_auth (1200), ldap_auth (1250), basic_auth (1300), hmac_auth (1400), soap_ws_security (1500) |
/// | AuthZ     | 2000–2999   | Authorization and admission control       | access_control (2000), tcp_connection_throttle (2050), mesh_authz (2075), opa (2080), adaptive_concurrency (2090), ai_transcript_audit (2740), request_deduplication (2750), request_size_limiting (2800), graphql (2850), rate_limiting (2900), ai_prompt_shield (2925), waf (2930), body_validator (2950), openapi_validator (2960), ai_semantic_firewall (2968), ai_request_guard (2975), ai_tool_governor (2978), ai_stream_router (2984), mcp_gateway (2992), a2a_gateway (2993), mesh_route_dispatch (2995), ai_semantic_cache (2996) |
/// | Transform | 3000–3999   | Request shaping and response buffering    | request_transformer (3000), serverless_function (3025), response_mock (3030), grpc_deadline (3050), load_testing (3070), request_mirror (3075), response_size_limiting (3490), response_caching (3500) |
/// | Response  | 4000–4999   | Response transformation, security headers, and AI accounting | response_transformer (4000), compression (4050), ai_prompt_compressor (4055), ai_federation (4060), ai_response_guard (4075), security_headers (4080), ai_token_metrics (4100), ai_rate_limiter (4200) |
/// | Logging   | 9000–9999   | Observability and frame logging           | stdout_logging (9000), ws_frame_logging (9050), statsd_logging (9075), http_logging (9100), tcp_logging (9125), kafka_logging (9150), loki_logging (9155), udp_logging (9160), ws_logging (9175), transaction_debugger (9200), prometheus_metrics (9300), api_chargeback (9350), api_chargeback_sink (9351), workload_metrics (9360), __mesh_bpf_metrics (9365), transaction_log_schema (9999, config-only) |
#[allow(dead_code)]
pub mod priority {
    pub const OTEL_TRACING: u16 = 25;
    pub const CORRELATION_ID: u16 = 50;
    pub const CORS: u16 = 100;
    pub const REQUEST_TERMINATION: u16 = 125;
    /// `mesh_outbound_registry`: rejects outbound requests whose
    /// destination is not in the mesh registry. Auto-injected only when
    /// `MeshConfig.outbound_traffic_policy == RegistryOnly`. Runs in the
    /// `on_request_received` band so the rejection is visible to all
    /// downstream observability without engaging the auth pipeline.
    pub const MESH_OUTBOUND_REGISTRY: u16 = 130;
    pub const IP_RESTRICTION: u16 = 150;
    pub const GEO_RESTRICTION: u16 = 175;
    pub const BOT_DETECTION: u16 = 200;
    pub const SPEC_EXPOSE: u16 = 210;
    pub const SSE: u16 = 250;
    pub const GRPC_WEB: u16 = 260;
    pub const GRPC_METHOD_ROUTER: u16 = 275;
    pub const SPIFFE_IDENTITY: u16 = 940;
    pub const MTLS_AUTH: u16 = 950;
    pub const JWKS_AUTH: u16 = 1000;
    pub const OAUTH2_INTROSPECTION: u16 = 1050;
    pub const OIDC_RELYING_PARTY: u16 = 1075;
    pub const JWT_AUTH: u16 = 1100;
    pub const KEY_AUTH: u16 = 1200;
    pub const LDAP_AUTH: u16 = 1250;
    pub const BASIC_AUTH: u16 = 1300;
    pub const HMAC_AUTH: u16 = 1400;
    pub const SOAP_WS_SECURITY: u16 = 1500;
    pub const ACCESS_CONTROL: u16 = 2000;
    pub const TCP_CONNECTION_THROTTLE: u16 = 2050;
    pub const MESH_AUTHZ: u16 = 2075;
    pub const OPA: u16 = 2080;
    pub const ADAPTIVE_CONCURRENCY: u16 = 2090;
    pub const REQUEST_DEDUPLICATION: u16 = 2750;
    pub const REQUEST_SIZE_LIMITING: u16 = 2800;
    pub const GRAPHQL: u16 = 2850;
    pub const RATE_LIMITING: u16 = 2900;
    /// Runs before request deduplication and reject-capable AI guardrails so
    /// cached replays and blocked prompts are staged for audit, while final
    /// request-body hooks refresh the capture after downstream transforms.
    pub const AI_TRANSCRIPT_AUDIT: u16 = 2740;
    pub const AI_PROMPT_SHIELD: u16 = 2925;
    pub const WAF: u16 = 2930;
    pub const FAULT_INJECTION: u16 = 2940;
    pub const BODY_VALIDATOR: u16 = 2950;
    pub const OPENAPI_VALIDATOR: u16 = 2960;
    pub const AI_SEMANTIC_FIREWALL: u16 = 2968;
    pub const AI_REQUEST_GUARD: u16 = 2975;
    /// `ai_tool_governor`: deterministic allow/deny/approval policy on AI tool /
    /// function calls (names, arguments, JSON Schema, regex, identity, approval).
    /// Runs after semantic/request admission but before `ai_semantic_cache` and
    /// `ai_federation` so disallowed tool schemas are screened before caching or
    /// federation routing.
    pub const AI_TOOL_GOVERNOR: u16 = 2978;
    /// `ai_stream_router`: claims streaming (`"stream": true`) OpenAI Chat
    /// Completions requests, rewrites `route_override_*` to the matched provider,
    /// and normalizes provider-native SSE to OpenAI `chat.completion.chunk` SSE.
    /// Runs before `ai_semantic_cache` (and before `ai_federation` at 4060) so
    /// cache lookup observes the effective provider destination for streaming
    /// claims while the non-streaming federation path can still defer via the
    /// `ai_stream_router_claimed` marker.
    pub const AI_STREAM_ROUTER: u16 = 2984;
    /// `mcp_gateway`: parses MCP JSON-RPC bodies and applies MCP-aware route
    /// overrides after generic admission/auth plugins but before final dispatch.
    pub const MCP_GATEWAY: u16 = 2992;
    /// `a2a_gateway`: detects A2A HTTP/REST/gRPC traffic, applies lightweight
    /// method policy, rewrites HTTP Agent Cards, and emits `a2a.*` metadata.
    pub const A2A_GATEWAY: u16 = 2993;
    /// `mesh_route_dispatch`: rewrites `route_override_*` on `RequestContext`
    /// based on Istio VirtualService method/header/query-param predicates.
    /// Runs after admission plugins and immediately before `ai_semantic_cache`
    /// so cache identity can bind the post-routing effective destination;
    /// backend dispatch applies the override after `before_proxy`.
    pub const MESH_ROUTE_DISPATCH: u16 = 2995;
    /// `ai_semantic_cache`: exact/semantic LLM response cache. Runs after
    /// route-dispatch plugins (`ai_stream_router`, `mcp_gateway`, `a2a_gateway`,
    /// `mesh_route_dispatch`) so exact and semantic keys include the canonical
    /// route/operation identity and the effective destination/provider that
    /// will serve a miss, and before request transformers / `ai_federation`.
    pub const AI_SEMANTIC_CACHE: u16 = 2996;
    pub const REQUEST_TRANSFORMER: u16 = 3000;
    pub const SERVERLESS_FUNCTION: u16 = 3025;
    pub const RESPONSE_MOCK: u16 = 3030;
    pub const GRPC_DEADLINE: u16 = 3050;
    /// `load_testing`: strips the reserved trigger header on every path before
    /// later deferred transforms (notably `request_mirror`) can observe it.
    pub const LOAD_TESTING: u16 = 3070;
    pub const REQUEST_MIRROR: u16 = 3075;
    pub const RESPONSE_SIZE_LIMITING: u16 = 3490;
    pub const RESPONSE_CACHING: u16 = 3500;
    pub const RESPONSE_TRANSFORMER: u16 = 4000;
    pub const COMPRESSION: u16 = 4050;
    /// `ai_prompt_compressor`: shortens prompt text to cut LLM token usage.
    /// Runs after `compression` so opt-in request decompression exposes
    /// plaintext prompt JSON before this plugin rewrites the backend body.
    pub const AI_PROMPT_COMPRESSOR: u16 = 4055;
    pub const AI_FEDERATION: u16 = 4060;
    pub const AI_RESPONSE_GUARD: u16 = 4075;
    /// `security_headers`: injects response security headers and strips
    /// fingerprinting headers in `after_proxy`. Runs late in the response band
    /// so it is authoritative over `response_transformer` (4000) and
    /// `compression` (4050) header changes.
    pub const SECURITY_HEADERS: u16 = 4080;
    pub const AI_TOKEN_METRICS: u16 = 4100;
    pub const AI_RATE_LIMITER: u16 = 4200;
    pub const STDOUT_LOGGING: u16 = 9000;
    pub const STATSD_LOGGING: u16 = 9075;
    pub const HTTP_LOGGING: u16 = 9100;
    pub const TCP_LOGGING: u16 = 9125;
    pub const KAFKA_LOGGING: u16 = 9150;
    pub const LOKI_LOGGING: u16 = 9155;
    pub const UDP_LOGGING: u16 = 9160;
    pub const TRANSACTION_DEBUGGER: u16 = 9200;
    pub const PROXY_ALERTS: u16 = 9250;
    pub const PROMETHEUS_METRICS: u16 = 9300;
    pub const API_CHARGEBACK: u16 = 9350;
    pub const API_CHARGEBACK_SINK: u16 = 9351;
    pub const WORKLOAD_METRICS: u16 = 9360;
    /// `__mesh_bpf_metrics`: exposes TCP-layer counters (Connect, Accept,
    /// Rst, Fin, SRTT, BPF drop reasons, ringbuf overrun) from the
    /// SOCK_OPS event consumer. Auto-injected only when topology is
    /// `NodeWaypoint`. Lives in the observability band alongside other
    /// metric-emitter plugins so its `log` hook runs after all
    /// transaction-summary serialization.
    pub const MESH_BPF_METRICS: u16 = 9365;
    /// `transaction_log_schema` is a config-only plugin with no lifecycle
    /// hooks; its priority is irrelevant in practice but is kept at the
    /// top of the logging band so any future hook would run after all
    /// observability sinks.
    pub const TRANSACTION_LOG_SCHEMA: u16 = 9999;
    pub const WS_MESSAGE_SIZE_LIMITING: u16 = 2810;
    pub const WS_RATE_LIMITING: u16 = 2910;
    pub const WS_LOGGING: u16 = 9175;
    pub const WS_FRAME_LOGGING: u16 = 9050;
    pub const UDP_RATE_LIMITING: u16 = 2915;
    /// Default priority for unknown/custom plugins — runs after transforms, before logging.
    pub const DEFAULT: u16 = 5000;
}

#[derive(Clone, Copy, Debug)]
pub struct BackendAdmissionOutcome {
    pub response_status: u16,
    pub connection_error: bool,
    pub error_class: Option<crate::retry::ErrorClass>,
    pub backend_elapsed: Duration,
}

pub trait BackendAdmissionPermit: Send + Sync {
    fn record_backend_outcome(&self, outcome: BackendAdmissionOutcome);

    /// Record an outcome for an admission whose in-flight slot is still held
    /// after this call returns — long-lived sessions such as WebSocket, where
    /// the permit lives for the entire session rather than a single
    /// request/response. Feeds the same latency/failure signals as
    /// [`Self::record_backend_outcome`] but must never grow the limit: with the
    /// slot still occupied, every concurrent handshake observes the limiter at
    /// capacity, so growing here would ratchet the limit upward and defeat the
    /// in-flight session cap. Defaults to `record_backend_outcome` for permits
    /// that do not distinguish the two.
    fn record_backend_outcome_holding(&self, outcome: BackendAdmissionOutcome) {
        self.record_backend_outcome(outcome);
    }
}

#[derive(Clone, Default)]
pub struct BackendAdmissionPermitSet {
    permits: Vec<Arc<dyn BackendAdmissionPermit>>,
}

impl BackendAdmissionPermitSet {
    pub fn new(permits: Vec<Arc<dyn BackendAdmissionPermit>>) -> Option<Self> {
        (!permits.is_empty()).then_some(Self { permits })
    }

    pub fn record_backend_outcome(&self, outcome: BackendAdmissionOutcome) {
        for permit in &self.permits {
            permit.record_backend_outcome(outcome);
        }
    }

    /// Record an outcome while the in-flight slot stays held (long-lived
    /// sessions such as WebSocket). See
    /// [`BackendAdmissionPermit::record_backend_outcome_holding`].
    pub fn record_backend_outcome_holding(&self, outcome: BackendAdmissionOutcome) {
        for permit in &self.permits {
            permit.record_backend_outcome_holding(outcome);
        }
    }
}

pub struct BackendAdmissionContext<'a> {
    pub proxy: &'a Proxy,
    pub upstream_target: Option<&'a UpstreamTarget>,
    pub protocol: ProxyProtocol,
}

impl<'a> BackendAdmissionContext<'a> {
    pub fn backend_host(&self) -> &'a str {
        self.upstream_target
            .map(|target| target.host.as_str())
            .unwrap_or(self.proxy.backend_host.as_str())
    }

    pub fn backend_port(&self) -> u16 {
        self.upstream_target
            .map(|target| target.port)
            .unwrap_or(self.proxy.backend_port)
    }
}

pub enum BackendAdmissionDecision {
    Continue,
    Admit(Arc<dyn BackendAdmissionPermit>),
    Reject {
        status_code: u16,
        body: Vec<u8>,
        headers: HashMap<String, String>,
    },
}

/// Plugin lifecycle hooks.
#[async_trait]
pub trait Plugin: Send + Sync {
    /// Returns the plugin name.
    fn name(&self) -> &str;

    /// Returns the immutable country-MMDB snapshot retained by this plugin.
    ///
    /// Plugin-cache generation construction uses this cold-path hook to enforce
    /// the aggregate live-snapshot budget across both rebuilt and retained geo
    /// instances. Ordinary plugins retain the allocation-free default.
    fn country_mmdb_snapshot(&self) -> Option<&crate::config::types::CountryMmdbSnapshot> {
        None
    }

    /// Cold-path: publish the active per-proxy ownership generations and drop
    /// lifecycle rows for proxies absent from that map.
    ///
    /// Incremental plugin-cache commits call this on preserved global and
    /// proxy-group instances after the new generation is published so delete,
    /// rename, group-membership churn, and ID reuse cannot inherit prior
    /// cooldown/recovery ownership. Values are ownership generations (not a
    /// bare active-ID set) so an in-flight sample from a prior incarnation of
    /// the same proxy ID cannot repopulate state after retain. Must not run on
    /// the request hot path. Ordinary plugins retain the no-op default.
    fn retain_active_proxy_state(&self, _active_proxy_generations: &HashMap<&str, u64>) {}

    /// Test helper: seed per-proxy lifecycle state owned by this plugin under
    /// `generation`.
    #[doc(hidden)]
    fn seed_proxy_lifecycle_state_for_test(&self, _proxy_id: &str, _generation: u64) {}

    /// Test helper: whether this plugin currently holds lifecycle state for
    /// `proxy_id`.
    #[doc(hidden)]
    fn has_proxy_lifecycle_state_for_test(&self, _proxy_id: &str) -> bool {
        false
    }

    /// Test helper: whether this plugin holds lifecycle state for
    /// `(proxy_id, generation)`.
    #[doc(hidden)]
    fn has_proxy_lifecycle_state_for_generation_for_test(
        &self,
        _proxy_id: &str,
        _generation: u64,
    ) -> bool {
        false
    }

    /// Test helper: write lifecycle state under `generation`, bypassing the
    /// admission precheck (race-contract tests).
    #[doc(hidden)]
    fn write_proxy_lifecycle_state_for_test(&self, _proxy_id: &str, _generation: u64) {}

    /// Return the node-local `.mmdb` path this instance was built from together
    /// with the validated snapshot it currently holds, or `None` when it holds
    /// no snapshot.
    ///
    /// The DP node-local refresh path uses this cold-path hook to carry a
    /// last-known-good snapshot across a transient file outage. Retention is
    /// keyed on the path so a configuration that repoints `db_path` never
    /// inherits the previous file's data. Ordinary plugins retain the default.
    #[doc(hidden)]
    fn country_mmdb_retained_load(
        &self,
    ) -> Option<(&str, Arc<crate::config::types::CountryMmdbSnapshot>)> {
        None
    }

    /// Return the non-empty correlation header owned by this instance, or
    /// `None` when it owns no correlation header. Plugin-cache admission trims
    /// and ASCII-case-folds claims before rejecting empty, deployment-owned
    /// `FERRUM_REAL_IP_HEADER`, or ambiguous writers.
    #[doc(hidden)]
    fn correlation_id_header_name(&self) -> Option<&str> {
        None
    }

    /// Cold-path scrape exporter for `__mesh_bpf_metrics`.
    ///
    /// Plugin-cache generations extract this once from the constructed global
    /// instance so authenticated `GET /metrics` can append the BPF surface
    /// without scanning plugins or allocating a new representation per scrape.
    /// Ordinary plugins retain the allocation-free default.
    fn mesh_bpf_metrics_exporter(
        &self,
    ) -> Option<crate::plugins::mesh::bpf_metrics::MeshBpfMetricsExporter> {
        None
    }

    /// Returns the execution priority (lower = runs first).
    ///
    /// Plugins are sorted by priority within each lifecycle phase.
    /// See [`priority`] module for standard bands and assignments.
    fn priority(&self) -> u16 {
        priority::DEFAULT
    }

    /// Apply a request-receipt gRPC deadline policy synchronously, before any
    /// plugin or request-body await. Only `grpc_deadline` overrides this hook.
    /// It must not perform I/O or mutate the forwarded header; `before_proxy`
    /// emits the relative upstream value from the typed absolute state.
    fn prepare_grpc_deadline(&self, _ctx: &mut RequestContext) -> PluginResult {
        PluginResult::Continue
    }

    /// Returns `true` when this plugin participates in the synchronous gRPC
    /// deadline preflight. The plugin cache uses this to build a dedicated
    /// phase list so ordinary gRPC requests do not scan the full plugin chain
    /// before the first asynchronous hook.
    fn requires_grpc_deadline_preflight(&self) -> bool {
        false
    }

    /// Called after routing and per-proxy allowed-method admission succeed.
    /// Native gRPC requests must also use `POST` before this hook runs.
    ///
    /// The hook receives a context whose `matched_proxy` is populated and runs
    /// over the resolved plugin view for that proxy (applicable global plugins
    /// plus proxy/proxy-group-scoped plugins). An unmatched route returns 404,
    /// and a matched route with a disallowed method returns 405, before any
    /// `on_request_received` hook runs. Consequently neither global nor scoped
    /// implementations observe those two early terminal paths on H1, H2, or H3.
    /// Matched-proxy `allowed_methods` 405 responses still emit one terminal
    /// transaction summary (`rejection_phase = "allowed_methods"`) without
    /// running this or other ordinary request-policy hooks. Terminal
    /// transaction logging is a separate lifecycle concern and must not be
    /// inferred from whether this ordinary request hook ran.
    async fn on_request_received(&self, _ctx: &mut RequestContext) -> PluginResult {
        PluginResult::Continue
    }

    /// Identifies the cache-internal wrapper used to defer a composed CORS
    /// chain. This prevents incremental cache rebuilds from nesting wrappers.
    fn is_deferred_cors_wrapper(&self) -> bool {
        false
    }

    /// Authentication phase. Uses ConsumerIndex for O(1) credential lookups.
    async fn authenticate(
        &self,
        _ctx: &mut RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        PluginResult::Continue
    }

    /// Marks configured query credential locations before authentication
    /// starts. The authentication dispatcher calls this for every configured
    /// auth plugin before multi-auth can stop at the first success, allowing
    /// later authorization plugins to omit every possible query credential.
    fn mark_query_credentials_for_redaction(&self, _ctx: &mut RequestContext) {}

    /// Request header names whose values contain reusable credentials and must
    /// be omitted from diagnostics and policy calls. Names are collected once
    /// when the plugin cache is built, not rediscovered on the request hot path.
    fn request_headers_to_redact(&self) -> &[String] {
        &[]
    }

    /// Authorization phase (after authentication).
    async fn authorize(&self, _ctx: &mut RequestContext) -> PluginResult {
        PluginResult::Continue
    }

    /// Returns `true` if this plugin may modify outgoing request headers
    /// during the `before_proxy` phase. The gateway uses this hint to skip
    /// cloning the header map when no plugin needs to modify it.
    ///
    /// Default is `false`. Override in plugins that insert, remove, or
    /// modify headers in `before_proxy`.
    fn modifies_request_headers(&self) -> bool {
        false
    }

    /// Returns `true` if this plugin may transform the request body before
    /// it is sent to the backend. The gateway uses this hint to call
    /// `transform_request_body` only when needed.
    ///
    /// Default is `false`. Override in plugins that rewrite JSON fields,
    /// rename body keys, etc.
    fn modifies_request_body(&self) -> bool {
        false
    }

    /// Returns `true` when this plugin sends the buffered request body to an
    /// external service during `before_proxy`, before request-body transforms
    /// and final-body policy hooks run. Cache validation rejects a same-protocol
    /// transformer in that chain so policy cannot govern different bytes than
    /// the backend receives.
    fn egresses_request_body_before_finalization(&self) -> bool {
        false
    }

    /// Returns `true` when this plugin can execute an external side effect and
    /// then terminate the request from `before_proxy`.
    ///
    /// A configured `request_deduplication` instance must have a strictly lower
    /// effective priority so it acquires replay/in-flight ownership before the
    /// side effect can run. This capability does not require deduplication to be
    /// configured; it only makes an attached deduplication chain fail closed on
    /// an unsafe ordering.
    fn requires_prior_request_deduplication(&self) -> bool {
        false
    }

    /// Returns `true` if this plugin needs the raw request body to be available
    /// during `before_proxy`.
    ///
    /// This is narrower than `requires_request_body_buffering()`: body
    /// transformers can buffer later, after `before_proxy` rejects have had a
    /// chance to short-circuit. Override this only for plugins that inspect
    /// `ctx.metadata["request_body"]` or `ctx.request_body_bytes` inside
    /// `before_proxy`.
    fn requires_request_body_before_before_proxy(&self) -> bool {
        false
    }

    /// Returns `true` when this plugin rewrites the prebuffered request body
    /// after the pre-`before_proxy` buffer is stored and before any
    /// `before_proxy` hook runs.
    ///
    /// Use this for gateway-owned request-body normalization that later
    /// `before_proxy` consumers must observe (for example configured gzip/Brotli
    /// request decompression so `soap_ws_security` validates plaintext XML).
    /// Ordinary body transforms that only need to affect the backend-visible
    /// bytes should keep using `transform_request_body` instead.
    fn normalizes_buffered_request_body_before_before_proxy(&self) -> bool {
        false
    }

    /// Optionally rewrite `body` (and related request headers) before the
    /// `before_proxy` phase.
    ///
    /// The proxy invokes this only for plugins that return `true` from
    /// [`normalizes_buffered_request_body_before_before_proxy`] after the
    /// pre-`before_proxy` buffer is stored on H1/H2 and native H3. Successful
    /// rewrites must leave `body` as the authoritative plaintext that later
    /// `before_proxy` hooks and the eventual backend forward path observe.
    /// Reject to fail closed on malformed or over-limit input before header
    /// normalization commits.
    async fn normalize_buffered_request_body_before_before_proxy(
        &self,
        _ctx: &mut RequestContext,
        _headers: &mut HashMap<String, String>,
        _body: &mut Vec<u8>,
    ) -> PluginResult {
        PluginResult::Continue
    }

    /// Returns `true` if this plugin needs the raw request body to be available
    /// during the `authenticate` phase.
    ///
    /// This is even narrower than `requires_request_body_before_before_proxy()`:
    /// it forces request body buffering BEFORE the authenticate phase runs, so
    /// auth plugins can verify body integrity (e.g., a Ferrum HMAC signing
    /// string that covers RFC 9530 `Content-Digest` or legacy `Digest`).
    ///
    /// Override this only for auth plugins that perform body integrity checks
    /// at authentication time (e.g., `hmac_auth`).
    fn requires_request_body_before_authenticate(&self) -> bool {
        false
    }

    /// Return whether this request should be buffered before authentication
    /// after credential checks that do not require body bytes.
    ///
    /// The default preserves the ordinary request-time buffering predicate.
    /// Body-authentication plugins can override this to reject malformed,
    /// expired, or unknown credentials without first collecting an attacker-
    /// controlled request body.
    fn should_buffer_request_body_before_authenticate(
        &self,
        ctx: &RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> bool {
        self.should_buffer_request_body(ctx)
    }

    /// Returns `true` if this plugin needs the raw request body to be available
    /// during the `authorize` phase.
    ///
    /// This buffers only after authentication has succeeded, so authorization
    /// plugins cannot make unauthenticated clients upload and retain a body
    /// before an authentication plugin has had a chance to reject them.
    fn requires_request_body_before_authorize(&self) -> bool {
        false
    }

    /// Returns `true` if this plugin needs binary-safe access to the raw
    /// request body bytes via `ctx.request_body_bytes`.
    ///
    /// Most plugins read the body from `ctx.metadata["request_body"]` which
    /// is UTF-8 only. This flag gates a `Bytes::copy_from_slice` allocation
    /// that would otherwise run on every buffered request. Only override
    /// this for plugins that handle non-UTF-8 payloads (e.g., gRPC protobuf).
    fn needs_request_body_bytes(&self) -> bool {
        false
    }

    /// Returns `true` when the plugin needs SHA-256 and SHA-512 snapshots of
    /// the body but does not need to retain the body itself.
    fn needs_request_body_digests(&self) -> bool {
        false
    }

    /// Returns `true` if this plugin needs the UTF-8 request-body copy in
    /// `ctx.metadata["request_body"]`.
    ///
    /// The compatibility default is `true`; binary-only consumers can override
    /// it to avoid retaining a second full body representation.
    fn needs_request_body_text(&self) -> bool {
        true
    }

    /// Optional plugin-local request body ceiling. The proxy combines every
    /// applicable plugin ceiling with the global request-body limit and uses
    /// the strictest positive value. This keeps body-aware plugins bounded even
    /// when the global limit is configured as unlimited (`0`).
    fn request_body_buffer_limit(&self) -> Option<usize> {
        None
    }

    /// Returns `true` if this plugin may require the request body to be
    /// buffered instead of streamed for at least some requests.
    ///
    /// The gateway uses this as a config-time upper bound in `PluginCache`.
    /// Request-time body buffering can still remain disabled when
    /// `should_buffer_request_body()` returns `false` for the current request.
    fn requires_request_body_buffering(&self) -> bool {
        self.modifies_request_body()
            || self.requires_request_body_before_before_proxy()
            || self.requires_request_body_before_authenticate()
            || self.requires_request_body_before_authorize()
    }

    /// Called just before the request is proxied to the backend.
    async fn before_proxy(
        &self,
        _ctx: &mut RequestContext,
        _headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        PluginResult::Continue
    }

    /// Returns `true` when `before_proxy` can dispatch external work or
    /// synthesize a terminal response and therefore must wait until an active
    /// backend-path policy has authorized the resolved route and target path.
    ///
    /// The ordinary plugin pipeline is unchanged when no backend-path plugin
    /// is active. Opt-in hooks retain their relative order in a deferred pass.
    fn defer_before_proxy_until_backend_path_resolved(&self) -> bool {
        false
    }

    /// Returns `true` when a deferred `before_proxy` hook can mutate headers
    /// that normally participate in upstream target selection. The gateway
    /// runs these hooks in a separate deferred subphase after backend-path
    /// enforcement and pins the authorized target across the external call;
    /// the returned headers cannot steer this request onto a different path.
    fn deferred_before_proxy_may_change_routing_headers(&self) -> bool {
        false
    }

    /// Returns `true` when this plugin must inspect the backend-effective path
    /// after route overrides and load balancing have selected the first target.
    ///
    /// The plugin cache precomputes this opt-in list, so requests without a
    /// participating plugin do not scan the full chain at this boundary.
    fn requires_backend_path_resolution(&self) -> bool {
        false
    }

    /// Called after the backend-effective path has been assembled from the
    /// route override, listen-path stripping, proxy/backend path, and selected
    /// upstream target path. The selected target is pinned and this hook runs
    /// exactly once before deferred external/synthetic hooks or backend dial,
    /// so implementations may safely commit stateful policy such as rate-limit
    /// charges here.
    async fn on_backend_path_resolved(
        &self,
        _ctx: &mut RequestContext,
        _backend_path: &str,
    ) -> PluginResult {
        PluginResult::Continue
    }

    /// Enables cache-managed aggregation of a plugin's unmatched decision.
    /// The default is a no-op; `mesh_route_dispatch` uses this to preserve
    /// standalone behavior while coordinating multiple cached instances.
    fn enable_deferred_unmatched_rejection(&self) {}

    /// Returns `true` if this plugin participates in target-aware backend
    /// admission after load balancing and before backend dispatch.
    fn is_backend_admission_plugin(&self) -> bool {
        false
    }

    /// Called after the gateway has selected the backend target but before it
    /// dials or sends the request. Returning a permit keeps backend admission
    /// state alive for the response or upgraded-session lifetime.
    fn try_backend_admission(
        &self,
        _ctx: &RequestContext,
        _admission: &BackendAdmissionContext<'_>,
    ) -> BackendAdmissionDecision {
        BackendAdmissionDecision::Continue
    }

    /// Returns `true` when the current request should buffer the request body
    /// for this plugin.
    ///
    /// Override this for config-sensitive or header-sensitive plugins so the
    /// gateway can keep streaming requests that clearly do not need body access
    /// (for example, non-JSON requests on an AI policy plugin).
    fn should_buffer_request_body(&self, _ctx: &RequestContext) -> bool {
        self.requires_request_body_buffering()
    }

    /// Called after the response is received from the backend.
    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        PluginResult::Continue
    }

    /// Return whether this hook authoritatively owns a response field even
    /// when it writes the same bytes the backend supplied. Most plugins rely
    /// on mutation tracking; request-aware decorators with configurable names
    /// should opt in so an exact backend spoof cannot hide their write.
    fn owns_deadline_response_header(&self, _ctx: &RequestContext, _name: &str) -> bool {
        false
    }

    /// Decorate the successful WebSocket handshake response before the
    /// frontend commits it.
    ///
    /// H1 Upgrade and H2/H3 Extended CONNECT bypass the ordinary
    /// `after_proxy` response lifecycle. This deliberately non-rejecting,
    /// synchronous hook gives request-local header decorators an equivalent
    /// boundary without introducing backend-handshake rollback or I/O after
    /// the upstream has already accepted the session. Protocol-managed fields
    /// are removed after the ordered hook chain, then the frontend restores
    /// its authoritative Upgrade/subprotocol fields.
    fn apply_websocket_handshake_response_headers(
        &self,
        _ctx: &RequestContext,
        _response_status: u16,
        _response_headers: &mut HashMap<String, String>,
    ) {
    }

    /// How completely this plugin's response-side *presentation* policy — the
    /// client-facing body rewrites that a finalized replay
    /// (`RequestContext::finalized_response_replay`) deliberately skips so
    /// non-idempotent rules cannot run twice over an already-transformed
    /// representation — can be described to a representation retained for
    /// replay.
    ///
    /// Returning `Some` enrolls the instance in replay provenance. The plugin
    /// cache folds every `Static` contribution, in configured execution order,
    /// into one per-proxy digest
    /// (`PluginCacheRequestView::response_presentation_policy_digest`) that
    /// `request_deduplication` binds into every representation it retains; a
    /// stored representation replays only while that digest still matches, so
    /// newly configured redaction can never be skipped by a retained replay. A
    /// single [`ResponsePresentationPolicy::Dynamic`] contribution collapses the
    /// whole per-proxy fold to `None`, because a fold that silently omitted an
    /// undescribable member would assert a completeness it does not have.
    ///
    /// `Static` implementations must derive the digest **only** from static
    /// configuration — never from per-request data, live discovery state,
    /// pointers, timestamps, or process-random state — so two processes loading
    /// equivalent configuration derive the same value, and it must change
    /// whenever any rule that shapes the client-visible representation changes.
    /// Use `utils::policy_digest::static_config_digest` with a plugin-specific
    /// domain separator. Return only the digest: the value is persisted outside
    /// this process, so raw configuration must never be exposed here.
    ///
    /// Only response *body* transforms need enrollment. `after_proxy` header
    /// hooks — including the rejection-path hooks a synthetic replay runs
    /// through — still execute on a finalized replay, so header policy is
    /// enforced live and is never skipped. (`response_transformer` consuming
    /// `ctx.route_override_response_transform` without applying it on a
    /// finalized replay is the deliberate counterpart: those route rules are
    /// header-only and are already baked into the stored header map.)
    ///
    /// Every current implementor of `transform_response_body` /
    /// `transform_response_body_with_context` has been audited against that
    /// rule. Enrolled `Static`: `response_transformer`, `sse` — both rewrite
    /// bodies purely from accepted configuration and hold no interior mutable
    /// presentation state. Enrolled `Dynamic`: `mcp_gateway`.
    /// Deliberately not enrolled, and why the skip drops no live decision:
    ///
    /// - `compression` — content coding, not presentation. A replay is
    ///   delivered through the rejection path, where `after_proxy` declines to
    ///   commit a `Content-Encoding` at all, so the skipped transform cannot
    ///   leave a mislabeled body. The retained bytes are self-describing (the
    ///   stored `Content-Encoding` travels with them) and `request_deduplication`
    ///   binds `Accept-Encoding` into the request fingerprint, so a replay only
    ///   ever reaches a client that advertised the stored coding.
    /// - `grpc_web` — protocol framing with no static presentation
    ///   configuration. The translation mode comes entirely from the request
    ///   `Content-Type` (fingerprint-bound) and the response's own trailers,
    ///   which are part of the retained bytes. Its one static knob,
    ///   `expose_headers`, is CORS *header* policy applied in `after_proxy`.
    /// - `ai_response_guard`, `ai_tool_governor` — their current-policy
    ///   inspection re-runs over the replayed bytes and opts a mandatory
    ///   transform back in through `requires_replay_response_body_transform`,
    ///   failing closed when it cannot rewrite. Newly configured redaction is
    ///   therefore applied to a replay under the *live* policy, which is
    ///   strictly stronger than proving a stored digest still matches.
    ///
    /// The `Dynamic` case is `compression`/`grpc_web`'s opposite: neither of
    /// those has any interior mutable state that shapes a body (their atomics
    /// are instance counters and metrics), so exclusion stays sound.
    fn response_presentation_policy(&self) -> Option<ResponsePresentationPolicy> {
        None
    }

    /// Returns `true` when this plugin defines deterministic response-header
    /// policy that must be enforced on protocol-specific initial response
    /// boundaries as well as the ordinary `after_proxy` path.
    ///
    /// The plugin cache uses this marker to pre-filter a priority-ordered list;
    /// request paths must not rediscover these plugins with name checks or scans.
    fn is_initial_response_header_policy(&self) -> bool {
        false
    }

    /// Apply this plugin's deterministic policy to an initial response header
    /// map. Called only for plugins that opt in through
    /// [`Self::is_initial_response_header_policy`]. Implementations must not
    /// consume request-local state or perform I/O.
    fn apply_initial_response_header_policy(
        &self,
        _response_headers: &mut HashMap<String, String>,
    ) {
    }

    /// Canonical field names this initial-response policy may set or remove.
    /// The plugin cache unions these at reload time so buffered protocol paths
    /// track only relevant fields and never scan the plugin chain per request.
    fn initial_response_header_policy_names(&self) -> &[String] {
        &[]
    }

    /// Returns `true` when this plugin may change the response `Content-Type`
    /// in `after_proxy` for the current request.
    ///
    /// `response_content_type` is the backend's `Content-Type` — the value the
    /// downgrade would otherwise key off. Plugins that relabel only *some*
    /// backend types should consult it so the gate matches their `after_proxy`
    /// exactly: a plugin that rewrites a non-SSE type to `text/event-stream`
    /// must return `false` when the backend already sent `text/event-stream`,
    /// otherwise an unbounded stream is pinned to the buffered path and
    /// collected until the max-response-body limit 502s it.
    ///
    /// The proxy uses this as a safety gate before content-type-aware
    /// buffer-to-stream downgrades. If a later `after_proxy` hook can relabel a
    /// response from a non-inspectable type to an inspectable one, body
    /// inspection plugins must keep the buffered path selected by the
    /// pre-flight decision.
    fn may_modify_response_content_type(
        &self,
        _ctx: &RequestContext,
        _response_content_type: Option<&str>,
    ) -> bool {
        false
    }

    /// Returns `true` when this plugin may add a `Cache-Control:
    /// no-transform` response directive in a later `after_proxy` hook.
    ///
    /// Compression uses this to avoid committing `Content-Encoding` before a
    /// later response-header plugin marks the final representation as
    /// no-transform.
    fn may_add_response_cache_control_no_transform(
        &self,
        _ctx: &RequestContext,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        false
    }

    /// Returns `true` when this plugin may add a strong `ETag` response
    /// validator in a later `after_proxy` hook.
    ///
    /// Compression uses this to avoid transforming a representation before a
    /// later response-header plugin attaches a strong validator for the
    /// untransformed bytes.
    fn may_add_response_strong_etag(
        &self,
        _ctx: &RequestContext,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        false
    }

    /// Applies this plugin's deterministic `after_proxy` response-header
    /// mutations to a simulated header map.
    ///
    /// The proxy uses this for preflight decisions that need to reason about
    /// later header hooks without actually running plugin side effects early.
    /// Implementations MUST keep this pure with respect to the real request:
    /// the caller passes a cloned context when mutation is needed to mirror
    /// runtime consumption of route overrides.
    fn simulate_after_proxy_response_headers(
        &self,
        _ctx: &mut RequestContext,
        _response_headers: &mut HashMap<String, String>,
    ) {
    }

    /// Returns `true` when this plugin reads
    /// `ferrum:later_no_transform_response` from request metadata before
    /// committing response headers.
    ///
    /// The proxy uses this to avoid simulating later response-header hooks for
    /// plugins that cannot act on the result. Compression is the built-in
    /// consumer because it must not commit `Content-Encoding` before a later
    /// hook marks the final representation `Cache-Control: no-transform`.
    fn needs_later_response_cache_control_no_transform(&self) -> bool {
        false
    }

    /// Returns `true` when this plugin reads `ferrum:later_strong_etag_response`
    /// from request metadata before committing response headers.
    ///
    /// Compression is the built-in consumer because it must not commit
    /// `Content-Encoding` before a later hook attaches a strong `ETag`.
    fn needs_later_response_strong_etag(&self) -> bool {
        false
    }

    /// Returns `true` when this plugin can release response body buffering if a
    /// later hook will add a strong `ETag`.
    fn should_release_response_body_for_later_strong_etag(
        &self,
        _ctx: &RequestContext,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        false
    }

    /// Returns `true` if this plugin should also run its `after_proxy`
    /// header decoration logic for gateway-generated rejection responses.
    ///
    /// Intended for response-header plugins like CORS, tracing propagation,
    /// and correlation IDs. Plugins that rely on a real backend response
    /// should leave the default `false`.
    fn applies_after_proxy_on_reject(&self) -> bool {
        false
    }

    /// Returns `true` when a [`PluginResult::Reject`] from this plugin's
    /// reject-path [`Self::after_proxy`] hook must replace the still-uncommitted
    /// response.
    ///
    /// Most reject-path hooks only decorate headers and retain the historical
    /// ignore-on-reject behavior. Fail-closed enforcement plugins may opt in at
    /// the shared finalizer, before any response bytes are sent.
    fn may_replace_rejection_response(&self) -> bool {
        false
    }

    /// Returns `true` when a successful reject-path response replacement
    /// should emit a warning.
    ///
    /// Fail-closed enforcement plugins should retain the default. A plugin
    /// performing an expected protocol normalization (for example suppressing
    /// a `HEAD` response body without changing its representation) may return
    /// `false`; the replacement is then logged at debug level instead.
    fn warn_on_rejection_response_replacement(&self) -> bool {
        true
    }

    /// Returns `true` when a translated gRPC-Web response must retain the
    /// buffered compatibility view so this plugin can enforce policy against
    /// terminal backend metadata.
    ///
    /// Native gRPC trailers arrive after `after_proxy`. The gRPC-Web buffered
    /// path merges those trailers into the hook-visible response map and then
    /// reconciles policy changes back into the body-framed terminal block.
    /// Plugins that enforce header policy over that compatibility view should
    /// opt in here. The shared response decision consults this only for a
    /// request already claimed by `grpc_web`, so ordinary HTTP and native gRPC
    /// streaming are unaffected.
    fn requires_buffered_grpc_web_trailer_policy(&self, _ctx: &RequestContext) -> bool {
        false
    }

    /// Returns `true` if this plugin needs the entire response body buffered
    /// in memory before forwarding to the client. When any active plugin
    /// returns `true`, the gateway forces buffered mode for that proxy
    /// regardless of the `response_body_mode` configuration.
    ///
    /// Default is `false` (compatible with streaming). Override this in
    /// plugins that inspect or transform the response body.
    fn requires_response_body_buffering(&self) -> bool {
        false
    }

    /// Returns `true` when the current request's response should be buffered
    /// for this plugin.
    ///
    /// This is the response-side equivalent of `should_buffer_request_body()`:
    /// a per-request refinement that lets plugins skip buffering when the
    /// response is clearly irrelevant (e.g., `compression` skipping when
    /// `Accept-Encoding` is absent, `ai_token_metrics` skipping for non-AI
    /// content-types).
    ///
    /// Only called when `requires_response_body_buffering()` returns `true`
    /// (the config-time upper bound). Override this for content-type-sensitive
    /// or header-sensitive response plugins.
    fn should_buffer_response_body(&self, _ctx: &RequestContext) -> bool {
        self.requires_response_body_buffering()
    }

    /// Returns `true` when this plugin must run the buffered response-body
    /// pipeline for a zero-byte synthetic response.
    ///
    /// Gateway-generated short-circuits normally skip body hooks when their
    /// body is empty. Validators whose contract distinguishes an absent/empty
    /// representation from a valid one can opt in here so the same final-body
    /// policy runs as on an empty buffered backend response. The synthetic
    /// gate calls this only after the plugin's config-time and per-request
    /// buffering predicates both return `true`.
    fn should_process_empty_synthetic_response_body(
        &self,
        _ctx: &RequestContext,
        _response_status: u16,
    ) -> bool {
        false
    }

    /// Returns `true` when this active buffering plugin may release an
    /// inherently streaming response after headers arrive even though retries
    /// are configured.
    ///
    /// The proxy uses this pre-header signal to select a header-first streaming
    /// transport for a retry attempt. After headers arrive, this plugin must
    /// confirm the concrete response and every other active buffering plugin
    /// must report that it does not need that content type. Keep the default
    /// conservative: most response transforms and inspectors require a
    /// replayable body while retries are in flight.
    fn may_release_response_body_under_retries(&self, _ctx: &RequestContext) -> bool {
        false
    }

    /// Header-aware confirmation for
    /// [`may_release_response_body_under_retries`].
    ///
    /// Called only after backend response headers arrive. Returning `true`
    /// allows this response to stream and makes mid-body retry impossible; use
    /// it only for inherently streaming representations whose retry decision is
    /// complete from status and headers.
    fn should_release_response_body_under_retries(
        &self,
        _ctx: &RequestContext,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        false
    }

    /// Returns `true` when a plugin that otherwise buffers this response can
    /// release it before the proxy applies the conservative content-type relabel
    /// guard.
    ///
    /// Only use this for response-header invariants that make buffering
    /// unnecessary independent of the final `Content-Type` (for example range
    /// or `Cache-Control: no-transform` responses for compression). Returning
    /// `false` keeps the existing content-type guard behavior.
    fn should_release_response_body_before_content_type_rewrite(
        &self,
        _ctx: &RequestContext,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        false
    }

    /// Returns `true` when this plugin can release a buffered response because
    /// a later `after_proxy` hook will add `Cache-Control: no-transform`.
    ///
    /// This is narrower than
    /// [`should_release_response_body_before_content_type_rewrite`]: the proxy
    /// has already established that a later hook can mark the final
    /// representation as no-transform, and asks only whether that invariant
    /// makes this plugin's buffered transform unnecessary.
    fn should_release_response_body_for_later_no_transform(
        &self,
        _ctx: &RequestContext,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        false
    }

    /// Content-type-aware refinement of [`should_buffer_response_body`].
    ///
    /// Evaluated once per response *after* the backend response headers arrive,
    /// so plugins that only need the body for certain content-types (e.g. `waf`
    /// skipping non-allowlisted/binary bodies) can release a response the proxy
    /// would otherwise buffer and then immediately discard. The response
    /// `Content-Type` is unknown at the pre-flight `should_buffer_response_body`
    /// decision, which is why this is a separate hook.
    ///
    /// The full `response_headers` map (and `response_status`) are also passed so
    /// the refinement can account for representation metadata beyond
    /// `Content-Type`. A plugin can release a response it will decline to
    /// transform once headers are known — e.g. `compression` skips `206 Partial
    /// Content` / `Content-Range` responses, so it must not pin them onto the
    /// buffered path either. Conversely, a buffered final hook that must decode
    /// or reject a non-identity `Content-Encoding` must keep that representation
    /// buffered; releasing opaque wire bytes would bypass the final hook.
    ///
    /// Contract: this MUST only narrow `should_buffer_response_body` — it may
    /// return `false` where the unconditional check returned `true`, but never
    /// the reverse. The proxy uses it solely to downgrade buffer -> stream and
    /// never to force buffering. The default returns the content-type-agnostic
    /// decision, so plugins that do not override it are unchanged.
    ///
    /// [`should_buffer_response_body`]: Plugin::should_buffer_response_body
    fn should_buffer_response_body_for_content_type(
        &self,
        ctx: &RequestContext,
        _content_type: Option<&str>,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        self.should_buffer_response_body(ctx)
    }

    /// Normalize a buffered provider/protocol-native response into the
    /// client-visible representation before response guardrails inspect it.
    ///
    /// This is a distinct lifecycle phase from `transform_response_body`: use it
    /// only for representation adapters whose output is the contract consumed by
    /// downstream policy plugins (for example Anthropic SSE to OpenAI SSE).
    /// Ordinary presentation transforms remain in `transform_response_body`,
    /// after `on_response_body`. Return `Some(new_body)` to replace the body.
    async fn normalize_response_body_with_context(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _body: &[u8],
        _content_type: Option<&str>,
        _response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        None
    }

    /// Called after the full response body has been received from the backend.
    ///
    /// Only invoked when `requires_response_body_buffering()` returns `true` for
    /// at least one active plugin on the proxy. Plugins that need to inspect,
    /// validate, or cache the response body should override this method.
    ///
    /// The body bytes are the normalized backend response body (after
    /// `normalize_response_body_with_context`, before ordinary response
    /// transformation). The response_status and response_headers are the values
    /// after the `after_proxy` phase. `response_headers` is mutable so a plugin
    /// may refresh client-visible headers after body inspection (for example
    /// `ai_rate_limiter` rewriting `x-ai-ratelimit-usage` / `remaining` after
    /// usage reconciliation). The proxy records deadline provenance for each
    /// completed Continue so those mutations survive a later deadline rebuild.
    ///
    /// Returning `PluginResult::Reject` replaces the buffered response with the
    /// rejection body/status before it reaches the client (useful for enforcing
    /// API response contracts).
    async fn on_response_body(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &mut HashMap<String, String>,
        _body: &[u8],
    ) -> PluginResult {
        PluginResult::Continue
    }

    /// Transform the request body before it is sent to the backend.
    ///
    /// Called after `before_proxy` hooks, only when `modifies_request_body()`
    /// returns `true` for at least one active plugin. The body bytes are the
    /// raw request body collected from the client.
    ///
    /// Return `Some(new_body)` to replace the body, or `None` to leave it
    /// unchanged. The `content_type` parameter is extracted from the request
    /// headers so plugins can decide whether to parse the body. The full
    /// `request_headers` map is also available for plugins that need other
    /// headers (e.g., `content-encoding` for decompression).
    async fn transform_request_body(
        &self,
        _body: &[u8],
        _content_type: Option<&str>,
        _request_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        None
    }

    /// Context-aware variant of `transform_request_body`.
    ///
    /// Existing plugins can keep overriding `transform_request_body`. Plugins
    /// that need to use decisions or metadata from earlier hooks can override
    /// this method and the proxy will call it when a mutable request context is
    /// available.
    async fn transform_request_body_with_context(
        &self,
        _ctx: &mut RequestContext,
        body: &[u8],
        content_type: Option<&str>,
        request_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        self.transform_request_body(body, content_type, request_headers)
            .await
    }

    /// Called after all `transform_request_body` hooks on buffered requests.
    ///
    /// Use this hook when the plugin must inspect or validate the final
    /// backend-visible request body after all request transformations have run.
    async fn on_final_request_body(
        &self,
        _headers: &HashMap<String, String>,
        _body: &[u8],
    ) -> PluginResult {
        PluginResult::Continue
    }

    /// Context-aware variant of `on_final_request_body`.
    ///
    /// Existing plugins can keep overriding `on_final_request_body`. Plugins
    /// that need to annotate request metadata after request body transforms
    /// can override this hook and the proxy will call it instead.
    ///
    /// **Contract on the H1/H2 path**: `ctx` is a lightweight clone built by
    /// [`RequestContext::clone_for_final_request_body_hooks`]; only
    /// `ctx.metadata` is copied back to the real request context after the
    /// hook returns. Mutations to other fields (`ctx.headers`,
    /// `ctx.query_params`, `ctx.route_override_*`, …) on H1/H2 are dropped.
    /// On the H3 path the hook receives the real `&mut RequestContext`, so
    /// implementations MUST limit observable side effects to `ctx.metadata`
    /// if they want consistent behavior across protocols.
    async fn on_final_request_body_with_context(
        &self,
        _ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        self.on_final_request_body(headers, body).await
    }

    /// Returns true when `on_final_request_body_with_context` needs the real
    /// mutable request context rather than the compatibility wrapper.
    fn needs_final_request_body_context(&self) -> bool {
        false
    }

    /// Returns true when the final request-body hook is a terminal dispatch
    /// boundary and must run before backend-only circuit-breaker, egress,
    /// admission, pool, or TLS work. When backend-path policy is active, the
    /// selected path is authorized and deferred `before_proxy` hooks finish
    /// before this terminal hook may perform external dispatch.
    ///
    /// This is narrower than [`Plugin::needs_final_request_body_context`]. It
    /// is intended for plugins such as provider federators that consume the
    /// finalized HTTP request body, perform their own external dispatch, and
    /// return the complete client response from the hook. Ordinary validators
    /// should keep the default so fail-fast backend gates can reject without
    /// first draining a client upload.
    fn requires_final_request_body_before_backend_dispatch(&self) -> bool {
        false
    }

    /// Transform the response body before it is sent to the client.
    ///
    /// Called after `on_response_body` hooks, only for buffered responses
    /// when `requires_response_body_buffering()` returns `true`. The body
    /// bytes are the raw backend response body.
    ///
    /// Return `Some(new_body)` to replace the body, or `None` to leave it
    /// unchanged. The `content_type` parameter is extracted from the response
    /// headers so plugins can decide whether to parse the body. The full
    /// `response_headers` map is also available for plugins that need other
    /// headers (e.g., `content-encoding` for compression).
    async fn transform_response_body(
        &self,
        _body: &[u8],
        _content_type: Option<&str>,
        _response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        None
    }

    /// Context-aware variant of `transform_response_body`.
    ///
    /// Existing plugins can keep overriding `transform_response_body`. Plugins
    /// that need to use decisions or metadata from earlier response hooks can
    /// override this method and the proxy will call it when a mutable request
    /// context is available.
    async fn transform_response_body_with_context(
        &self,
        _ctx: &mut RequestContext,
        body: &[u8],
        content_type: Option<&str>,
        response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        self.transform_response_body(body, content_type, response_headers)
            .await
    }

    /// Whether this plugin has a configured body policy that claims authority
    /// over this response's bytes.
    ///
    /// Returning `true` is a security claim, not a capability advertisement: it
    /// asserts that the operator configured this plugin to rewrite or redact
    /// bodies like this one, so the gateway must not serve the response unless
    /// the policy was genuinely applied. The shared representation gate
    /// (`response_representation`) uses this to decide whether an encoded,
    /// partial, or non-parseable representation is an ordinary pass-through or a
    /// fail-closed rejection.
    ///
    /// Return `false` whenever the configured policy would decline this response
    /// anyway (no rules configured, a runtime kill-switch disabled the scope, or
    /// the media type is outside the policy's document model). Claiming a
    /// response the policy would not have touched converts benign traffic into
    /// errors; failing to claim one it would have touched reopens the bypass.
    ///
    /// `response_content_type` is the live `Content-Type`, matching what
    /// [`Plugin::transform_response_body_with_context`] will receive.
    ///
    /// `response_body` is the byte string the enforcer will actually be handed —
    /// the decoded identity representation once the gate has decoded one, the
    /// wire bytes otherwise. It is supplied because media type and request
    /// flavor are not always sufficient evidence: a gRPC/gRPC-Web request whose
    /// response carries NO `Content-Type` at all is either framed gRPC (which no
    /// JSON field rule can act on) or a bare JSON error/envelope document (which
    /// a configured redaction must still cover), and only the bytes distinguish
    /// them. Implementations must decide structurally — a total parse such as
    /// [`crate::plugins::grpc_web::bytes_are_complete_grpc_frames`], run against
    /// the grammar that
    /// [`crate::plugins::grpc_web::client_grpc_framing_representation`] selects
    /// for this request rather than the union of every gRPC representation —
    /// never by sniffing a prefix.
    fn enforces_response_body_policy(
        &self,
        _ctx: &RequestContext,
        _response_content_type: Option<&str>,
        _response_body: &[u8],
    ) -> bool {
        false
    }

    /// Whether this plugin may make [`Plugin::enforces_response_body_policy`]
    /// return `true` for the current request.
    ///
    /// The response lifecycle consults this before `after_proxy`, when neither
    /// the final live `Content-Type` nor the response body is known, to decide
    /// whether it must retain gateway-header provenance for a possible
    /// representation rejection. It is therefore a CAPABILITY question and must
    /// OVER-approximate: answering `false` for a request whose claim later turns
    /// out to be `true` means the rejection sheds gateway decorators (CORS,
    /// security, correlation headers) that had already been applied.
    ///
    /// The default probes the untyped, empty-bodied response shape, which is an
    /// under-approximation for any plugin whose claim depends on the media type
    /// or the bytes. Such plugins MUST override this predicate with one that
    /// depends only on configuration and request state.
    fn may_enforce_response_body_policy(&self, ctx: &RequestContext) -> bool {
        self.enforces_response_body_policy(ctx, None, &[])
    }

    /// Whether this plugin's response inspection just determined that its
    /// transform is required to make an already-finalized response replay
    /// (`response_caching` HIT/REVALIDATED or `request_deduplication` replay)
    /// safe under current policy.
    ///
    /// Ordinary presentation transforms do not run twice over replayed bytes.
    /// A plugin returning true here is therefore making a fail-closed security
    /// claim: its transform must return replacement bytes before delivery. As
    /// with every response-body hook, the plugin must also advertise response
    /// buffering through `requires_response_body_buffering()`.
    fn requires_replay_response_body_transform(&self, _ctx: &RequestContext) -> bool {
        false
    }

    /// Called immediately after this plugin returns a transformed response
    /// body, after the core removes stale representation metadata and before
    /// the next body transform runs.
    ///
    /// Use this to attach validators, integrity digests, or other headers the
    /// plugin recomputed for its replacement bytes. The hook is not called when
    /// the transform returns `None`, so unchanged responses retain their
    /// original headers.
    fn on_response_body_transformed(
        &self,
        _ctx: &mut RequestContext,
        _response_headers: &mut HashMap<String, String>,
    ) {
    }

    /// Called after all `transform_response_body` hooks on buffered responses.
    ///
    /// Use this hook when the plugin must inspect or act on the final
    /// client-visible response body, such as for outbound validation,
    /// post-transform size checks, or caching the transformed payload.
    async fn on_final_response_body(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
        _body: &[u8],
    ) -> PluginResult {
        PluginResult::Continue
    }

    /// Returns `true` when this plugin needs the observe-only committed response
    /// hook for buffered responses.
    ///
    /// The plugin cache precomputes this capability so requests pay only a bit
    /// test when no exporter needs the hook.
    fn requires_response_committed_hook(&self) -> bool {
        false
    }

    /// Observes the final client-visible buffered response after every
    /// `on_final_response_body` hook and any resulting rejection replacement.
    ///
    /// This hook cannot mutate or reject the response. Exporters should keep
    /// fail-closed admission checks in an earlier rejecting hook, then construct
    /// and enqueue records here so status and body describe what the client will
    /// receive.
    async fn on_response_committed(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
        _body: &[u8],
    ) {
    }

    /// Called exactly once when a streamed, non-buffered response body reaches a
    /// terminal state.
    ///
    /// Unlike `on_response_body` / `on_final_response_body`, this hook does not
    /// receive body bytes and cannot replace the response. It exists for plugins
    /// that hold per-request state across streaming responses and need the same
    /// terminal signal the proxy uses for deferred logging/accounting. The
    /// mutable context is the write-back point for aggregate results captured by
    /// an inspector: metadata written here is copied into the final
    /// [`TransactionSummary`] before `log` runs. This is distinct from
    /// [`ResponseStreamInspector`] chunk inspection: it cannot inspect, forward,
    /// or truncate body bytes.
    async fn on_response_stream_terminated(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _outcome: &crate::proxy::deferred_log::BodyOutcome,
    ) {
    }

    /// Called for transaction logging.
    ///
    /// Buffered HTTP-family handlers normally await each plugin's hook
    /// sequentially before returning the response. When an absolute gRPC
    /// deadline is active, buffered H1/H2 handlers instead move logging to a
    /// bounded detached cleanup task so a blocked sink cannot suppress the
    /// terminal RPC response. Native H3 awaits the hooks after it has
    /// synchronously driven the response body to completion. Hyper-owned
    /// streamed H1/H2/gRPC bodies spawn terminal hooks and logging when the body
    /// completes; spawned work can be lost if no runtime remains during
    /// shutdown. Plugins should hand slow I/O to a bounded, lifecycle-owned
    /// worker rather than awaiting it inline or spawning one unbounded task per
    /// transaction.
    async fn log(&self, _summary: &TransactionSummary) {}

    /// Called for transaction logging with a precomputed mesh RED key when
    /// multiple built-in mesh observability sinks need the same labels.
    async fn log_with_mesh_key(
        &self,
        summary: &TransactionSummary,
        _mesh_key: Option<&crate::plugins::mesh::prometheus_helpers::MeshRequestKey>,
    ) {
        self.log(summary).await;
    }

    /// Returns `true` if this plugin participates in the authentication phase.
    ///
    /// The gateway uses this to filter plugins for the authentication lifecycle
    /// phase, where auth mode (Single vs Multi) determines how failures are
    /// handled. Custom auth plugins should override this to return `true`.
    ///
    /// Default is `false`. Built-in auth plugins (mtls_auth, jwks_auth,
    /// oauth2_introspection, oidc_relying_party, jwt_auth, key_auth, ldap_auth,
    /// basic_auth, hmac_auth) override this to return `true`.
    fn is_auth_plugin(&self) -> bool {
        false
    }

    /// Returns the challenge advertised when the full authentication chain
    /// completes without a credential or identity. The first configured auth
    /// plugin that supplies a challenge wins; direct plugin rejections retain
    /// their own response headers.
    fn authentication_challenge(&self) -> Option<&'static str> {
        None
    }

    /// Stages runtime-owned background work after the complete plugin-cache
    /// generation has validated and before it is published. Constructors must
    /// remain pure because offline validation invokes them without a runtime.
    ///
    /// Fallible producer/client construction, secret resolution, and channel
    /// construction belong here. Workers capable of externally visible writes,
    /// exports, replay, or live-state mutation must stay dormant — gated on
    /// [`Self::commit_background_tasks`] — so a generation that later fails
    /// registry/cache commit has no such side effects. Read-only discovery or
    /// refresh workers may stage earlier when their implementation documents
    /// that lifecycle. Implementations must be idempotent; dropping an
    /// uncommitted instance must cancel every staged worker it owns.
    fn start_background_tasks(&self) -> Result<(), String> {
        Ok(())
    }

    /// Releases staged workers and publishes process-global runtime state after
    /// the complete plugin-cache generation has been atomically installed.
    /// Implementations must be infallible and idempotent: all fallible setup
    /// belongs in [`Self::start_background_tasks`].
    fn commit_background_tasks(&self) {}

    /// Returns `true` if this plugin participates in the authorization phase.
    ///
    /// The gateway uses this to pre-filter authorize callbacks at config
    /// reload time when a plugin can safely declare it has no authorization
    /// work. The default stays `true` so existing custom plugins that already
    /// override `authorize()` keep running after upgrade.
    fn is_authorize_plugin(&self) -> bool {
        true
    }

    /// Returns hostnames that this plugin will send traffic to.
    ///
    /// Used during DNS warmup to pre-resolve plugin endpoint hostnames
    /// alongside proxy backend hostnames, avoiding cold-cache DNS lookups
    /// on the first request through the plugin.
    ///
    /// Default implementation returns an empty list (most plugins make no
    /// outbound network calls). Override this if your plugin has a configured
    /// endpoint URL (e.g., http_logging, jwks_auth JWKS endpoints).
    fn warmup_hostnames(&self) -> Vec<String> {
        Vec::new()
    }

    /// Returns the set of proxy protocols this plugin supports.
    ///
    /// The gateway uses this to filter plugins per proxy based on its protocol.
    /// For example, CORS only applies to HTTP, while ip_restriction works on all
    /// protocols. Plugins are skipped for protocols they don't support.
    ///
    /// Default is HTTP-only.
    /// Use the protocol constants (`ALL_PROTOCOLS`, `HTTP_FAMILY_PROTOCOLS`, etc.)
    /// for common patterns.
    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        HTTP_ONLY_PROTOCOLS
    }

    /// Returns the number of tracked rate-limit keys, if applicable.
    ///
    /// Only meaningful for stateful plugins that track per-key counters
    /// (e.g., rate_limiting). Returns `None` by default.
    fn tracked_keys_count(&self) -> Option<usize> {
        None
    }

    /// Called when a new stream connection (TCP/UDP session) is established.
    ///
    /// Returning `PluginResult::Reject` closes the connection immediately.
    /// Plugins can insert metadata (e.g., correlation ID) into `ctx.metadata`
    /// which is carried through to `on_stream_disconnect`.
    async fn on_stream_connect(&self, _ctx: &mut StreamConnectionContext) -> PluginResult {
        PluginResult::Continue
    }

    /// Called when a stream connection (TCP/UDP session) is completed.
    async fn on_stream_disconnect(&self, _summary: &StreamTransactionSummary) {}

    /// Returns `true` if this plugin needs per-frame WebSocket inspection.
    /// Zero overhead when `false` (default) — the frame forwarding loop skips plugins entirely.
    fn requires_ws_frame_hooks(&self) -> bool {
        false
    }

    /// Returns `true` when this plugin only observes WebSocket frame decisions
    /// and never mutates or rejects them.
    ///
    /// After an earlier admission/mutating `on_ws_frame` hook returns a
    /// terminal `Message::Close`, the shared H1/H2/H3 relay keeps invoking
    /// observational hooks with that already-final Close so they can record
    /// the decision, while skipping later mutating plugins so they neither
    /// charge budget nor replace the Close code/reason.
    /// The relay ignores the return value from an observational hook for every
    /// frame, enforcing the observe-only contract even if an implementation
    /// accidentally returns a replacement.
    fn observes_ws_frame_decisions(&self) -> bool {
        false
    }

    /// Optional parser-level WebSocket size policy.
    ///
    /// Implementations must return immutable construction-time values. The
    /// shared H1/H2/H3 relay evaluates this once per upgraded connection and
    /// applies the strictest values before reading frames from either peer.
    fn websocket_size_limits(&self) -> Option<WebSocketSizeLimits> {
        None
    }

    /// Returns `true` when this plugin requires the parsed WebSocket relay.
    ///
    /// Parser-policy plugins automatically opt out of raw tunnel mode even if
    /// they do not need the post-reassembly [`Plugin::on_ws_frame`] hook.
    fn requires_websocket_framing(&self) -> bool {
        self.requires_ws_frame_hooks() || self.websocket_size_limits().is_some()
    }

    /// Called for each complete WebSocket message when a plugin opts in.
    ///
    /// Tungstenite reassembles Text/Binary continuation frames before this
    /// hook. Plugins that require actual wire-frame enforcement must contribute
    /// parser policy through [`Plugin::websocket_size_limits`] instead.
    ///
    /// `connection_id` is a unique per-connection identifier (monotonic counter) that
    /// stateful plugins (e.g., ws_rate_limiting) can use to track per-connection state.
    ///
    /// Return `Some(message)` to replace the frame, `None` to pass through unchanged.
    /// Returning `Some(Message::Close(...))` will close the WebSocket in both directions.
    ///
    /// The first terminal Close from a priority-ordered admission/mutating hook
    /// is preserved for the rest of the chain: later mutating plugins are not
    /// invoked for that frame, and observational hooks
    /// ([`Plugin::observes_ws_frame_decisions`]) may still see the final Close.
    ///
    /// Delivery-accurate frame logging must use
    /// [`Plugin::prepare_ws_frame_delivery`] /
    /// [`Plugin::emit_ws_frame_delivery`] instead of emitting from this hook:
    /// this chain runs before the control-frame guard and before the destination
    /// sink accepts the write.
    async fn on_ws_frame(
        &self,
        _proxy_id: &str,
        _connection_id: u64,
        _direction: WebSocketFrameDirection,
        _message: &tokio_tungstenite::tungstenite::Message,
    ) -> Option<tokio_tungstenite::tungstenite::Message> {
        None
    }

    /// Prepare a deferred delivery observation from the final post-plugin,
    /// post-control-guard message **before** the destination `send()` moves it.
    ///
    /// Return `Some` only when this plugin will emit after a successful sink
    /// accept. The relay discards prepared observations on cancel/write failure
    /// so frame logs share the success-only boundary with `frames_*` /
    /// `bytes_*` counters. Default: no observation.
    fn prepare_ws_frame_delivery(
        &self,
        _message: &tokio_tungstenite::tungstenite::Message,
    ) -> Option<WsFrameDeliveryObservation> {
        None
    }

    /// Emit a previously prepared delivery observation after the destination
    /// sink accepted the frame. Must not mutate protocol state.
    fn emit_ws_frame_delivery(
        &self,
        _proxy_id: &str,
        _connection_id: u64,
        _direction: WebSocketFrameDirection,
        _observation: WsFrameDeliveryObservation,
    ) {
    }

    /// Returns `true` if this plugin needs per-chunk inspection of *streaming*
    /// (non-buffered) HTTP response bodies — e.g. windowed inspection of an SSE
    /// LLM completion. Zero overhead when `false` (default): the proxy's
    /// streaming pipeline skips the hook path entirely, and `PluginCache`
    /// precomputes an O(1) per-proxy flag from this so unrelated proxies never
    /// pay. Distinct from response-body buffering — a plugin that inspects a
    /// stream window-by-window does **not** buffer the whole body.
    fn requires_response_stream_hooks(&self) -> bool {
        false
    }

    /// Run this plugin's stream-termination hook after ordinary termination
    /// hooks, while preserving relative priority order within each group.
    ///
    /// Terminal observers that aggregate metadata from peer plugins use this
    /// to see the final request context before the transaction summary is
    /// cloned. This affects only the post-body terminal path, never request,
    /// response, or inspector ordering.
    fn defers_response_stream_termination_until_after_peers(&self) -> bool {
        false
    }

    /// Called once after the final response headers select a streaming body,
    /// before those headers are committed. Unlike
    /// [`Self::response_stream_inspector`], this notification also runs for
    /// direct H2/H3 transports that cannot attach a chunk inspector.
    fn on_response_stream_selected(
        &self,
        _ctx: &RequestContext,
        _response_status: u16,
        _content_type: Option<&str>,
    ) {
    }

    /// Create a stateful [`ResponseStreamInspector`] for a streaming (non-buffered)
    /// response body, or `None` to stream it through unchanged. Called once per
    /// eligible response for **every** plugin that opts in via
    /// [`Self::requires_response_stream_hooks`] (the proxy chains the returned
    /// inspectors, so multiple stream-inspecting plugins compose); the plugin
    /// decides applicability from `ctx`, the response `response_status`, and the
    /// `content_type` (e.g. only inspect a 2xx `text/event-stream`, matching how
    /// [`Self::on_response_body`] only inspects success responses).
    ///
    /// Returning an inspector is how a plugin generalizes the [`Self::on_ws_frame`]
    /// model to HTTP response streams: the proxy then drives the inspector
    /// chunk-by-chunk. The inspector **owns** its window/accumulator state, so it
    /// works both inside the async H3 loop and inside the detached task that
    /// drives the poll-based H1/H2 channel body (which cannot borrow `ctx`).
    fn response_stream_inspector(
        &self,
        _ctx: &RequestContext,
        _response_status: u16,
        _content_type: Option<&str>,
    ) -> Option<Box<dyn ResponseStreamInspector>> {
        None
    }

    /// Returns `true` if THIS request should prefer the reqwest streaming path
    /// over a native backend transport. Every streaming dispatch arm drives
    /// response inspectors, so this is an optimization (for example to avoid a
    /// transport-specific bridge), not the inspection correctness boundary.
    /// Evaluated from the finalized request context immediately before backend
    /// dispatch, so body-transform markers are visible. Zero overhead when no
    /// response-stream plugin is configured or this returns `false` (default).
    fn forces_reqwest_dispatch(&self, _ctx: &RequestContext) -> bool {
        false
    }

    /// Returns `true` if this plugin needs per-datagram UDP inspection.
    /// Zero overhead when `false` (default) — the datagram forwarding path skips plugins entirely.
    fn requires_udp_datagram_hooks(&self) -> bool {
        false
    }

    /// Returns `true` if this plugin needs the opening client bytes of a
    /// plain/passthrough TCP stream captured into
    /// `StreamConnectionContext.first_bytes` before `on_stream_connect` runs.
    /// These are obtained with a non-destructive peek, so the splice fast path
    /// is preserved. Zero overhead when `false` (default) — the proxy skips the
    /// capture entirely.
    fn requires_stream_first_bytes(&self) -> bool {
        false
    }

    /// Returns `true` if this plugin needs the opening *decrypted* application
    /// bytes of a TLS-terminating TCP frontend captured into
    /// `StreamConnectionContext.first_bytes` before `on_stream_connect` runs.
    ///
    /// Separate from [`Self::requires_stream_first_bytes`] because recovering
    /// decrypted bytes requires a *consuming* read that blocks until the client
    /// sends data and disables the kTLS-splice fast path. That cost is only
    /// worth paying when the bytes will actually be inspected (e.g. signature
    /// matching) — not for transport-shape guards (`tcp_require_tls`) that the
    /// completed TLS handshake already satisfies. Returning `true` here for a
    /// guard-only config would needlessly stall server-first protocols.
    fn requires_stream_first_bytes_decrypted(&self) -> bool {
        false
    }

    /// The smallest number of opening client bytes this plugin needs captured
    /// into [`StreamConnectionContext::first_bytes`] before it can classify a
    /// plain/passthrough TCP stream. A transport-shape guard that inspects the
    /// leading TLS record header, for example, needs the whole header present —
    /// not just the first byte the socket happens to deliver.
    ///
    /// The TCP proxy keeps peeking (non-destructively, so the splice fast path
    /// stays intact) until at least this many bytes are buffered or the
    /// handshake deadline expires, so a ClientHello split across TCP segments is
    /// not misread as a short non-TLS chunk and falsely rejected. `0` (default)
    /// means "the first readable chunk is enough" and preserves the single-peek
    /// behavior. Only consulted when [`Self::requires_stream_first_bytes`] is
    /// `true`.
    fn stream_first_bytes_min_len(&self) -> usize {
        0
    }

    /// Returns `true` if this plugin needs notification when a WebSocket
    /// session ends. Zero overhead when `false` (default) — the relay teardown
    /// path skips constructing the context and iterating plugins.
    ///
    /// Mirrors the opt-in pattern used by `requires_ws_frame_hooks()` and
    /// `requires_udp_datagram_hooks()` so most deployments pay no cost.
    fn requires_ws_disconnect_hooks(&self) -> bool {
        false
    }

    /// Called when a WebSocket session (H1 upgrade or H2 Extended CONNECT)
    /// terminates. Receives a summary of the session including directional
    /// failure classification and per-direction frame counts.
    ///
    /// Default no-op. Plugins wanting end-of-session observability should
    /// override this and set `requires_ws_disconnect_hooks()` to `true`.
    async fn on_ws_disconnect(&self, _ctx: &WsDisconnectContext) {}

    /// Returns `true` when this plugin requires HTTP/3 query params to use the
    /// percent-decoded representation. HTTP/3 historically exposed raw query
    /// params to plugins, so this opt-in is intentionally narrow: enabling it
    /// affects the shared `ctx.query_params` map for all plugins on the proxy.
    fn requires_decoded_query_params(&self) -> bool {
        false
    }

    /// Called for each UDP datagram in both directions (client→backend and backend→client).
    ///
    /// Only invoked when at least one plugin on the proxy opts in via
    /// `requires_udp_datagram_hooks()`. Return `UdpDatagramVerdict::Drop` to
    /// silently discard the datagram (standard UDP flood mitigation).
    /// Use `ctx.direction` to distinguish client→backend from backend→client.
    async fn on_udp_datagram(&self, _ctx: &UdpDatagramContext<'_>) -> UdpDatagramVerdict {
        UdpDatagramVerdict::Forward
    }

    /// Returns the JWKS URIs this plugin is actively using.
    ///
    /// Implemented by plugins such as `jwks_auth` and `oidc_relying_party` that
    /// retain shared JWKS stores. Used by the plugin cache to clean up stale
    /// entries (and their background refresh tasks) when plugins are removed.
    fn active_jwks_uris(&self) -> Vec<String> {
        Vec::new()
    }

    /// Returns the refresh interval required for each actively referenced
    /// shared JWKS URI. The plugin cache reconciles duplicate consumers to the
    /// minimum interval after every full or incremental publication.
    fn active_jwks_refresh_requirements(&self) -> Vec<(String, Duration)> {
        Vec::new()
    }
}

/// Create a plugin instance from its name and configuration.
///
/// Uses a default `PluginHttpClient` for plugins that make outbound HTTP calls.
/// Prefer [`create_plugin_with_http_client`] in production to share the gateway's
/// pooled client across all plugins for connection reuse and keepalive.
///
/// Plugins that partition or attribute work by configured identity (notably
/// `request_deduplication`, `waf` anomaly scoring, and `request_mirror`
/// transaction records) should be constructed through
/// [`create_plugin_with_http_client_and_config_id`] with the stable plugin-config
/// resource id. Direct construction here uses a validation-only default
/// identity.
#[allow(dead_code)]
pub fn create_plugin(name: &str, config: &Value) -> Result<Option<Arc<dyn Plugin>>, String> {
    create_plugin_with_http_client(
        name,
        config,
        PluginHttpClient::default().with_process_compression_admission_policy(),
    )
}

/// Create a plugin instance with a shared HTTP client for outbound calls.
///
/// Plugins that make network calls (http_logging, future OTel exporters, webhooks,
/// etc.) will use this shared client, which is configured with the gateway's
/// connection pool settings (keepalive, idle timeout, HTTP/2 multiplexing).
///
/// This ensures all plugin outbound traffic gets proper connection reuse instead
/// of opening a new TCP+TLS connection per call.
///
/// Returns:
/// - `Ok(Some(plugin))` — plugin created successfully
/// - `Ok(None)` — unknown plugin name
/// - `Err(msg)` — plugin config validation failed
///
/// For runtime construction of identity-partitioned plugins, prefer
/// [`create_plugin_with_http_client_and_config_id`].
pub fn create_plugin_with_http_client(
    name: &str,
    config: &Value,
    http_client: PluginHttpClient,
) -> Result<Option<Arc<dyn Plugin>>, String> {
    create_plugin_with_http_client_and_config_id(name, config, http_client, None)
}

/// Create a plugin instance with a shared HTTP client and optional stable
/// plugin-config resource id.
///
/// `plugin_config_id` is the configured plugin-config resource id (global /
/// proxy / proxy_group). Production `PluginCache` passes `Some(&pc.id)` so
/// Redis-backed `request_deduplication` instances partition logical keys by that
/// identity, `waf` instances isolate anomaly-score accumulators / ownership
/// metadata, and `api_chargeback_sink` instances publish accepted-generation
/// status/metrics under that stable identity, while `request_mirror` records
/// attribute each shadow destination. Pass `None` for config-validation and
/// direct/test construction that does not need sibling isolation or attribution
/// (uses the plugin's standalone default id). Blank ids fail closed when
/// supplied.
pub fn create_plugin_with_http_client_and_config_id(
    name: &str,
    config: &Value,
    http_client: PluginHttpClient,
    plugin_config_id: Option<&str>,
) -> Result<Option<Arc<dyn Plugin>>, String> {
    // Fail CLOSED before constructing plugins with literal endpoints. LDAP uses
    // a dedicated fresh, policy-screened dial resolver; kafka_logging and
    // ws_logging dial through their own clients. JWKS uses the shared client but
    // must still reject denied literals at config admission rather than
    // installing a permanently keyless provider.
    // The production `PluginCache` is built with the real-policy client
    // (`proxy/mod.rs` → `PluginHttpClient::new` → `with_http_client`), this also
    // makes a database-mode legacy row pointing at e.g. `169.254.169.254` exclude
    // the plugin instead of letting its background loop reach the metadata service.
    // LDAP repeats this screen at every dial; config admission remains useful for
    // rejecting an invalid literal before the plugin can enter the runtime cache.
    screen_direct_client_endpoint_egress(name, config, http_client.backend_allow_ips())?;
    // Rate limiters partition their default Redis key space by this id so two
    // independent policies of one plugin type in a namespace never share
    // counters (GHSA-gr3x-g777-hm78). Validation/direct construction has no
    // resource id and uses the standalone placeholder.
    let rate_limit_config_id =
        plugin_config_id.unwrap_or(utils::rate_limit::STANDALONE_RATE_LIMIT_CONFIG_ID);
    match name {
        "stdout_logging" => Ok(Some(Arc::new(stdout_logging::StdoutLogging::new(config)?))),
        "transaction_log_schema" => Ok(Some(Arc::new(
            transaction_log_schema::TransactionLogSchema::new(config)?,
        ))),
        "statsd_logging" => Ok(Some(Arc::new(statsd_logging::StatsdLogging::new(
            config,
            http_client.clone(),
        )?))),
        "http_logging" => Ok(Some(Arc::new(http_logging::HttpLogging::new(
            config,
            http_client.clone(),
        )?))),
        "tcp_logging" => Ok(Some(Arc::new(tcp_logging::TcpLogging::new(
            config,
            http_client,
        )?))),
        "ws_logging" => Ok(Some(Arc::new(ws_logging::WsLogging::new(
            config,
            http_client,
        )?))),
        "loki_logging" => Ok(Some(Arc::new(loki_logging::LokiLogging::new(
            config,
            http_client,
        )?))),
        "udp_logging" => Ok(Some(Arc::new(udp_logging::UdpLogging::new(
            config,
            http_client,
        )?))),
        "kafka_logging" => Ok(Some(Arc::new(kafka_logging::KafkaLogging::new(
            config,
            &http_client,
        )?))),
        "transaction_debugger" => Ok(Some(Arc::new(
            transaction_debugger::TransactionDebugger::new(config)?,
        ))),
        "jwks_auth" => Ok(Some(Arc::new(jwks_auth::JwksAuth::new(
            config,
            http_client.clone(),
        )?))),
        "oauth2_introspection" => Ok(Some(Arc::new(
            oauth2_introspection::Oauth2Introspection::new(config, http_client.clone())?,
        ))),
        "oidc_relying_party" => Ok(Some(Arc::new(oidc_relying_party::OidcRelyingParty::new(
            config,
            http_client.clone(),
        )?))),
        "jwt_auth" => Ok(Some(Arc::new(jwt_auth::JwtAuth::new(config)?))),
        "key_auth" => Ok(Some(Arc::new(key_auth::KeyAuth::new(config)?))),
        "basic_auth" => Ok(Some(Arc::new(basic_auth::BasicAuth::new(config)?))),
        "ldap_auth" => Ok(Some(Arc::new(ldap_auth::LdapAuth::new(
            config,
            http_client,
        )?))),
        "hmac_auth" => Ok(Some(Arc::new(hmac_auth::HmacAuth::new(config)?))),
        "mtls_auth" => Ok(Some(Arc::new(mtls_auth::MtlsAuth::new(config)?))),
        "spiffe_identity" => Ok(Some(Arc::new(mesh::spiffe_identity::SpiffeIdentity::new(
            config,
        )?))),
        "compression" => {
            let gzip_enabled = http_client.compression_gzip_enabled();
            let brotli_enabled = http_client.compression_brotli_enabled();
            let max_request_body_size_bytes = http_client.max_request_body_size_bytes();
            let plugin = compression::CompressionPlugin::new_with_algorithm_support_and_body_limit(
                config,
                gzip_enabled,
                brotli_enabled,
                max_request_body_size_bytes,
            )?;
            Ok(Some(Arc::new(plugin)))
        }
        "cors" => Ok(Some(Arc::new(cors::CorsPlugin::new(config)?))),
        "security_headers" => Ok(Some(Arc::new(security_headers::SecurityHeaders::new(
            config,
        )?))),
        "access_control" => Ok(Some(Arc::new(access_control::AccessControl::new(config)?))),
        "tcp_connection_throttle" => Ok(Some(Arc::new(
            tcp_connection_throttle::TcpConnectionThrottle::new_with_pool_shard_amount(
                config,
                http_client.pool_shard_amount(),
            )?,
        ))),
        "adaptive_concurrency" => Ok(Some(Arc::new(
            adaptive_concurrency::AdaptiveConcurrency::new(config, http_client.clone())?,
        ))),
        "mesh_authz" => Ok(Some(Arc::new(mesh::authz::MeshAuthz::new(config)?))),
        "opa" => Ok(Some(Arc::new(opa::Opa::new(config, http_client.clone())?))),
        "mesh_outbound_registry" => Ok(Some(Arc::new(
            mesh::outbound_registry::OutboundRegistry::new(config)?,
        ))),
        "ip_restriction" => Ok(Some(Arc::new(ip_restriction::IpRestriction::new(config)?))),
        "geo_restriction" => Ok(Some(Arc::new(geo_restriction::GeoRestriction::new(
            config,
        )?))),
        "bot_detection" => Ok(Some(Arc::new(bot_detection::BotDetection::new(config)?))),
        "correlation_id" => {
            let plugin = match http_client.real_ip_header() {
                Some(real_ip_header) => correlation_id::CorrelationId::new_with_real_ip_header(
                    config,
                    Some(real_ip_header),
                )?,
                None => correlation_id::CorrelationId::new(config)?,
            };
            Ok(Some(Arc::new(plugin)))
        }
        "request_transformer" => Ok(Some(Arc::new(
            request_transformer::RequestTransformer::new(config)?,
        ))),
        "mesh_route_dispatch" => Ok(Some(Arc::new(mesh_route_dispatch::MeshRouteDispatch::new(
            config,
        )?))),
        "response_transformer" => Ok(Some(Arc::new(
            response_transformer::ResponseTransformer::new(config)?,
        ))),
        "sse" => Ok(Some(Arc::new(sse::SsePlugin::new(config)?))),
        "graphql" => {
            let plugin = graphql::GraphqlPlugin::new_with_config_id(
                config,
                http_client.clone(),
                rate_limit_config_id,
            )?;
            Ok(Some(Arc::new(plugin)))
        }
        "grpc_method_router" => {
            let plugin = grpc_method_router::GrpcMethodRouter::new_with_config_id(
                config,
                http_client.clone(),
                rate_limit_config_id,
            )?;
            Ok(Some(Arc::new(plugin)))
        }
        "grpc_deadline" => Ok(Some(Arc::new(grpc_deadline::GrpcDeadline::new(config)?))),
        "grpc_web" => Ok(Some(Arc::new(grpc_web::GrpcWebPlugin::new(config)?))),
        "rate_limiting" => {
            let plugin = rate_limiting::RateLimiting::new_with_config_id(
                config,
                http_client.clone(),
                rate_limit_config_id,
            )?;
            Ok(Some(Arc::new(plugin)))
        }
        "request_mirror" => Ok(Some(Arc::new(
            request_mirror::RequestMirror::new_with_config_id(
                config,
                http_client.clone(),
                plugin_config_id,
            )?,
        ))),
        "load_testing" => Ok(Some(Arc::new(load_testing::LoadTesting::new(
            config,
            http_client.clone(),
        )?))),
        "request_deduplication" => {
            let plugin = match plugin_config_id {
                Some(config_id) => {
                    request_deduplication::RequestDeduplication::new_with_instance_id(
                        config,
                        http_client.clone(),
                        config_id,
                    )?
                }
                None => {
                    request_deduplication::RequestDeduplication::new(config, http_client.clone())?
                }
            };
            Ok(Some(Arc::new(plugin)))
        }
        "request_size_limiting" => Ok(Some(Arc::new(
            request_size_limiting::RequestSizeLimiting::new(config)?,
        ))),
        "waf" => Ok(Some(Arc::new(waf::Waf::new_with_config_id(
            config,
            plugin_config_id,
        )?))),
        "response_size_limiting" => Ok(Some(Arc::new(
            response_size_limiting::ResponseSizeLimiting::new(config)?,
        ))),
        "body_validator" => Ok(Some(Arc::new(body_validator::BodyValidator::new(config)?))),
        "openapi_validator" => Ok(Some(Arc::new(openapi_validator::OpenapiValidator::new(
            config,
        )?))),
        "soap_ws_security" => Ok(Some(Arc::new(soap_ws_security::SoapWsSecurity::new(
            config,
        )?))),
        "request_termination" => Ok(Some(Arc::new(
            request_termination::RequestTermination::new(config)?,
        ))),
        "response_caching" => Ok(Some(Arc::new(
            response_caching::ResponseCaching::new_with_pool_shard_amount(
                config,
                http_client.pool_shard_amount(),
            )?,
        ))),
        "fault_injection" => Ok(Some(Arc::new(fault_injection::FaultInjectionPlugin::new(
            config,
        )?))),
        "response_mock" => Ok(Some(Arc::new(response_mock::ResponseMock::new(config)?))),
        "serverless_function" => Ok(Some(Arc::new(
            serverless_function::ServerlessFunction::new(config, http_client)?,
        ))),
        "prometheus_metrics" => Ok(Some(Arc::new(prometheus_metrics::PrometheusMetrics::new(
            config,
            http_client.namespace(),
        )?))),
        "proxy_alerts" => Ok(Some(Arc::new(proxy_alerts::ProxyAlerts::new(
            config,
            http_client.clone(),
        )?))),
        "api_chargeback" => Ok(Some(Arc::new(
            api_chargeback::ApiChargeback::new_with_shard_amount(
                config,
                http_client.namespace(),
                http_client.pool_shard_amount(),
            )?,
        ))),
        "api_chargeback_sink" => Ok(Some(Arc::new(
            api_chargeback_sink::ApiChargebackSink::new_with_config_id(
                config,
                http_client.clone(),
                http_client.namespace(),
                plugin_config_id,
            )?,
        ))),
        "otel_tracing" => Ok(Some(Arc::new(
            otel_tracing::OtelTracing::new_with_http_client(config, http_client)?,
        ))),
        "ai_token_metrics" => Ok(Some(Arc::new(ai_token_metrics::AiTokenMetrics::new(
            config,
        )?))),
        "ai_request_guard" => Ok(Some(Arc::new(ai_request_guard::AiRequestGuard::new(
            config,
        )?))),
        "ai_rate_limiter" => {
            let plugin = ai_rate_limiter::AiRateLimiter::new_with_config_id(
                config,
                http_client.clone(),
                rate_limit_config_id,
            )?;
            Ok(Some(Arc::new(plugin)))
        }
        "ai_prompt_shield" => Ok(Some(Arc::new(ai_prompt_shield::AiPromptShield::new(
            config,
        )?))),
        "ai_prompt_compressor" => Ok(Some(Arc::new(
            ai_prompt_compressor::AiPromptCompressor::new(config)?,
        ))),
        "ai_semantic_firewall" => Ok(Some(Arc::new(
            ai_semantic_firewall::AiSemanticFirewall::new(config, http_client.clone())?,
        ))),
        "ai_semantic_cache" => Ok(Some(Arc::new(ai_semantic_cache::AiSemanticCache::new(
            config,
            http_client.clone(),
        )?))),
        "ai_response_guard" => Ok(Some(Arc::new(ai_response_guard::AiResponseGuard::new(
            config,
        )?))),
        "ai_stream_router" => Ok(Some(Arc::new(ai_stream_router::AiStreamRouter::new(
            config,
            http_client.clone(),
        )?))),
        "ai_federation" => Ok(Some(Arc::new(ai_federation::AiFederation::new(
            config,
            http_client.clone(),
        )?))),
        "ai_tool_governor" => Ok(Some(Arc::new(ai_tool_governor::AiToolGovernor::new(
            config,
            http_client.clone(),
        )?))),
        "ai_transcript_audit" => Ok(Some(Arc::new(ai_transcript_audit::AiTranscriptAudit::new(
            config,
            http_client.clone(),
        )?))),
        "mcp_gateway" => Ok(Some(Arc::new(mcp_gateway::McpGateway::new(
            config,
            http_client.clone(),
        )?))),
        "a2a_gateway" => Ok(Some(Arc::new(a2a_gateway::A2aGateway::new(config)?))),
        "ws_message_size_limiting" => Ok(Some(Arc::new(
            ws_message_size_limiting::WsMessageSizeLimiting::new(config)?,
        ))),
        "ws_frame_logging" => Ok(Some(Arc::new(ws_frame_logging::WsFrameLogging::new(
            config,
        )?))),
        "ws_rate_limiting" => {
            let plugin = ws_rate_limiting::WsRateLimiting::new_with_config_id(
                config,
                http_client.clone(),
                rate_limit_config_id,
            )?;
            Ok(Some(Arc::new(plugin)))
        }
        "udp_rate_limiting" => {
            let plugin = udp_rate_limiting::UdpRateLimiting::new_with_config_id(
                config,
                http_client.clone(),
                rate_limit_config_id,
            )?;
            Ok(Some(Arc::new(plugin)))
        }
        "spec_expose" => Ok(Some(Arc::new(spec_expose::SpecExpose::new(
            config,
            http_client,
        )?))),
        "workload_metrics" => Ok(Some(Arc::new(
            mesh::workload_metrics::WorkloadMetrics::new_with_http_client(config, http_client)?,
        ))),
        // GAP-SC3 / GAP-3D: `__mesh_bpf_metrics` is auto-injected on
        // `NodeWaypoint` topology. When the gateway is mesh-mode +
        // node-waypoint, `ProxyState::new` attaches the shared
        // `Arc<BpfMetricsState>` to the `PluginHttpClient`, and the
        // SOCK_OPS ringbuf consumer updates the same Arc. When the slot
        // is empty (every other mode/topology, or a dev build that
        // doesn't run the kernel program), fall back to a fresh
        // unattached state — the plugin still emits a stable Prometheus
        // surface populated by zeros.
        "__mesh_bpf_metrics" => {
            let plugin = match http_client.bpf_metrics_state() {
                Some(state) => mesh::bpf_metrics::MeshBpfMetrics::with_state(config, state)?,
                None => mesh::bpf_metrics::MeshBpfMetrics::new(config)?,
            };
            Ok(Some(Arc::new(plugin)))
        }
        _ => {
            // Reserve retired security-plugin aliases before the custom plugin
            // registry: a custom plugin sharing a retired name (e.g.
            // `semantic_ai_firewall`) must not silently instantiate and bypass
            // the fail-closed handling, which only fires on `Ok(None)` in
            // `plugin_cache::try_create_plugin`. Returning `Ok(None)` here routes
            // the retired name to that fatal fail-closed path regardless of any
            // custom plugin registered under the same name.
            if removed_plugin_registration(name).is_some() {
                return Ok(None);
            }
            // Fall through to custom plugins registry
            let result = crate::custom_plugins::create_custom_plugin(name, config, http_client)?;
            if result.is_none() {
                tracing::warn!("Unknown plugin: {}", name);
            }
            Ok(result)
        }
    }
}

/// Built-in plugins that the request-body-buffering screen must never
/// construct, because their constructors reach node-local state that a
/// config-admission screen has no business touching:
///
/// - `geo_restriction` opens the configured MaxMind `.mmdb` database,
/// - `udp_logging` opens node-local DTLS key material,
/// - `oidc_relying_party` performs OIDC discovery / JWKS work and retains
///   background refresh state.
///
/// None of them can ever require request-body buffering, so the screen answers
/// [`RequestBodyBufferingScreen::Streams`] for them without construction. That
/// claim is not free-floating: the drift coverage in
/// `tests/unit/plugins/request_body_buffering_screen_tests.rs` fails if any
/// entry here ever gains a buffering-related `Plugin` override, and fails if a
/// new shape-only carve-out appears in
/// [`validate_plugin_config_with_http_client`] without being classified here or
/// in [`REQUEST_BODY_BUFFERING_SCREEN_SHAPE_ONLY`].
pub const REQUEST_BODY_BUFFERING_SCREEN_NO_CONSTRUCT: &[&str] =
    &["geo_restriction", "oidc_relying_party", "udp_logging"];

/// Built-in plugins the screen constructs through a shape-only path instead of
/// the ordinary factory.
///
/// `body_validator`'s runtime constructor reads the configured protobuf
/// `FileDescriptorSet` off local disk. Its shape-only constructor parses the
/// same config and derives the identical `has_request_validation` flag (the
/// protobuf request/response *targets* come from the config shape, not from the
/// descriptor file), so `Plugin::requires_request_body_buffering()` on the
/// shape-only instance is the authoritative runtime answer.
pub const REQUEST_BODY_BUFFERING_SCREEN_SHAPE_ONLY: &[&str] = &["body_validator"];

/// Why the request-body-buffering screen could not evaluate a plugin config.
///
/// Deliberately value-free: the variants classify the gap without echoing any
/// configuration value back into logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestBodyBufferingScreenGap {
    /// Not a built-in plugin — a `custom_plugins/` build-time plugin, or an
    /// unknown / retired name. The screen refuses to instantiate third-party
    /// constructors during config admission.
    NotBuiltin,
    /// A built-in plugin whose configuration did not construct. The
    /// configuration is rejected on its own merits by plugin-config validation;
    /// the buffering question is simply unanswerable here.
    ConstructionFailed,
}

impl RequestBodyBufferingScreenGap {
    /// Stable, value-redacted reason token for structured diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotBuiltin => "plugin is not a built-in plugin",
            Self::ConstructionFailed => "plugin configuration did not construct",
        }
    }
}

/// Result of the config-time request-body-buffering screen for one plugin
/// config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestBodyBufferingScreen {
    /// The constructed plugin reports
    /// `Plugin::requires_request_body_buffering() == true`.
    Buffers,
    /// The constructed plugin reports
    /// `Plugin::requires_request_body_buffering() == false`.
    Streams,
    /// The screen could not evaluate this plugin config.
    Indeterminate(RequestBodyBufferingScreenGap),
}

impl RequestBodyBufferingScreen {
    fn from_trait_answer(buffers: bool) -> Self {
        if buffers {
            Self::Buffers
        } else {
            Self::Streams
        }
    }
}

/// Side-effect-free screen for "does this plugin config force request-body
/// buffering", derived from the authoritative
/// [`Plugin::requires_request_body_buffering`] implementation.
///
/// Backend-TLS SNI admission uses this: plain HTTPS SNI overrides require the
/// direct-H2 pool, which cannot dispatch when request bodies are pre-buffered.
/// The screen builds a plugin instance from the SAME parsed configuration the
/// runtime `PluginCache` builds and asks the same trait method, so there is no
/// second implementation of "which plugins buffer" to drift out of sync.
///
/// Construction here is deliberately inert:
///
/// - the plugin is dropped immediately and never enters a cache, so no
///   candidate state is published,
/// - `Plugin::start_background_tasks()` is never called, which is where every
///   built-in defers its workers, timers, spool files, and registry
///   publication,
/// - the node-local / networked constructors are carved out entirely
///   ([`REQUEST_BODY_BUFFERING_SCREEN_NO_CONSTRUCT`]) or routed through their
///   existing shape-only constructor
///   ([`REQUEST_BODY_BUFFERING_SCREEN_SHAPE_ONLY`]),
/// - custom (`custom_plugins/`) and unknown names are never instantiated.
///
/// The HTTP client carries a default-open egress policy on purpose: the screen
/// asks a buffering question, and endpoint egress admission is owned by
/// [`validate_plugin_config_with_policy`]. Screening must not invent a
/// rejection for an unrelated policy reason.
pub struct RequestBodyBufferingScreener {
    http_client: PluginHttpClient,
}

impl Default for RequestBodyBufferingScreener {
    fn default() -> Self {
        Self::new()
    }
}

impl RequestBodyBufferingScreener {
    /// Build a screener. The client construction is the same one
    /// [`create_plugin`] uses, so a plugin whose construction depends on
    /// process-wide compression admission resolves identically here and at
    /// config-load validation.
    pub fn new() -> Self {
        Self {
            http_client: PluginHttpClient::default().with_process_compression_admission_policy(),
        }
    }

    /// Screen one plugin config.
    pub fn screen(&self, plugin_name: &str, config: &Value) -> RequestBodyBufferingScreen {
        if REQUEST_BODY_BUFFERING_SCREEN_NO_CONSTRUCT.contains(&plugin_name) {
            return RequestBodyBufferingScreen::Streams;
        }
        if REQUEST_BODY_BUFFERING_SCREEN_SHAPE_ONLY.contains(&plugin_name) {
            return Self::screen_shape_only(plugin_name, config);
        }
        if !is_builtin_plugin_name(plugin_name) {
            return RequestBodyBufferingScreen::Indeterminate(
                RequestBodyBufferingScreenGap::NotBuiltin,
            );
        }
        let client = self.http_client.clone();
        match create_plugin_with_http_client(plugin_name, config, client) {
            // The instance is dropped right here: nothing is published and
            // `Plugin::start_background_tasks()` is never called.
            Ok(Some(plugin)) => {
                let buffers = plugin.requires_request_body_buffering();
                RequestBodyBufferingScreen::from_trait_answer(buffers)
            }
            // A registered built-in that yields `None` is a retired/fail-closed
            // alias; treat it like any other unanswerable name.
            Ok(None) => {
                RequestBodyBufferingScreen::Indeterminate(RequestBodyBufferingScreenGap::NotBuiltin)
            }
            // The constructor message can echo configured values, so it is
            // deliberately dropped here — plugin-config validation surfaces the
            // detailed error on its own path.
            Err(_) => RequestBodyBufferingScreen::Indeterminate(
                RequestBodyBufferingScreenGap::ConstructionFailed,
            ),
        }
    }

    /// Screen a plugin listed in [`REQUEST_BODY_BUFFERING_SCREEN_SHAPE_ONLY`]
    /// through its shape-only constructor.
    fn screen_shape_only(plugin_name: &str, config: &Value) -> RequestBodyBufferingScreen {
        let answer = match plugin_name {
            "body_validator" => body_validator::BodyValidator::new_shape_only(config)
                .map(|plugin| plugin.requires_request_body_buffering()),
            // Unreachable today. A name added to the shape-only list without a
            // branch here must fail unanswerable rather than be silently
            // mis-screened as non-buffering; the drift test also fails.
            _ => {
                return RequestBodyBufferingScreen::Indeterminate(
                    RequestBodyBufferingScreenGap::ConstructionFailed,
                );
            }
        };
        match answer {
            Ok(buffers) => RequestBodyBufferingScreen::from_trait_answer(buffers),
            Err(_) => RequestBodyBufferingScreen::Indeterminate(
                RequestBodyBufferingScreenGap::ConstructionFailed,
            ),
        }
    }
}

/// Validate a plugin configuration by attempting to instantiate the plugin,
/// with a default-open egress policy.
///
/// Most plugin instances are created and immediately dropped. Plugins with
/// persistent constructor side effects use a dedicated shape-only validation
/// path instead.
///
/// Production config-load paths (file/db/admin/spec) use
/// [`validate_plugin_config_with_policy`] so a plugin's literal-IP endpoints
/// are screened against the configured backend egress policy. This bare
/// variant remains a `pub` entrypoint for external test crates that only need
/// shape validation of endpoint-less plugins (e.g. `cors`,
/// `transaction_log_schema`). `#[allow(dead_code)]` because the binary target
/// recompiles the source without those test crates, so it sees no caller.
///
/// Returns `Ok(())` if the config is valid, `Err(msg)` if validation fails.
#[allow(dead_code)]
pub fn validate_plugin_config(name: &str, config: &Value) -> Result<(), String> {
    validate_plugin_config_with_http_client(
        name,
        config,
        PluginHttpClient::default().with_process_compression_admission_policy(),
    )
}

/// Validate a plugin configuration with a caller-supplied HTTP policy without
/// retaining runtime workers. OIDC discovery/JWKS construction is explicitly
/// shape-only here so admin validation and config admission cannot leak retry
/// tasks that outlive the temporary instance.
pub(crate) fn validate_plugin_config_with_http_client(
    name: &str,
    config: &Value,
    http_client: PluginHttpClient,
) -> Result<(), String> {
    if name == "geo_restriction" {
        return geo_restriction::GeoRestriction::validate_config(config);
    }
    if name == "body_validator" {
        // Shape-only: CP/admin admission must not require descriptor files
        // installed on data-plane nodes. Mode-aware dependency validation and
        // runtime construction handle the local FileDescriptorSet.
        return body_validator::BodyValidator::validate_config(config);
    }
    if name == "udp_logging" {
        // Shape-only: shared Admin / CP validation must not open node-local
        // DTLS paths. Mode-aware dependency validation and construction do.
        return udp_logging::UdpLogging::validate_config(config, http_client);
    }
    if name == "oidc_relying_party" {
        screen_direct_client_endpoint_egress(name, config, http_client.backend_allow_ips())?;
        return oidc_relying_party::OidcRelyingParty::validate_config(config, http_client);
    }
    match create_plugin_with_http_client(name, config, http_client)? {
        Some(_) => Ok(()),
        None => Err(format!("Unknown plugin name '{}'", name)),
    }
}

/// Like [`validate_plugin_config`] but screens any literal-IP plugin endpoint
/// (AI provider, log sink, webhook) against the configured backend egress
/// policy, so file/db config-load validation rejects e.g.
/// `http://169.254.169.254/...` the same way runtime plugin construction does
/// — instead of accepting (and a CP distributing) a config a data plane later
/// rejects.
pub fn validate_plugin_config_with_policy(
    name: &str,
    config: &Value,
    backend_allow_ips: &crate::config::BackendEgressPolicy,
) -> Result<(), String> {
    let http_client = PluginHttpClient::default_with_backend_allow_ips(backend_allow_ips.clone())
        .with_real_ip_header(crate::config::env_config::resolve_real_ip_header())
        .with_process_compression_admission_policy();
    validate_plugin_config_with_http_client(name, config, http_client)?;
    validate_plugin_config_policy_only(name, config, backend_allow_ips)
}

/// Apply admission-policy checks that live outside plugin construction.
///
/// Prospective named-schema validation constructs `schema_ref` consumers while
/// an isolated schema registry is staged. Callers therefore skip a second full
/// construction after that bracket is aborted, but must still apply these
/// policy-only checks so an unrelated plugin cannot add an ignored
/// `schema_ref` key to bypass egress admission.
pub(crate) fn validate_plugin_config_policy_only(
    name: &str,
    config: &Value,
    backend_allow_ips: &crate::config::BackendEgressPolicy,
) -> Result<(), String> {
    // The HTTP-endpoint screen above does not cover a plugin's own
    // literal-IP backend fields that aren't dialed through the shared
    // client (mesh_route_dispatch route destinations).
    if name == "mesh_route_dispatch"
        && let Err(errs) = screen_mesh_route_dispatch_egress(config, backend_allow_ips)
    {
        return Err(errs.join("; "));
    }
    // Redis-backed plugins (rate_limit / request_deduplication /
    // ai_semantic_cache with sync_mode=redis) build their client from
    // `redis_url` WITHOUT the egress policy, and the client skips literals
    // / falls back to the hostname on a DNS denial — so a denied literal
    // endpoint must be rejected here at config-load.
    screen_redis_endpoint_egress(config, backend_allow_ips)?;
    // NOTE: ldap_auth / kafka_logging / ws_logging literal endpoints are
    // screened *inside* `create_plugin_with_http_client` above (before a dial),
    // so no explicit `screen_direct_client_endpoint_egress` call is needed
    // here. LDAP additionally repeats the policy check at dial time.
    Ok(())
}

/// Screen a `mesh_route_dispatch` plugin's per-rule `destination.backend_host`
/// literal IPs against the backend egress policy. A route override can point a
/// matched request at an arbitrary backend, so a denied address (e.g.
/// `169.254.169.254`) must be rejected at config-admission time — not only in
/// Screen a Redis-backed plugin's `redis_url` literal-IP host against the egress
/// policy at config-load. Redis-backed plugins (`rate_limit`,
/// `request_deduplication`, `ai_semantic_cache` with `sync_mode=redis`) build
/// their client from `redis_url` WITHOUT the policy, and the client skips IP
/// literals / falls back to the hostname on a DNS denial — so a denied literal
/// endpoint (`redis://169.254.169.254:6379`) would otherwise be dialed. No-op
/// when there is no `redis_url`, it's a hostname (screened at resolve), or it
/// doesn't parse (shape errors are surfaced by the constructor).
pub(crate) fn screen_redis_endpoint_egress(
    config: &Value,
    backend_allow_ips: &crate::config::BackendEgressPolicy,
) -> Result<(), String> {
    let Some(redis_url) = config.get("redis_url").and_then(|v| v.as_str()) else {
        return Ok(());
    };
    let Ok(parsed) = url::Url::parse(redis_url) else {
        return Ok(());
    };
    if let Some(host) = parsed.host_str() {
        let bare = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        if let Ok(ip) = bare.parse::<std::net::IpAddr>()
            && let Some(reason) = backend_allow_ips.deny_reason(&ip)
        {
            return Err(format!(
                "redis_url IP {ip} denied by backend egress policy: {reason}"
            ));
        }
    }
    Ok(())
}

/// Screen literal-IP endpoints that require config-admission enforcement.
/// `jwks_auth` retains the shared client's runtime DNS/IP backstop, and
/// `ldap_auth` (`ldap_url`) has a dedicated dial-time resolver/backstop.
/// `kafka_logging` (`broker_list`, via librdkafka) and `ws_logging` dial outside
/// the shared resolver. A denied literal endpoint must still be rejected at
/// config-load so file/admin/DB/CP-DP admission is consistent with runtime.
///
/// LDAP and `ws_logging` hostnames are freshly resolved and screened
/// immediately before every connection/reconnection, and only screened
/// addresses are dialed. `kafka_logging` cannot reach that bar with the pinned
/// librdkafka client and is therefore refused outright under any policy that
/// can deny an address (see `kafka_logging::screen_kafka_broker_list_egress`).
/// JWKS hostname resolution keeps the shared client's runtime policy backstop.
pub(crate) fn screen_direct_client_endpoint_egress(
    name: &str,
    config: &Value,
    backend_allow_ips: &crate::config::BackendEgressPolicy,
) -> Result<(), String> {
    match name {
        // JWKS endpoints use the shared client (which keeps a runtime DNS/IP
        // backstop), but literal denials must fail config admission before a
        // provider can become permanently keyless and reject all tokens.
        "jwks_auth" => {
            if let Some(providers) = config.get("providers").and_then(Value::as_array) {
                for (provider_idx, provider) in providers.iter().enumerate() {
                    let Some(provider) = provider.as_object() else {
                        continue;
                    };
                    for field in ["jwks_uri", "discovery_url"] {
                        if let Some(url) = provider.get(field).and_then(Value::as_str)
                            && let Ok(parsed) = url::Url::parse(url.trim())
                            && let Some(host) = parsed.host_str()
                            && let Some(ip) = crate::config::types::egress_literal_ip(host)
                            && let Some(reason) = backend_allow_ips.deny_reason(&ip)
                        {
                            return Err(format!(
                                "providers[{provider_idx}].{field} IP {ip} denied by backend egress policy: {reason}"
                            ));
                        }
                    }
                }
            }
        }
        // ldap_url is a single ldap:// / ldaps:// URL.
        "ldap_auth" => {
            if let Some(url) = config.get("ldap_url").and_then(|v| v.as_str())
                && let Ok(parsed) = url::Url::parse(url.trim())
                && let Some(host) = parsed.host_str()
                && let Some(ip) = crate::config::types::egress_literal_ip(host)
                && let Some(reason) = backend_allow_ips.deny_reason(&ip)
            {
                return Err(format!(
                    "ldap_url IP {ip} denied by backend egress policy: {reason}"
                ));
            }
        }
        // broker_list is parsed with the pinned librdkafka grammar
        // (`[proto://]host[:port]`, comma separated) so protocol-prefixed
        // literals are screened too, and kafka_logging is refused outright when
        // the policy can deny addresses librdkafka would dial without Ferrum
        // ever seeing them (bootstrap hostname resolution, metadata-advertised
        // brokers). See `kafka_logging::screen_kafka_broker_list_egress`.
        "kafka_logging" => {
            kafka_logging::screen_kafka_broker_list_egress(config, backend_allow_ips)?;
        }
        // endpoint_url is a single ws:// / wss:// URL; ws_logging dials it via
        // tokio_tungstenite outside the shared client + DnsCache.
        "ws_logging" => {
            if let Some(url) = config.get("endpoint_url").and_then(|v| v.as_str())
                && let Ok(parsed) = url::Url::parse(url.trim())
                && let Some(host) = parsed.host_str()
                && let Some(ip) = crate::config::types::egress_literal_ip(host)
                && let Some(reason) = backend_allow_ips.deny_reason(&ip)
            {
                return Err(format!(
                    "endpoint_url IP {ip} denied by backend egress policy: {reason}"
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

/// whole-config validation but on direct/batch admin plugin writes too.
/// Returns prefix-free messages; no-op for configs that don't parse as
/// mesh_route_dispatch (shape errors are surfaced by the constructor).
pub fn screen_mesh_route_dispatch_egress(
    config: &Value,
    backend_allow_ips: &crate::config::BackendEgressPolicy,
) -> Result<(), Vec<String>> {
    let Ok(dispatch_config) =
        crate::plugins::mesh_route_dispatch::MeshRouteDispatchConfig::from_value_normalized(config)
    else {
        return Ok(());
    };
    let mut errors = Vec::new();
    for (rule_idx, rule) in dispatch_config.rules.iter().enumerate() {
        if let Some(host) = rule.destination.backend_host.as_deref()
            && let Some(ip) = crate::config::types::egress_literal_ip(host)
            && let Some(reason) = backend_allow_ips.deny_reason(&ip)
        {
            errors.push(format!(
                "mesh_route_dispatch.rules[{rule_idx}].destination.backend_host IP {ip} denied by backend egress policy: {reason}"
            ));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Removed built-in plugins that were historically security-sensitive.
///
/// These names are intentionally fail-closed during config load so upgrades
/// cannot silently drop authentication/authorization protections.
pub const REMOVED_PLUGIN_REGISTRATIONS: &[PluginRegistration] = &[
    builtin_plugin("oauth2_auth", PluginFailurePolicy::FailClosed),
    builtin_plugin("semantic_ai_firewall", PluginFailurePolicy::FailClosed),
];

/// Built-in plugin factory registrations, excluding build-time custom plugins.
pub const BUILTIN_PLUGIN_REGISTRATIONS: &[PluginRegistration] = &[
    builtin_plugin(
        "transaction_log_schema",
        PluginFailurePolicy::KeepLastKnownGood,
    ),
    builtin_plugin("stdout_logging", PluginFailurePolicy::OptionalFailOpen),
    builtin_plugin("http_logging", PluginFailurePolicy::OptionalFailOpen),
    builtin_plugin("tcp_logging", PluginFailurePolicy::KeepLastKnownGood),
    builtin_plugin("kafka_logging", PluginFailurePolicy::KeepLastKnownGood),
    builtin_plugin("ws_logging", PluginFailurePolicy::KeepLastKnownGood),
    builtin_plugin(
        "transaction_debugger",
        PluginFailurePolicy::OptionalFailOpen,
    ),
    builtin_plugin("jwks_auth", PluginFailurePolicy::FailClosed),
    builtin_plugin("oauth2_introspection", PluginFailurePolicy::FailClosed),
    builtin_plugin("oidc_relying_party", PluginFailurePolicy::FailClosed),
    builtin_plugin("jwt_auth", PluginFailurePolicy::FailClosed),
    builtin_plugin("key_auth", PluginFailurePolicy::FailClosed),
    builtin_plugin("basic_auth", PluginFailurePolicy::FailClosed),
    builtin_plugin("ldap_auth", PluginFailurePolicy::FailClosed),
    builtin_plugin("hmac_auth", PluginFailurePolicy::FailClosed),
    builtin_plugin("mtls_auth", PluginFailurePolicy::FailClosed),
    builtin_plugin("spiffe_identity", PluginFailurePolicy::FailClosed),
    builtin_plugin("mesh_authz", PluginFailurePolicy::FailClosed),
    builtin_plugin("opa", PluginFailurePolicy::FailClosed),
    builtin_plugin("mesh_outbound_registry", PluginFailurePolicy::FailClosed),
    builtin_plugin("compression", PluginFailurePolicy::KeepLastKnownGood),
    builtin_plugin("cors", PluginFailurePolicy::FailClosed),
    builtin_plugin("security_headers", PluginFailurePolicy::FailClosed),
    builtin_plugin("access_control", PluginFailurePolicy::FailClosed),
    builtin_plugin("tcp_connection_throttle", PluginFailurePolicy::FailClosed),
    builtin_plugin("adaptive_concurrency", PluginFailurePolicy::FailClosed),
    builtin_plugin("ip_restriction", PluginFailurePolicy::FailClosed),
    builtin_plugin("bot_detection", PluginFailurePolicy::FailClosed),
    builtin_plugin("correlation_id", PluginFailurePolicy::KeepLastKnownGood),
    builtin_plugin(
        "request_transformer",
        PluginFailurePolicy::KeepLastKnownGood,
    ),
    builtin_plugin(
        "response_transformer",
        PluginFailurePolicy::KeepLastKnownGood,
    ),
    builtin_plugin("mesh_route_dispatch", PluginFailurePolicy::FailClosed),
    builtin_plugin("graphql", PluginFailurePolicy::FailClosed),
    builtin_plugin("grpc_method_router", PluginFailurePolicy::FailClosed),
    builtin_plugin("grpc_deadline", PluginFailurePolicy::FailClosed),
    builtin_plugin("grpc_web", PluginFailurePolicy::KeepLastKnownGood),
    builtin_plugin("rate_limiting", PluginFailurePolicy::FailClosed),
    builtin_plugin("request_size_limiting", PluginFailurePolicy::FailClosed),
    builtin_plugin("waf", PluginFailurePolicy::FailClosed),
    builtin_plugin("response_size_limiting", PluginFailurePolicy::FailClosed),
    builtin_plugin("body_validator", PluginFailurePolicy::FailClosed),
    builtin_plugin("openapi_validator", PluginFailurePolicy::FailClosed),
    builtin_plugin("request_termination", PluginFailurePolicy::FailClosed),
    builtin_plugin("response_caching", PluginFailurePolicy::KeepLastKnownGood),
    builtin_plugin("response_mock", PluginFailurePolicy::KeepLastKnownGood),
    builtin_plugin(
        "serverless_function",
        PluginFailurePolicy::KeepLastKnownGood,
    ),
    builtin_plugin("prometheus_metrics", PluginFailurePolicy::OptionalFailOpen),
    builtin_plugin("proxy_alerts", PluginFailurePolicy::OptionalFailOpen),
    builtin_plugin("otel_tracing", PluginFailurePolicy::OptionalFailOpen),
    builtin_plugin("ai_token_metrics", PluginFailurePolicy::OptionalFailOpen),
    builtin_plugin("ai_request_guard", PluginFailurePolicy::FailClosed),
    builtin_plugin("ai_rate_limiter", PluginFailurePolicy::FailClosed),
    builtin_plugin("ai_prompt_shield", PluginFailurePolicy::FailClosed),
    builtin_plugin(
        "ai_prompt_compressor",
        PluginFailurePolicy::KeepLastKnownGood,
    ),
    builtin_plugin("ai_semantic_firewall", PluginFailurePolicy::FailClosed),
    builtin_plugin("ai_response_guard", PluginFailurePolicy::FailClosed),
    builtin_plugin("ai_tool_governor", PluginFailurePolicy::FailClosed),
    builtin_plugin("ai_semantic_cache", PluginFailurePolicy::KeepLastKnownGood),
    builtin_plugin("ai_stream_router", PluginFailurePolicy::FailClosed),
    builtin_plugin("ai_federation", PluginFailurePolicy::KeepLastKnownGood),
    // Privacy/fail-closed sink policy typos must not silently drop the audit
    // instance (OptionalFailOpen) or publish an incomplete cache. Reject the
    // candidate generation so callers keep the last-known-good plugin cache.
    // Runtime fail-closed capture remains the explicit
    // `sink.on_sink_error` / `sink.on_buffer_full` = `reject` config.
    builtin_plugin(
        "ai_transcript_audit",
        PluginFailurePolicy::KeepLastKnownGood,
    ),
    builtin_plugin("mcp_gateway", PluginFailurePolicy::FailClosed),
    builtin_plugin("a2a_gateway", PluginFailurePolicy::FailClosed),
    builtin_plugin("ws_message_size_limiting", PluginFailurePolicy::FailClosed),
    builtin_plugin("ws_frame_logging", PluginFailurePolicy::OptionalFailOpen),
    builtin_plugin("ws_rate_limiting", PluginFailurePolicy::FailClosed),
    builtin_plugin("udp_rate_limiting", PluginFailurePolicy::FailClosed),
    builtin_plugin("udp_logging", PluginFailurePolicy::OptionalFailOpen),
    builtin_plugin("statsd_logging", PluginFailurePolicy::OptionalFailOpen),
    builtin_plugin("loki_logging", PluginFailurePolicy::OptionalFailOpen),
    builtin_plugin("sse", PluginFailurePolicy::KeepLastKnownGood),
    builtin_plugin("request_mirror", PluginFailurePolicy::KeepLastKnownGood),
    builtin_plugin("load_testing", PluginFailurePolicy::KeepLastKnownGood),
    builtin_plugin("geo_restriction", PluginFailurePolicy::FailClosed),
    builtin_plugin("request_deduplication", PluginFailurePolicy::FailClosed),
    builtin_plugin("soap_ws_security", PluginFailurePolicy::FailClosed),
    builtin_plugin("spec_expose", PluginFailurePolicy::KeepLastKnownGood),
    builtin_plugin("api_chargeback", PluginFailurePolicy::KeepLastKnownGood),
    builtin_plugin(
        "api_chargeback_sink",
        PluginFailurePolicy::KeepLastKnownGood,
    ),
    builtin_plugin("workload_metrics", PluginFailurePolicy::OptionalFailOpen),
    builtin_plugin("__mesh_bpf_metrics", PluginFailurePolicy::OptionalFailOpen),
    builtin_plugin("fault_injection", PluginFailurePolicy::KeepLastKnownGood),
];

// Keep documentation/parity inventory linked in both the library crate (consumed
// by integration tests) and the binary crate (same sources, separate compilation).
// Length equality is a cheap compile-time guard; name set-equality remains in tests.
const _: () = {
    assert!(BUILTIN_PLUGIN_PARITY_META.len() == BUILTIN_PLUGIN_REGISTRATIONS.len());
    let _: fn(&str) -> Option<&'static BuiltinPluginParityMeta> = builtin_plugin_parity_meta;
    let _: BuiltinPluginClassification = BuiltinPluginClassification::Public;
};

pub fn builtin_plugin_registration(name: &str) -> Option<&'static PluginRegistration> {
    BUILTIN_PLUGIN_REGISTRATIONS
        .iter()
        .find(|registration| registration.name == name)
}

pub fn removed_plugin_registration(name: &str) -> Option<&'static PluginRegistration> {
    REMOVED_PLUGIN_REGISTRATIONS
        .iter()
        .find(|registration| registration.name == name)
}

pub fn plugin_failure_policy(name: &str) -> Option<PluginFailurePolicy> {
    builtin_plugin_registration(name)
        .map(|registration| registration.failure_policy)
        .or_else(|| {
            removed_plugin_registration(name).map(|registration| registration.failure_policy)
        })
        .or_else(|| crate::custom_plugins::custom_plugin_failure_policy(name))
}

/// Returns true when `name` is handled by the built-in plugin factory.
pub fn is_builtin_plugin_name(name: &str) -> bool {
    builtin_plugin_registration(name).is_some()
}

pub fn available_plugins() -> Vec<&'static str> {
    let mut plugins: Vec<_> = BUILTIN_PLUGIN_REGISTRATIONS
        .iter()
        .map(|registration| registration.name)
        .collect();
    plugins.extend(crate::custom_plugins::custom_plugin_names());
    plugins
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn upstream_override_reprojects_resolved_tls_from_snapshot() {
        let mut proxy: Proxy = serde_json::from_value(json!({
            "backend_host": "stable.svc",
            "backend_port": 8080,
            "upstream_id": "stable",
        }))
        .expect("minimal proxy should deserialize");
        proxy.resolved_tls = BackendTlsConfig {
            client_cert_path: Some("/certs/stable.pem".to_string()),
            client_key_path: Some("/certs/stable.key".to_string()),
            server_ca_cert_path: Some("/certs/stable-ca.pem".to_string()),
            verify_server_cert: true,
            sni: None,
            san_allow_list: Vec::new(),
            san_allow_list_key_digest: None,
        };

        let canary: Upstream = serde_json::from_value(json!({
            "id": "canary",
            "targets": [{"host": "canary.svc", "port": 9090}],
            "backend_tls_client_cert_path": "/certs/canary.pem",
            "backend_tls_client_key_path": "/certs/canary.key",
            "backend_tls_server_ca_cert_path": "/certs/canary-ca.pem",
            "backend_tls_verify_server_cert": false,
        }))
        .expect("minimal upstream should deserialize");
        let mut upstreams = HashMap::new();
        upstreams.insert("canary".to_string(), Arc::new(canary));

        let mut ctx =
            RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
        ctx.route_override_upstream_id = Some("canary".to_string());

        let result = ctx.apply_route_overrides_with_upstreams(Arc::new(proxy), &upstreams);
        assert_eq!(result.upstream_id.as_deref(), Some("canary"));
        assert_eq!(
            result.resolved_tls.client_cert_path.as_deref(),
            Some("/certs/canary.pem")
        );
        assert_eq!(
            result.resolved_tls.client_key_path.as_deref(),
            Some("/certs/canary.key")
        );
        assert_eq!(
            result.resolved_tls.server_ca_cert_path.as_deref(),
            Some("/certs/canary-ca.pem")
        );
        assert!(!result.resolved_tls.verify_server_cert);
    }

    #[test]
    fn upstream_override_recomputes_dispatch_port_override_fallback() {
        // codex r1 #1806 finding 1: a route override that swaps the destination
        // upstream must recompute the SD top-level `connectionPool.http`
        // fallback from the NEW upstream — picking up the new destination's
        // fallback, never leaking the old one.
        use crate::config::types::UpstreamPortOverride;

        // Source proxy points at SD upstream `stable` which carries no top-level
        // overlay; assert the override TO `canary` picks up canary's overlay.
        let proxy: Proxy = serde_json::from_value(json!({
            "backend_host": "stable.svc",
            "backend_port": 8080,
            "upstream_id": "stable",
        }))
        .expect("minimal proxy should deserialize");

        let mut canary: Upstream = serde_json::from_value(json!({
            "id": "canary",
            "targets": [{"host": "canary.svc", "port": 9090}],
        }))
        .expect("minimal upstream should deserialize");
        // SD top-level overlay (serde-skipped field, set directly).
        canary.dispatch_port_override_fallback = Some(UpstreamPortOverride {
            http1_max_pending_requests: Some(16),
            h2_max_concurrent_streams: Some(64),
            ..Default::default()
        });
        let mut upstreams = HashMap::new();
        upstreams.insert("canary".to_string(), Arc::new(canary));

        let mut ctx =
            RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
        ctx.route_override_upstream_id = Some("canary".to_string());

        let result = ctx.apply_route_overrides_with_upstreams(Arc::new(proxy), &upstreams);
        assert_eq!(result.upstream_id.as_deref(), Some("canary"));
        let fallback = result
            .dispatch_port_override_fallback
            .as_ref()
            .expect("override TO an SD upstream must pick up that upstream's fallback");
        assert_eq!(fallback.http1_max_pending_requests, Some(16));
        assert_eq!(fallback.h2_max_concurrent_streams, Some(64));
    }

    #[test]
    fn upstream_override_clears_fallback_when_new_upstream_has_none() {
        // codex r1 #1806 finding 1 (no-leak): a proxy carrying an SD fallback
        // routed TO a different upstream WITHOUT one must have it CLEARED — the
        // old upstream's overlay must not leak onto the new destination.
        let mut proxy: Proxy = serde_json::from_value(json!({
            "backend_host": "stable.svc",
            "backend_port": 8080,
            "upstream_id": "stable",
        }))
        .expect("minimal proxy should deserialize");
        // The referencing proxy already carries `stable`'s projected fallback.
        proxy.dispatch_port_override_fallback = Some(crate::config::types::ResolvedPortOverride {
            http1_max_pending_requests: Some(99),
            ..Default::default()
        });

        // `plain` has no top-level overlay.
        let plain: Upstream = serde_json::from_value(json!({
            "id": "plain",
            "targets": [{"host": "plain.svc", "port": 9090}],
        }))
        .expect("minimal upstream should deserialize");
        let mut upstreams = HashMap::new();
        upstreams.insert("plain".to_string(), Arc::new(plain));

        let mut ctx =
            RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
        ctx.route_override_upstream_id = Some("plain".to_string());

        let result = ctx.apply_route_overrides_with_upstreams(Arc::new(proxy), &upstreams);
        assert_eq!(result.upstream_id.as_deref(), Some("plain"));
        assert!(
            result.dispatch_port_override_fallback.is_none(),
            "routing to an upstream without a fallback must CLEAR the inherited one (no leak)"
        );
    }

    #[test]
    fn direct_backend_override_clears_dispatch_port_override_fallback() {
        // codex r1 #1806 finding 1: a direct-backend override (no upstream)
        // must clear the SD fallback, mirroring how it clears
        // `dispatch_port_overrides`.
        let mut proxy: Proxy = serde_json::from_value(json!({
            "backend_host": "stable.svc",
            "backend_port": 8080,
            "upstream_id": "stable",
        }))
        .expect("minimal proxy should deserialize");
        proxy.dispatch_port_override_fallback = Some(crate::config::types::ResolvedPortOverride {
            max_retries: Some(3),
            ..Default::default()
        });

        let mut ctx =
            RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
        ctx.route_override_backend_host = Some("direct.svc".to_string());

        let result = ctx.apply_route_overrides_with_upstreams(Arc::new(proxy), &HashMap::new());
        assert_eq!(result.upstream_id, None);
        assert!(
            result.dispatch_port_override_fallback.is_none(),
            "a direct-backend override must clear the SD fallback"
        );
    }

    #[test]
    fn direct_backend_override_clears_inherited_dns_override_when_host_changes() {
        let mut proxy: Proxy = serde_json::from_value(json!({
            "backend_host": "stable.svc",
            "backend_port": 8080,
        }))
        .expect("minimal proxy should deserialize");
        proxy.dns_override = Some("192.0.2.10".to_string());

        let mut ctx =
            RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
        ctx.route_override_backend_host = Some("api.openai.com".to_string());
        ctx.route_override_backend_port = Some(443);

        let result = ctx.apply_route_overrides_with_upstreams(Arc::new(proxy), &HashMap::new());
        assert_eq!(result.backend_host, "api.openai.com");
        assert_eq!(result.backend_port, 443);
        assert!(
            result.dns_override.is_none(),
            "a direct-backend host override must not inherit the original proxy dns_override"
        );
    }

    #[test]
    fn absolute_route_override_path_disables_listen_path_stripping() {
        let proxy: Proxy = serde_json::from_value(json!({
            "backend_host": "stable.svc",
            "backend_port": 8080,
            "listen_path": "/mcp",
            "backend_path": "/placeholder",
            "strip_listen_path": true
        }))
        .expect("minimal proxy should deserialize");

        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/mcp".to_string(),
        );
        ctx.route_override_path = Some("/mcp".to_string());
        ctx.route_override_path_is_absolute = true;

        let result = ctx.apply_route_overrides(Arc::new(proxy));
        assert!(!result.strip_listen_path);
        assert_eq!(result.backend_path, None);
    }
}

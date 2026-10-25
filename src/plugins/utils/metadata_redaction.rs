//! Central redaction for sensitive metadata keys before log serialization.
//!
//! Plugins (built-in or custom) can write arbitrary key/value pairs into
//! `TransactionSummary.metadata` and `StreamTransactionSummary.metadata`.
//! Without redaction, anything they put there — auth tokens, cookies, session
//! IDs, credential tokens — flows verbatim through every logging sink
//! (stdout, http, tcp, kafka, loki, udp, ws, statsd). That has bitten us
//! before with `transaction_debugger.rs` (which only redacts request HEADERS).
//!
//! This module is the single redaction layer. Both summary serializers delegate
//! their `metadata` field here, so every logger that serializes a summary gets
//! the same sanitized output and a new logger cannot bypass redaction by
//! choosing a different sink.
//!
//! Matching is case-insensitive against:
//!   * a built-in default list (`DEFAULT_SENSITIVE_METADATA_KEYS`);
//!   * an operator-extensible list parsed once from
//!     `FERRUM_LOG_REDACT_METADATA_KEYS` (comma-separated).
//!
//! Matching strategy: most built-in keys use substring-on-lowercased-key, so a
//! key like `request_authorization_header` redacts because it contains
//! `authorization`. Token and API-key concepts use per-segment classifiers so
//! delimiter forms (`api_key`, `api-key`), concatenated forms (`apikey`), and
//! acronym camelCase (`APIKey`, `APIToken`) redact while usage metrics like
//! `ai_total_tokens` stay visible. Every other credential class (session
//! identifiers, passwords and passphrases, PINs and one-time codes,
//! credentials, JWTs, signatures, private/access/signing keys, bearer
//! assertions, CSRF state) goes through the credential-class classifier
//! ([`is_credential_class_metadata_key`]), which fails closed on unlisted
//! spellings such as `userSessionIdentifier`, `x-session-id`, `GPG_PASSPHRASE`
//! or `clientAssertion` instead of relying on an exact-name list.
//!
//! **Fail-closed allowlist (issue #6619).** The rules above are a DENY layer.
//! The primary gate is an allowlist: a metadata VALUE is emitted only when its
//! key is a known-safe name, and every other value serializes as
//! `[REDACTED]`. Known-safe names are the gateway's own reviewed metadata keys
//! ([`BUILTIN_SAFE_METADATA_KEYS`], exact names, plus a few fixed-grammar
//! per-instance families; never whole namespaces) plus the operator allowlist
//! `FERRUM_LOG_SAFE_METADATA_KEYS` (exact names, or `prefix*` entries). The deny
//! layer still wins over the allowlist, and an operator entry the deny layer
//! classifies as credential-shaped is ignored with a startup warning. Because
//! unknown names are redacted by default, a credential spelling the classifier
//! does not recognize no longer reaches a sink.
//!
//! Request-private lifecycle keys in the `_dedup_*` namespace (case, delimiter,
//! and camelCase spellings under a leading `_` + first segment `dedup`) are
//! removed before an in-process transaction summary is built and are also
//! omitted from every external transaction-log projection (omitted, not
//! redacted). Typed request state is the primary home for that material.
//!
//! Internal mesh-metrics plans/markers under `mesh.metrics.*` follow a
//! two-stage lifetime: they stay on the in-process summary long enough for
//! built-in observers such as Prometheus to consume disable and tag-override
//! plans, then are omitted from external serialization/schema output. The mesh
//! metrics namespace coordinates metric production and is not user metadata.

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};
use std::collections::HashMap;
use std::sync::OnceLock;

/// Default substrings (lowercase) that mark a metadata key as sensitive.
///
/// Substring match, not exact match — see module docs. Broad `token` / `api key`
/// matching is intentionally excluded from this list; those shapes go through
/// the per-segment classifiers so token-count metrics do not disappear and
/// delimiter / acronym spellings share one decision with native and schema
/// projections.
pub const DEFAULT_SENSITIVE_METADATA_KEYS: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "cache_request_headers_snapshot",
    // Base64-encoded backend trailer values retained request-locally so
    // gRPC-Web can distinguish same-name initial headers from true trailers.
    "grpc_web_shadowed_trailers",
    "claim_header.",
    "bearer",
    "password",
    "secret",
    // SSE reconnection identifiers (Last-Event-ID) are origin-defined opaque
    // resume cursors; substring match covers `sse:last_event_id` and variants.
    "last_event_id",
    "last-event-id",
];

/// Prefix reserved for request-private lifecycle coordination state.
///
/// Keys under this prefix (historically `_dedup_key`, `_dedup_fingerprint`,
/// `_dedup_local_inflight_token`, `_dedup_redis_lock_token`) must never appear
/// in transaction-log or audit projections. Prefer typed non-serializable
/// request state; this prefix is the fail-closed observability contract.
pub const INTERNAL_ONLY_METADATA_KEY_PREFIX: &str = "_dedup_";

/// Request-private staging key holding the COMPLETE validated gRPC-Web request
/// trailer block as a base64 JSON array.
///
/// It is a transport container, not observability metadata: the client's own
/// trailing metadata (which may carry application credentials) is inside it, and
/// the names are embedded in the encoded value rather than being the outer key,
/// so name-based sensitive classification cannot reach them and base64 is
/// reversible. The response-side counterpart `grpc_web_shadowed_trailers` is
/// already treated as sensitive for exactly this reason; the request container
/// is omitted outright, which is the stronger contract. Owner is
/// `crate::plugins::grpc_web`, which reads it from `ctx.metadata` at dispatch
/// only — never from a log projection.
pub const INTERNAL_ONLY_GRPC_WEB_REQUEST_TRAILERS_KEY: &str = "grpc_web.request_trailers";

/// Prefix reserved for internal mesh metric plans and lifecycle markers.
pub const INTERNAL_ONLY_MESH_METRICS_PREFIX: &str = "mesh.metrics.";

/// Placeholder string written in place of sensitive metadata values.
pub const REDACTED_PLACEHOLDER: &str = "[REDACTED]";

/// Username written in place of URL userinfo by the admin projections (and the
/// Redis URL log projection): `scheme://user:pass@host` becomes
/// `scheme://redacted@host`, with no password.
pub const REDACTED_USERINFO_PLACEHOLDER: &str = "redacted";

/// Placeholder substituted for a URL query that may carry credentials.
pub const REDACTED_QUERY_PLACEHOLDER: &str = "[REDACTED_QUERY]";

/// Placeholder substituted for a URL fragment that may carry credentials.
pub const REDACTED_FRAGMENT_PLACEHOLDER: &str = "[REDACTED_FRAGMENT]";

/// Reviewed metadata keys written by the gateway and its built-in plugins.
///
/// Exact names only (issue #6619): a namespace prefix proves nothing about a
/// key a plugin invents beneath it (`mesh.vault_blob`), so unknown names under
/// a built-in prefix stay redacted. Per-instance key families with a fixed
/// grammar are matched by [`is_builtin_metadata_key_family`]. Values under
/// these names are emitted unless the deny layer matches the key.
pub const BUILTIN_SAFE_METADATA_KEYS: &[&str] = &[
    "a2a.binding",
    "a2a.context_id",
    "a2a.context_id.truncated",
    "a2a.enabled",
    "a2a.error",
    "a2a.error.truncated",
    "a2a.method",
    "a2a.mode",
    "a2a.payload.response",
    "a2a.policy_decision",
    "a2a.protocol_version",
    "a2a.protocol_version.truncated",
    "a2a.response_body_size",
    "a2a.stream_events",
    "a2a.streaming",
    "a2a.task_id",
    "a2a.task_id.truncated",
    "a2a.task_state",
    "a2a.task_state.truncated",
    "a2a.task_state.unrecognized",
    "a2a.ttfb_ms",
    "ai_cache_match",
    "ai_cache_similarity",
    "ai_cache_status",
    "ai_completion_tokens",
    "ai_estimated_cost",
    "ai_federation.streaming_claimed",
    "ai_federation.streaming_outcome",
    "ai_federation.streaming_provider_attempts",
    "ai_federation.streaming_provider_type",
    "ai_federation_circuit_half_open_probes",
    "ai_federation_circuit_last_provider",
    "ai_federation_circuit_last_state",
    "ai_federation_circuit_open_skips",
    "ai_federation_multimodal_dropped_parts",
    "ai_federation_multimodal_dropped_roles",
    "ai_federation_multimodal_dropped_types",
    "ai_federation_multimodal_mode",
    "ai_federation_multimodal_provider",
    "ai_federation_provider",
    "ai_federation_status",
    "ai_model",
    "ai_prompt_compressor.compressed_tokens",
    "ai_prompt_compressor.fields_compressed",
    "ai_prompt_compressor.observed_compressed_tokens",
    "ai_prompt_compressor.observed_fields_compressed",
    "ai_prompt_compressor.observed_original_tokens",
    "ai_prompt_compressor.observed_tokens_saved",
    "ai_prompt_compressor.original_tokens",
    "ai_prompt_compressor.tokens_saved",
    "ai_prompt_tokens",
    "ai_provider",
    "ai_ratelimit_backend_status",
    "ai_ratelimit_limit",
    "ai_ratelimit_remaining",
    "ai_ratelimit_reserved_tokens",
    "ai_ratelimit_usage",
    "ai_ratelimit_window",
    "ai_request_guard.action",
    "ai_request_guard.reason",
    "ai_request_guard.uninspectable_body",
    "ai_request_guard.uninspectable_body_action",
    "ai_request_guard.uninspectable_body_reason",
    "ai_request_streaming",
    "ai_response_guard_detected",
    "ai_response_guard_redacted",
    "ai_response_guard_rejected",
    "ai_response_guard_warning",
    "ai_semantic_firewall.action",
    "ai_semantic_firewall.decision",
    "ai_semantic_firewall.enabled",
    "ai_semantic_firewall.mode",
    "ai_semantic_firewall.request.action",
    "ai_semantic_firewall.request.decision",
    "ai_semantic_firewall.request.uninspectable_body",
    "ai_semantic_firewall.request.would_action",
    "ai_semantic_firewall.response.action",
    "ai_semantic_firewall.response.decision",
    "ai_semantic_firewall.response.uninspectable_body",
    "ai_semantic_firewall.response.would_action",
    "ai_semantic_firewall.response_inspection",
    "ai_semantic_firewall.response_inspection_skipped",
    "ai_semantic_firewall.stream_buffer_requested",
    "ai_semantic_firewall.stream_hold_timeout_action",
    "ai_semantic_firewall.stream_hold_timeouts",
    "ai_semantic_firewall.stream_inspect_requested",
    "ai_semantic_firewall.stream_skip_requested",
    "ai_semantic_firewall.uninspectable_body",
    "ai_shield_redacted",
    "ai_shield_rejected",
    "ai_shield_warnings",
    "ai_stream_router.claimed",
    "ai_stream_router.enabled",
    "ai_stream_router.model",
    "ai_stream_router.normalized_response_stream",
    "ai_stream_router.provider",
    "ai_stream_router.provider_content_encoding",
    "ai_stream_router.provider_type",
    "ai_stream_router.request_translated",
    "ai_stream_router.tool_choice_none",
    "ai_stream_router_claimed",
    "ai_stream_router_pass_through",
    "ai_streaming",
    "ai_tool_governor.approval_id",
    "ai_tool_governor.arguments_hashes",
    "ai_tool_governor.decision",
    "ai_tool_governor.enabled",
    "ai_tool_governor.mode",
    "ai_tool_governor.observations_omitted",
    "ai_tool_governor.policy_ids",
    "ai_tool_governor.redacted_tools",
    "ai_tool_governor.risk",
    "ai_tool_governor.stream_model",
    "ai_tool_governor.stream_requested",
    "ai_tool_governor.tool_names",
    "ai_tool_governor.uninspectable_reason",
    "ai_total_tokens",
    "ai_transcript_audit.candidate",
    "ai_transcript_audit.final_req_seen",
    "ai_transcript_audit.record_id",
    "ai_transcript_audit.request_hash",
    "ai_transcript_audit.response_hash",
    "ai_transcript_audit.sample_hit",
    "ai_transcript_audit.sampled",
    "ai_transcript_audit.sink_status",
    "ai_transcript_audit.stream_marker",
    "ai_transcript_audit.stream_request",
    "authorization.termination_reason",
    "body_validator.request_detail",
    "body_validator.request_outcome",
    "body_validator.request_status",
    "body_validator.response_detail",
    "body_validator.response_outcome",
    "body_validator.response_status",
    "compression.codec",
    "compression.level",
    "compression.type",
    "compression:accept_encoding",
    "compression:algorithm",
    "compression:request_decoded",
    "compression:request_encoding",
    "compression:request_no_transform",
    "connection_security_policy",
    "consumer_username",
    "correlation_id",
    "cors_origin",
    "direction",
    "error_class",
    "extended_connect_protocol",
    "fault_abort_status",
    "fault_delay_ms",
    "fault_delay_outcome",
    "fault_injected",
    "fault_injection.route_applied",
    "fault_type",
    "ferrum.frontend_scheme",
    "ferrum:external_operation_completed",
    "ferrum:finalized_synthetic_response",
    "ferrum:later_no_transform_response",
    "ferrum:later_strong_etag_response",
    "ferrum:no_transform_request",
    "ferrum:no_transform_response",
    "ferrum:origin_encoded_request",
    "ferrum:origin_encoded_response",
    "ferrum:origin_fragment_response",
    "ferrum:original_response_content_length",
    "ferrum:original_response_content_type",
    "ferrum:original_response_metadata_stamped",
    "ferrum:query_params_transformed",
    "ferrum:range_response",
    "ferrum:rejection_response",
    "ferrum:release_dedup_inflight_on_commit",
    "ferrum:replaceable_rejection_response",
    "ferrum:representation_rejected",
    "ferrum:request_representation_rejected",
    "ferrum:retry_response_buffering",
    "ferrum:spec_expose_head_response",
    "ferrum:strong_etag_response",
    "ferrum:synthetic_response_method_override",
    "ferrum:synthetic_short_circuit",
    "frontend_listen_port",
    "graphql_complexity",
    "graphql_depth",
    "graphql_operation_name",
    "graphql_operation_type",
    "grpc_adjusted_deadline_ms",
    "grpc_deadline.request_body_transform_timed_out",
    "grpc_full_method",
    "grpc_message",
    "grpc_method",
    "grpc_original_deadline_ms",
    "grpc_service",
    "grpc_status",
    "grpc_status_unreadable",
    "grpc_timeout_invalid",
    "grpc_web.owner",
    "grpc_web.request_decoded",
    "grpc_web.request_trailer_error",
    "grpc_web.response_translated",
    "grpc_web.unframed_error_entity",
    "grpc_web_accept_rejected",
    "grpc_web_http_status",
    "grpc_web_mode",
    "grpc_web_original_ct",
    "grpc_web_trailer_names",
    "hbone.udp.termination_reason",
    "hbone_datagram",
    "http_method",
    "io_side",
    "ip_restriction.reason",
    "mcp.admission_violation",
    "mcp.arguments",
    "mcp.arguments_hash",
    "mcp.arguments_truncated",
    "mcp.batch",
    "mcp.batch_size",
    "mcp.bridge.gateway_error",
    "mcp.bridge.operation",
    "mcp.bridge.upstream_status",
    "mcp.catalog_degraded",
    "mcp.catalog_hit",
    "mcp.catalog_version",
    "mcp.enabled",
    "mcp.input_schema_hash",
    "mcp.item_name",
    "mcp.item_type",
    "mcp.jsonrpc",
    "mcp.message.kind",
    "mcp.method",
    "mcp.mode",
    "mcp.needs_request_rewrite",
    "mcp.needs_response_rewrite",
    "mcp.policy_decision",
    "mcp.prompt_name",
    "mcp.protocol_version",
    "mcp.protocol_version_negotiated",
    "mcp.public_tool_name",
    "mcp.resource_uri",
    "mcp.response_rewrite.catalog_version",
    "mcp.response_rewrite.method",
    "mcp.response_rewrite.server_id",
    "mcp.response_rewrite.session",
    "mcp.result_schema_validation",
    "mcp.rewrite.method",
    "mcp.rewrite.param",
    "mcp.rewrite.public_value",
    "mcp.rewrite.upstream_value",
    "mcp.route_decision",
    "mcp.schema_validation",
    "mcp.server_id",
    "mcp.session.downstream",
    "mcp.sse.cancel",
    "mcp.sse.delivery",
    "mcp.sse.error",
    "mcp.sse.resume_requested",
    "mcp.sse.stream",
    "mcp.tool_name",
    "mcp.upstream_prompt_name",
    "mcp.upstream_resource_uri",
    "mcp.upstream_tool_name",
    "mcp_gateway.discovery",
    "mcp_gateway.initialize",
    "mcp_gateway.initialized_notification",
    "mcp_gateway.session_delete",
    "mesh.cluster",
    "mesh.connection_security_policy",
    "mesh.cross_cluster",
    "mesh.destination.app",
    "mesh.destination.namespace",
    "mesh.destination.principal",
    "mesh.destination.service",
    "mesh.destination.trust_domain",
    "mesh.destination.workload",
    "mesh.direction",
    "mesh.eastwest_sni",
    "mesh.gateway.transport",
    "mesh.hbone",
    "mesh.hbone_authority_host",
    "mesh.hbone_dial_host",
    "mesh.hbone_peer_spiffe_id",
    "mesh.hbone_port",
    "mesh.ignored_baggage",
    "mesh.mtls",
    "mesh.mtls_authority_host",
    "mesh.mtls_authority_port",
    "mesh.mtls_dial_host",
    "mesh.mtls_port",
    "mesh.namespace",
    "mesh.network",
    "mesh.node_id",
    "mesh.port_name",
    "mesh.protocol",
    "mesh.relay.denial_reason",
    "mesh.relay.denied_destination",
    "mesh.relay.terminator_ip",
    "mesh.remote",
    "mesh.request_principal",
    "mesh.request_protocol",
    "mesh.response_code",
    "mesh.response_flags",
    "mesh.service",
    "mesh.source.app",
    "mesh.source.namespace",
    "mesh.source.principal",
    "mesh.source.service",
    "mesh.source.service_account",
    "mesh.source.trust_domain",
    "mesh.source.workload",
    "mesh.spiffe_id",
    "mesh.topology",
    "mesh.trust_domain",
    "mesh.unix_socket",
    "mesh.unix_socket_h2c",
    "mesh_authz.audit_policy",
    "mesh_authz.deny_policy",
    "mesh_authz.destination_scope_missing",
    "mesh_authz.ext_authz_outcome",
    "mesh_authz.ignored_baggage",
    "mesh_authz.ignored_baggage.assertion_out_of_scope",
    "mesh_authz.ignored_baggage.trust_domain_mismatch",
    "mesh_authz.ignored_baggage.unauthenticated",
    "mesh_authz.ignored_baggage.untrusted_assertor",
    "mesh_authz.ignored_udp_source_scope",
    "mesh_authz.ingress_listener_port_missing",
    "mesh_authz.node_waypoint_authorized_backend",
    "mesh_authz.node_waypoint_authorized_backend_aliases",
    "mesh_authz.node_waypoint_authorized_upstream_id",
    "mesh_authz.node_waypoint_scoped_authz_active",
    "mesh_authz.non_canonical_path",
    "mesh_authz.reevaluation",
    "mesh_authz.scope_missing",
    "mesh_request_auth.permissive_missing_token",
    "mesh_route_dispatch.rule_index",
    "mesh_route_dispatch.rule_name",
    "mirror_error",
    "namespace",
    "opa.decision",
    "opa.reason",
    "openapi_validator.action",
    "openapi_validator.matched_operation",
    "openapi_validator.mode",
    "openapi_validator.request_contract_phase",
    "openapi_validator.request_error",
    "openapi_validator.response_error",
    "openapi_validator.skip_reason",
    "parent_span_id",
    "peer_spiffe_id",
    "ratelimit_authority",
    "ratelimit_limit",
    "ratelimit_local_fallback",
    "ratelimit_mcp_tool_calls",
    "ratelimit_mcp_uninspectable",
    "ratelimit_remaining",
    "ratelimit_window",
    "rejection_phase",
    "request_body_size_bytes",
    "request_deduplication.publishing_external_operation_tombstone",
    "request_deduplication.replayed",
    "request_id",
    "request_path",
    "request_protocol",
    // Fixed, value-free reason literals (`template_unresolved`,
    // `non_json_content_type`, …); never request content.
    "request_transformer.body_skipped",
    "request_transformer.rule_skipped",
    "response_status_code",
    "route_request_timeout",
    "server_address",
    "server_port",
    "soap_ws_saml_subject",
    "soap_ws_security.credential_strip_range",
    "soap_ws_username",
    "span_id",
    "sse:leid_bytes",
    "sse:leid_present",
    "sse:relabeled_non_sse",
    "sse:retry_ms",
    "sse:wrap_non_sse",
    "suppress_backend_consumer_identity_headers",
    "trace_id",
    "trace_sampled",
    "traceparent",
    "tracestate",
    "waf.action",
    "waf.block_reason",
    "waf.body_too_large",
    "waf.body_too_large_target",
    "waf.body_uninspected",
    "waf.body_uninspected_target",
    "waf.detection_matched_fields",
    "waf.detection_paranoia",
    "waf.detection_rule_hits",
    "waf.first_blocking_rule",
    "waf.instance_scores",
    "waf.matched_fields",
    "waf.paranoia",
    "waf.response_stream_uninspectable",
    "waf.rule_hits",
    "waf.scan_timed_out",
    "waf.scan_truncated",
    "waf.score",
    "waf.scoring_instance",
    "waf.severity",
    "waf.target",
    "waf.would_block_reason",
    "websocket.session.duration_ms",
    "websocket.termination_reason",
    "workload_metrics.captured_b3",
    "workload_metrics.captured_traceparent",
    "workload_metrics.captured_tracestate",
    "workload_metrics.trace_attributes",
];

/// Fixed suffixes of `ai_semantic_firewall` decision keys.
const SEMANTIC_FIREWALL_SUFFIXES: &[&str] = &[
    "action",
    "decision",
    "direction",
    "json_paths",
    "match_directions",
    "matcher_type",
    "max_score",
    "max_severity",
    "on_hold_timeout",
    "provider_error",
    "request_body_size_bytes",
    "roles",
    "rule_descriptions",
    "rule_ids",
    "rule_packs",
    "segment_kinds",
    "snippet_hashes",
    "type",
    "uninspectable_body",
    "would_action",
];

/// Base names of `ai_rate_limiter` per-instance keys (`<base>#<instance id>`).
const AI_RATELIMIT_INSTANCE_BASES: &[&str] = &[
    "ai_ratelimit_limit",
    "ai_ratelimit_window",
    "ai_ratelimit_remaining",
    "ai_ratelimit_usage",
    "ai_ratelimit_backend_status",
    "ai_ratelimit_reserved_tokens",
];

fn is_decimal_instance_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 20 && id.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_identifier_segment(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

/// Built-in per-instance key families with an exact grammar: a fixed prefix,
/// one bounded identifier segment, and a fixed suffix. Nothing else beneath
/// these prefixes is allowlisted.
fn is_builtin_metadata_key_family(key: &str) -> bool {
    if let Some(rest) = key.strip_prefix("grpc_web.instance.") {
        return ["mode", "native_ct"].iter().any(|suffix| {
            rest.strip_suffix(suffix)
                .and_then(|id| id.strip_suffix('.'))
                .is_some_and(is_identifier_segment)
        });
    }
    if let Some(header) = key.strip_prefix("correlation_id.instance.") {
        return is_identifier_segment(header);
    }
    if let Some(rest) = key.strip_prefix("ai_semantic_firewall.") {
        let suffix = rest
            .strip_prefix("request.")
            .or_else(|| rest.strip_prefix("response."))
            .unwrap_or(rest);
        return SEMANTIC_FIREWALL_SUFFIXES.contains(&suffix);
    }
    if let Some(rest) = key.strip_prefix("ai_semantic_cache.") {
        return rest.split_once('.').is_some_and(|(id, suffix)| {
            is_decimal_instance_id(id)
                && matches!(suffix, "cache_status" | "cache_match" | "cache_similarity")
        });
    }
    if let Some(rest) = key.strip_prefix("ai_prompt_compressor.instances.") {
        return rest.split_once('.').is_some_and(|(id, suffix)| {
            is_decimal_instance_id(id)
                && matches!(
                    suffix,
                    "original_tokens"
                        | "compressed_tokens"
                        | "tokens_saved"
                        | "fields_compressed"
                        | "observed_original_tokens"
                        | "observed_compressed_tokens"
                        | "observed_tokens_saved"
                        | "observed_fields_compressed"
                        | "skipped"
                )
        });
    }
    key.split_once('#').is_some_and(|(base, id)| {
        AI_RATELIMIT_INSTANCE_BASES.contains(&base) && is_decimal_instance_id(id)
    })
}

/// Built-in names that carry payloads rather than bounded observability
/// values. Never emitted, whatever any allowlist says.
const PAYLOAD_METADATA_KEYS: &[&str] = &["request_body", "response_body"];

fn is_payload_metadata_key(key: &str) -> bool {
    PAYLOAD_METADATA_KEYS
        .iter()
        .any(|payload| key.eq_ignore_ascii_case(payload))
}

/// Operator-supplied safe names parsed once from `FERRUM_LOG_SAFE_METADATA_KEYS`.
static SAFE_METADATA_KEYS: OnceLock<Vec<String>> = OnceLock::new();

fn operator_safe_metadata_keys() -> &'static [String] {
    SAFE_METADATA_KEYS.get_or_init(|| {
        let parsed = parse_safe_metadata_keys(crate::config::conf_file::resolve_ferrum_var(
            "FERRUM_LOG_SAFE_METADATA_KEYS",
        ));
        for rejected in &parsed.rejected {
            tracing::warn!(
                entry = %rejected,
                "FERRUM_LOG_SAFE_METADATA_KEYS entry is credential-shaped and is ignored; its values stay redacted"
            );
        }
        parsed.accepted
    })
}

/// `FERRUM_LOG_SAFE_METADATA_KEYS` split into usable entries and entries the
/// deny layer refuses (credential-shaped names cannot be allowlisted).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ParsedSafeMetadataKeys {
    /// Lowercased exact names, or prefixes ending in `*`.
    pub accepted: Vec<String>,
    /// Entries ignored because the deny layer matches them.
    pub rejected: Vec<String>,
}

/// Parse an already-resolved `FERRUM_LOG_SAFE_METADATA_KEYS` value
/// (comma-separated). An entry ending in `*` allows that prefix; any other
/// entry is an exact, case-insensitive name. Entries the deny layer matches
/// are returned in `rejected`.
pub fn parse_safe_metadata_keys(resolved: Option<String>) -> ParsedSafeMetadataKeys {
    let mut parsed = ParsedSafeMetadataKeys::default();
    let Some(raw) = resolved else {
        return parsed;
    };
    for entry in raw.split(',') {
        let entry = entry.trim().to_ascii_lowercase();
        let name = entry.strip_suffix('*').unwrap_or(&entry);
        if name.is_empty() {
            continue;
        }
        if is_sensitive_metadata_key(name) || is_payload_metadata_key(name) {
            parsed.rejected.push(entry);
        } else {
            parsed.accepted.push(entry);
        }
    }
    parsed
}

/// Whether `key` is a reviewed built-in metadata name: an exact built-in key
/// or a member of a fixed-grammar per-instance family. Payload keys never are.
pub fn is_builtin_safe_metadata_name(key: &str) -> bool {
    !is_payload_metadata_key(key)
        && (BUILTIN_SAFE_METADATA_KEYS.contains(&key) || is_builtin_metadata_key_family(key))
}

/// Whether `key` matches an operator allowlist entry (exact or `prefix*`).
pub fn matches_safe_metadata_entries(key: &str, entries: &[String]) -> bool {
    entries.iter().any(|entry| match entry.strip_suffix('*') {
        Some(prefix) => {
            key.len() >= prefix.len()
                && key.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
        }
        None => key.eq_ignore_ascii_case(entry),
    })
}

/// The primary metadata gate with explicit operator lists (tests): a value is
/// emitted only when the key is allowlisted (built-in or `safe_entries`) and
/// the deny layer (`redact_extras` included) does not match it.
pub fn metadata_value_is_redacted_with(
    key: &str,
    safe_entries: &[String],
    redact_extras: &[String],
) -> bool {
    // Payload keys first: no allowlist, built-in or operator, can admit them.
    is_payload_metadata_key(key)
        || is_sensitive_metadata_key_with_extras(key, redact_extras)
        || !(is_builtin_safe_metadata_name(key) || matches_safe_metadata_entries(key, safe_entries))
}

/// The primary metadata gate: `true` unless the key is allowlisted and the
/// deny layer does not match it. Every sink that emits metadata VALUES
/// (transaction logs, schema projections, audit records, trace attributes)
/// uses this; name-shape checks for operator-chosen output names use
/// [`is_sensitive_metadata_key`].
pub fn metadata_value_is_redacted(key: &str) -> bool {
    // Payload keys first: no allowlist, built-in or operator, can admit them.
    is_payload_metadata_key(key)
        || is_sensitive_metadata_key(key)
        || !(is_builtin_safe_metadata_name(key)
            || matches_safe_metadata_entries(key, operator_safe_metadata_keys()))
}

/// Operator-supplied extras parsed once from `FERRUM_LOG_REDACT_METADATA_KEYS`.
///
/// Stored lowercased and trimmed. `None`-equivalent: an empty `Vec`.
static EXTRA_REDACTED_KEYS: OnceLock<Vec<String>> = OnceLock::new();

/// Read the current operator-supplied redaction extras. The list is loaded
/// from `FERRUM_LOG_REDACT_METADATA_KEYS` on first call and cached.
fn extra_redacted_keys() -> &'static [String] {
    EXTRA_REDACTED_KEYS.get_or_init(parse_extras_from_env)
}

/// Parse the comma-separated extras env var into a normalized list.
/// Public for tests — production callers go through the `OnceLock`.
pub fn parse_extras_from_env() -> Vec<String> {
    parse_extras_from_resolved(crate::config::conf_file::resolve_ferrum_var(
        "FERRUM_LOG_REDACT_METADATA_KEYS",
    ))
}

/// Parse extras from an already-resolved `FERRUM_LOG_REDACT_METADATA_KEYS` value
/// (env-over-conf). Public for tests proving ferrum.conf values are honored.
pub fn parse_extras_from_resolved(resolved: Option<String>) -> Vec<String> {
    match resolved {
        Some(raw) => parse_extras_list(&raw),
        None => Vec::new(),
    }
}

/// Parse a comma-separated extras string into a normalized lowercase list.
pub fn parse_extras_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|part| part.trim().to_ascii_lowercase())
        .filter(|part| !part.is_empty())
        .collect()
}

fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    let needle = needle.as_bytes();
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

fn for_each_metadata_key_segment(mut key: &str, mut visit: impl FnMut(&str)) {
    while let Some(first_non_ascii) = key.find(|ch: char| !ch.is_ascii()) {
        visit_ascii_metadata_key_segments(&key[..first_non_ascii], &mut visit);
        let Some(non_ascii_char) = key[first_non_ascii..].chars().next() else {
            break;
        };
        key = &key[first_non_ascii + non_ascii_char.len_utf8()..];
    }
    visit_ascii_metadata_key_segments(key, &mut visit);
}

fn visit_ascii_metadata_key_segments(key: &str, visit: &mut impl FnMut(&str)) {
    let mut start: Option<usize> = None;
    // Index of the most recent uppercase character in the current segment.
    // Used to split acronym boundaries (`APIKey` → `API` + `Key`,
    // `APIToken` → `API` + `Token`) without splitting single-letter prefixes
    // (`AToken` stays one leading `A` + `Token` only when a longer uppercase
    // run precedes the final capital).
    let mut last_upper: Option<usize> = None;
    let mut previous_was_lower_or_digit = false;

    for ch in key.chars() {
        debug_assert!(ch.is_ascii());
    }

    for (idx, ch) in key.char_indices() {
        if !ch.is_ascii_alphanumeric() {
            if let Some(segment_start) = start.take() {
                visit(&key[segment_start..idx]);
            }
            last_upper = None;
            previous_was_lower_or_digit = false;
            continue;
        }

        if ch.is_ascii_uppercase() {
            if previous_was_lower_or_digit {
                if let Some(segment_start) = start {
                    visit(&key[segment_start..idx]);
                }
                start = Some(idx);
            } else if start.is_none() {
                start = Some(idx);
            }
            last_upper = Some(idx);
            previous_was_lower_or_digit = false;
            continue;
        }

        if ch.is_ascii_lowercase() {
            if let (Some(segment_start), Some(upper_idx)) = (start, last_upper) {
                // `APIKey`: flush `API`, keep `Key` with this lowercase.
                if upper_idx > segment_start {
                    visit(&key[segment_start..upper_idx]);
                    start = Some(upper_idx);
                }
            } else if start.is_none() {
                start = Some(idx);
            }
            last_upper = None;
            previous_was_lower_or_digit = true;
            continue;
        }

        // Digits: extend the current segment; treat like lowercase for the
        // next camelCase boundary (`token2Value` → `token2` + `Value`).
        if start.is_none() {
            start = Some(idx);
        }
        last_upper = None;
        previous_was_lower_or_digit = true;
    }

    if let Some(segment_start) = start {
        visit(&key[segment_start..]);
    }
}

fn is_sensitive_token_metadata_key(key: &str) -> bool {
    let mut has_token_segment = false;

    for_each_metadata_key_segment(key, |segment| {
        if segment.eq_ignore_ascii_case("token") {
            has_token_segment = true;
        }
    });

    // Singular `token` is credential-shaped regardless of its producer or
    // provider prefix. An allowlist of known contexts fails open for custom
    // plugins (`vendor_token`) and new providers (`openaiToken`). Usage
    // counters conventionally use the distinct plural segment `tokens`, so
    // `ai_total_tokens` and peers remain observable.
    has_token_segment
}

/// Segments that name a credential class on their own.
const CREDENTIAL_CLASS_SEGMENTS: &[&str] = &[
    "session",
    "sessions",
    "sess",
    "sessid",
    "sessionid",
    "sid",
    "jwt",
    "jws",
    "jwe",
    "passwd",
    "pwd",
    "passphrase",
    "passcode",
    "pin",
    "otp",
    "totp",
    "hotp",
    // Singular `token` as a whole segment: the token classifier's rule,
    // repeated here so the lowercased retry also catches spellings whose
    // alternating case shatters the segment (`ToKeN` -> `To`/`Ke`/`N`).
    "token",
    "credential",
    "credentials",
    "cred",
    "creds",
    "signature",
    "signatures",
    "sig",
    "csrf",
    "xsrf",
];

/// Credential stems that stay credential-shaped anywhere inside a segment
/// (`usersession`, `dbpassword`, `gpgpassphrase`, `idjwt`, `dbpwd`,
/// `requestsignature`, `clientassertion`, `totpseed`), plus qualified
/// compounds whose bare parts are too common to match alone (`hsmpin`,
/// `otpseed`, `mfacode`).
const CREDENTIAL_CLASS_STEMS: &[&str] = &[
    "session",
    "sessid",
    "passw",
    "passkey",
    "passphrase",
    "passcode",
    "pwd",
    "credential",
    "jwt",
    "jws",
    "jwe",
    "signature",
    "assertion",
    "csrf",
    "xsrf",
    "totp",
    "hotp",
    "otpseed",
    "otpsecret",
    "otpcode",
    "otpkey",
    "mfacode",
    "mfasecret",
    "mfaseed",
    "pincode",
    "pinblock",
    "hsmpin",
    "simpin",
    "cardpin",
    "userpin",
    "adminpin",
    "devicepin",
    "sopin",
];

/// Key-material qualifiers. A `key` / `keys` segment after one of these
/// (`private_key`, `access-key`, `signingKey`), or a segment joining one to
/// `key` (`privatekey`, `x-clientkey`, `awsaccesskeyid`), is a credential.
/// A bare `key` stays visible so `cache_key` and `routing_key` remain
/// observable.
const CREDENTIAL_KEY_QUALIFIERS: &[&str] = &[
    "api",
    "mfa",
    "integrity",
    "aes",
    "rsa",
    "crypto",
    "crypt",
    "ecdsa",
    "ed25519",
    "x25519",
    "chacha",
    "private",
    "access",
    "secret",
    "signing",
    "session",
    "client",
    "master",
    "encryption",
    "decryption",
    "ssh",
    "pgp",
    "gpg",
    "hmac",
    "jwt",
];

// A key-material qualifier keeps the context open for the rest of the key,
// so any number of algorithm, curve, size, encoding or mode descriptors in
// between (`private_ec_p256_pkcs8_pem_key`) never closes it. Unlisted
// descriptors are not evidence of safety.

/// Complete metadata keys that name a policy OUTCOME about an assertion, not
/// the assertion itself, compared case-insensitively against the WHOLE key.
/// `mesh_authz.ignored_baggage.assertion_out_of_scope` is a documented
/// transaction-log signal.
const NON_SECRET_ASSERTION_SIGNAL_KEYS: &[&str] =
    &["mesh_authz.ignored_baggage.assertion_out_of_scope"];

/// Longest segment lowercased on the stack; longer segments (rare) allocate.
const CLASSIFIER_STACK_SEGMENT_BYTES: usize = 64;

/// Whether a key-material qualifier occurs in `lower` with `key` somewhere
/// after it in the same segment (`privatekey`, `privatekeypem`,
/// `privateecp256key`, `awsaccesskeyid`). Linear in the segment length.
fn has_inline_key_material(lower: &str) -> bool {
    CREDENTIAL_KEY_QUALIFIERS.iter().any(|qualifier| {
        lower
            .find(qualifier)
            .is_some_and(|offset| names_key_material(&lower[offset + qualifier.len()..]))
    }) || has_reverse_inline_key_material(lower)
}

/// Reverse order inside one segment: `key` / `keys` (optionally with
/// digits) directly followed by a key-material qualifier (`keyprivate`,
/// `keyssigning`, `key2rsa`). `key` closing an ordinary word (`monkey`,
/// `turkey`) does not count.
fn has_reverse_inline_key_material(lower: &str) -> bool {
    lower.match_indices("key").any(|(offset, _)| {
        let end = offset + "key".len();
        if BENIGN_KEY_WORDS
            .iter()
            .any(|word| lower[..end].ends_with(word))
        {
            return false;
        }
        let rest = &lower[end..];
        let rest = rest.strip_prefix('s').unwrap_or(rest);
        let rest = rest.trim_start_matches(|ch: char| ch.is_ascii_digit());
        CREDENTIAL_KEY_QUALIFIERS
            .iter()
            .any(|qualifier| rest.starts_with(qualifier))
    })
}

/// Whether a whole segment is a bare key word (`key`, `keys`, `key1`) that a
/// directly following qualifier segment turns into key material
/// (`key_private`, `x-key-signing`, `keyPrivate`).
fn is_bare_key_segment(lower: &str) -> bool {
    let rest = lower
        .strip_prefix("key")
        .map(|rest| rest.strip_prefix('s').unwrap_or(rest));
    rest.is_some_and(|rest| rest.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Ordinary words that end in `pass` and do not start a passphrase /
/// passcode / password compound across segments.
const BENIGN_PASS_ENDINGS: &[&str] = &[
    "bypass",
    "compass",
    "surpass",
    "overpass",
    "underpass",
    "trespass",
    "encompass",
];

/// Whether a segment ends in `pass` so that a following `phrase` / `code` /
/// `word` segment completes a credential (`pass_phrase`, `gpgpass_phrase`,
/// `x-vaultpass-code`).
fn ends_credential_pass(lower: &str) -> bool {
    lower.ends_with("pass") && !BENIGN_PASS_ENDINGS.contains(&lower)
}

/// What may follow `key` / `keys` and still name key material
/// (`keyid`, `keypem`, `keydata`); ordinary words such as `keyboard` and
/// `keyword` do not qualify.
const KEY_MATERIAL_TRAILERS: &[&str] = &[
    "id", "ids", "pem", "der", "data", "value", "values", "file", "path", "bytes", "b64", "base64",
    "hex", "json", "material", "pair", "raw", "blob", "bin", "string", "secret",
];

/// Plural usage-counter shapes after `token`: `tokens`, or `tokens` followed
/// by a counter word (`tokenspersecond`, `tokensused`). A singular credential
/// representation that merely starts with `s` (`tokensigned`) is not one.
fn is_token_count_shape(rest: &str) -> bool {
    // Complete counter expressions only, never prefixes (`tokensingleuse`
    // must not pass as `tokens` + `in…`).
    const COUNTER_SUFFIXES: &[&str] = &[
        "",
        "per",
        "persecond",
        "perminute",
        "perhour",
        "perday",
        "perrequest",
        "used",
        "total",
        "count",
        "in",
        "out",
        "input",
        "output",
        "remaining",
        "limit",
        "max",
        "min",
        "sent",
        "received",
        "consumed",
        "estimated",
        "budget",
    ];
    rest.strip_prefix('s')
        .is_some_and(|after| COUNTER_SUFFIXES.contains(&after))
}

/// A singular `token` followed by digits or a representation trailer inside
/// one segment (`vendortokenvalue`, `token1`, `accesstokenhash`). A plural
/// `tokens` names a usage count and stays visible (`ai_total_tokens`).
/// Qualifiers that make a plural `tokens` a set of credentials rather than a
/// usage count (`access_tokens`, `refreshTokens`, `x-access-tokens`).
const CREDENTIAL_TOKEN_QUALIFIERS: &[&str] = &[
    "access", "refresh", "id", "bearer", "auth", "session", "api", "csrf", "xsrf", "oauth", "jwt",
    "security", "secret", "client", "service", "personal",
];

/// A plural `tokens` naming credentials: a credential qualifier earlier in
/// the key (`refresh_v2_tokens`) or joined in front of it (`accesstokens`).
fn is_credential_token_plural(lower: &str, in_token_credential_context: bool) -> bool {
    lower.strip_suffix("tokens").is_some_and(|prefix| {
        // Joined in front, possibly through descriptors (`refreshopaquetokens`);
        // two-letter qualifiers (`id`) only count directly in front.
        in_token_credential_context
            || CREDENTIAL_TOKEN_QUALIFIERS.iter().any(|qualifier| {
                !prefix.is_empty()
                    && (prefix.ends_with(qualifier)
                        || (qualifier.len() >= 4 && prefix.contains(qualifier)))
            })
    })
}

/// Whether a segment opens the credential-token context: an exact qualifier,
/// a qualifier decorated with digits (`oauth2`), or a segment containing a
/// qualifier of four or more characters (`refreshopaque`).
fn opens_token_credential_context(lower: &str) -> bool {
    CREDENTIAL_TOKEN_QUALIFIERS.iter().any(|qualifier| {
        lower == *qualifier
            || lower.strip_prefix(qualifier).is_some_and(|rest| {
                !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_digit())
            })
            || (qualifier.len() >= 4 && lower.contains(qualifier))
    })
}

fn has_token_compound(lower: &str) -> bool {
    // Any singular `token` that continues inside the segment fails closed
    // for unknown representations (`tokenopaque`, `vendortokensigned`),
    // except complete plural counter expressions (`tokens`, `tokensused`)
    // and the tokenizer vocabulary.
    lower.match_indices("token").any(|(offset, _)| {
        let rest = &lower[offset + "token".len()..];
        !rest.is_empty() && !is_token_count_shape(rest) && !rest.starts_with("iz")
    })
}

/// MFA credential material named after an `mfa` qualifier, possibly through
/// descriptors (`mfa_recovery_code`, `mfabackupcode`, `mfa_seed`).
fn names_mfa_material(text: &str) -> bool {
    ["code", "seed", "secret", "key", "token", "pin"]
        .iter()
        .any(|word| text.contains(word))
}

/// Shared suffix policy for both compound classifiers: optional digits
/// (`pin1`, `signingkey1`), then nothing or text that starts with a listed
/// representation trailer, including composed ones (`base64url`,
/// `valuehex`, `1value`, `encoded`, `utf8`).
fn is_credential_suffix(rest: &str) -> bool {
    let after_digits = rest.trim_start_matches(|ch: char| ch.is_ascii_digit());
    if after_digits.len() < rest.len() && after_digits.is_empty() {
        return true;
    }
    SHORT_CLASS_TRAILERS
        .iter()
        .chain(KEY_MATERIAL_TRAILERS)
        .any(|trailer| trailer.len() >= 2 && after_digits.starts_with(trailer))
}

/// Whether `text` contains `key` / `keys` that ends it, is followed by digits,
/// or is followed by a key-material trailer (`key`, `rsakey`, `keypem`,
/// `p256keyid`, `keybase64url`, `key1`).
fn names_key_material(text: &str) -> bool {
    if BENIGN_KEY_WORDS.contains(&text) {
        return false;
    }
    text.match_indices("key").any(|(offset, _)| {
        let from_key = &text[offset..];
        // Fail closed: after a key-material qualifier, `key` followed by any
        // representation (`keyjwk`, `keystring`, `keyseed`) is key material,
        // unless the rest of the text is exactly an ordinary word (or its
        // plural): `keyboard` is ordinary, `keywordsbase64` is not.
        !BENIGN_KEY_WORD_PREFIXES.iter().any(|word| {
            from_key
                .strip_prefix(word)
                .is_some_and(|after| after.is_empty() || after == "s")
        })
    })
}

/// Whole segments that contain `key` without naming key material.
const BENIGN_KEY_WORDS: &[&str] = &[
    "monkey", "donkey", "turkey", "hockey", "jockey", "whiskey", "monkeys", "donkeys", "turkeys",
];

/// Ordinary words that start with `key`.
const BENIGN_KEY_WORD_PREFIXES: &[&str] = &[
    "keyboard",
    "keyword",
    "keyspace",
    "keystroke",
    "keynote",
    "keypad",
    "keyhole",
    "keyframe",
    "keydown",
    "keyup",
    "keyless",
    "keystone",
    "keychain",
    "keycap",
    "keylogger",
    "keypress",
];

/// Whether a segment opens a key-material context for the following
/// segments: it contains a qualifier (`private`, `awsaccess`, `signingrsa`).
fn opens_key_context(lower: &str) -> bool {
    CREDENTIAL_KEY_QUALIFIERS
        .iter()
        .any(|qualifier| lower.contains(qualifier))
}

/// Whole segments that contain a short credential class without naming one.
const BENIGN_SHORT_CLASS_SEGMENTS: &[&str] = &[
    "spin",
    "spins",
    "hairpin",
    "hairpins",
    "linchpin",
    "linchpins",
    "tailspin",
    "backspin",
    "topspin",
    "sidespin",
    "tenpin",
    "tenpins",
    "clothespin",
    "sacred",
    "assess",
    "obsess",
    "reassess",
    "lupin",
    "lupins",
];

/// Complete ordinary words that begin with a short credential class. Matched
/// as WHOLE segments only, so a word never shields a longer compound
/// (`pint` does not exempt `pintext`).
const BENIGN_LEADING_SHORT_CLASS_WORDS: &[&str] = &[
    "pinned",
    "pinning",
    "pinpoint",
    "pinpoints",
    "pine",
    "pines",
    "pineapple",
    "pink",
    "pint",
    "pints",
    "pinch",
    "pinyin",
    "pinout",
    "pinouts",
    "pinball",
    "pinhole",
    "pinwheel",
    "pinata",
    "pinion",
    "sign",
    "signs",
    "signal",
    "signals",
    "signaled",
    "signaling",
    "signalling",
    "signed",
    "signer",
    "signers",
    "signing",
    "signup",
    "signin",
    "signoff",
    "signpost",
    "signage",
    "signet",
    "significant",
    "significance",
    "sigma",
    "sigh",
    "sigil",
    "side",
    "sides",
    "sidebar",
    "sidebars",
    "sidecar",
    "sidecars",
    "sideways",
    "sidle",
    "sidekick",
    "sideload",
    "siding",
    "credit",
    "credits",
    "credited",
    "credible",
    "credibility",
    "credo",
    "credence",
    "credulous",
    "sessile",
];

/// Owner qualifiers that make any following short-class compound a
/// credential (`dbpin…`, `vendorsig…`, `usersid…`, `hsmpin…`).
const SHORT_CLASS_OWNER_QUALIFIERS: &[&str] = &[
    "db", "vendor", "user", "admin", "hsm", "sim", "card", "device", "master", "client", "api",
    "app", "service", "root", "account", "login", "auth", "sms", "email", "totp", "hmac", "jwt",
    "gpg", "pgp", "ssh", "tls", "door", "atm", "bank", "wallet", "puk", "tenant", "customer",
    "merchant", "partner", "org", "team", "owner", "operator", "consumer", "member",
];

/// Words that may follow a short credential class inside one segment
/// (`pinvalue`, `vendorpincode`, `usersidhash`, `smsotpcode`).
const SHORT_CLASS_TRAILERS: &[&str] = &[
    "s", "value", "values", "code", "codes", "id", "ids", "number", "num", "hash", "data",
    "string", "secret", "seed", "key", "token", "block", "base64", "b64", "b64url", "hex", "pem",
    "der", "raw", "bytes", "bin", "blob", "json", "encoded", "utf8", "utf16", "ascii", "latin1",
];

/// Short credential classes that only count inside a qualified compound,
/// with the minimum qualifier length in front of them when nothing follows.
const QUALIFIED_SHORT_CLASSES: &[(&str, usize)] = &[
    ("pin", 1),
    ("sid", 1),
    ("otp", 1),
    ("sig", 1),
    ("cred", 1),
    ("sess", 1),
];

/// Qualified short-class compounds that survive lowercasing: a short class
/// followed by a listed trailer word (`pinvalue`, `dbpinvalue`, `sigvalue`,
/// `credvalue`, `otpcode`), or ending the segment after a qualifier of the
/// minimum length (`vendorpin`, `usersid`, `smsotp`, `vendorsig`,
/// `vendorcred`). Ordinary words fail one of the bounds (`spin`, `inside`,
/// `president`, `footprint`, `design`, `credit`, `sacred`) or are listed
/// (`hairpin`).
fn has_qualified_short_class(lower: &str) -> bool {
    if BENIGN_SHORT_CLASS_SEGMENTS.contains(&lower) {
        return false;
    }
    // A segment that STARTS with a short class and continues is a credential
    // compound (`pincleartext`, `sidvalue`, `otpseed`) unless it is a listed
    // ordinary word (`pinned`, `signal`, `sidecar`, `credit`): unrecognized
    // representations fail closed.
    if QUALIFIED_SHORT_CLASSES
        .iter()
        .any(|(class, _)| lower.len() > class.len() && lower.starts_with(class))
        && !BENIGN_LEADING_SHORT_CLASS_WORDS.contains(&lower)
    {
        return true;
    }
    QUALIFIED_SHORT_CLASSES.iter().any(|(class, min_prefix)| {
        lower.match_indices(class).any(|(offset, _)| {
            let prefix = &lower[..offset];
            let rest = &lower[offset + class.len()..];
            // A real trailer word makes it a compound whatever precedes it;
            // the bare plural `s` only counts after a full qualifier.
            // Also after a grammatical plural (`credsvalue`, `pinshash`).
            if !rest.is_empty()
                && (is_credential_suffix(rest)
                    || rest
                        .strip_prefix('s')
                        .is_some_and(|plural| !plural.is_empty() && is_credential_suffix(plural)))
            {
                return true;
            }
            // After a recognized owner qualifier (`db`, `vendor`, `user`, …)
            // any representation fails closed (`dbpincleartext`,
            // `vendorsigheader`); ordinary words such as `mapping` or `inside`
            // have no such qualifier in front.
            if !rest.is_empty()
                && SHORT_CLASS_OWNER_QUALIFIERS
                    .iter()
                    .any(|owner| prefix.ends_with(owner))
            {
                return true;
            }
            !prefix.is_empty() && prefix.len() >= *min_prefix && (rest.is_empty() || rest == "s")
        })
    })
}

/// Judge one lowercased segment. `in_key_context` says whether any earlier
/// segment of the key contained a key-material qualifier.
fn lowered_segment_is_credential(lower: &str, in_key_context: bool) -> bool {
    CREDENTIAL_CLASS_SEGMENTS.contains(&lower)
        || (lower.len() > "token".len() && lower.ends_with("token"))
        || has_token_compound(lower)
        || CREDENTIAL_CLASS_STEMS
            .iter()
            .any(|stem| lower.contains(stem))
        || has_qualified_short_class(lower)
        || (in_key_context && names_key_material(lower))
        || has_inline_key_material(lower)
}

/// Credential-class classifier for metadata keys (issue #6619).
///
/// The key is split into segments exactly like the token classifier
/// (delimiters, camelCase, acronyms, non-ASCII boundaries) and each segment is
/// judged case-insensitively. A key is credential-shaped when:
///
/// * a segment is a credential-class word (`session`, `sid`, `jwt`, `pwd`,
///   `passphrase`, `pin`, `otp`, `credential`, `signature`, `csrf`, …);
/// * a segment contains a credential stem or qualified compound
///   (`usersession`, `gpgpassphrase`, `clientassertion`, `hsmpin`,
///   `totpseed`), or ends in `token` after a qualifier (`accesstoken`);
///   plural `tokens` stays visible for usage counts;
/// * key material: a key-material qualifier (`private`, `access`, `signing`,
///   `client`, …) reaches `key` / `keys`, optionally through algorithm or
///   encoding words (`rsa`, `pem`, `ed25519`, …), within one segment
///   (`privatekey`, `awsaccesskeyid`) or across segments (`private_key`,
///   `private_rsa_key`, `privateRsaKey`).
///   The reverse order is key material too (`key_private`, `keyPrivate`,
///   `keysigning`);
/// * an owner-qualified segment ending in `pass` followed by `phrase` /
///   `code` / `word` (`gpgpass_phrase`); `bypass_code` stays visible.
///
/// Lowercased compounds are recognized as well as camelCase ones, so a name
/// normalized before classification (an HTTP header name) cannot slip past.
/// The only exemption is an explicitly listed complete non-secret outcome key
/// ([`NON_SECRET_ASSERTION_SIGNAL_KEYS`]). The rule is deliberately narrower
/// than outbound header stripping: ordinary dimensions such as `cache_key`,
/// `routing_key`, `request_id`, and `ai_total_tokens` stay visible.
/// Allocation-free for segments up to 64 bytes.
pub fn is_credential_class_metadata_key(key: &str) -> bool {
    if NON_SECRET_ASSERTION_SIGNAL_KEYS
        .iter()
        .any(|exempt| key.eq_ignore_ascii_case(exempt))
    {
        return false;
    }
    is_credential_class_name(key)
}

/// Whether a request/response HEADER name is sensitive: the shared metadata
/// decision plus the credential-class classifier WITHOUT the metadata-only
/// outcome-key exemption. A header named like a gateway outcome signal is
/// still caller-supplied, so the name proves nothing about its value.
pub fn is_sensitive_header_name(name: &str) -> bool {
    is_sensitive_metadata_key(name) || is_credential_class_name(name)
}

/// The credential-class classifier without any exemption.
fn is_credential_class_name(key: &str) -> bool {
    // CamelCase splitting runs before case folding, so an irregular mix
    // (`JwT`, `HSM_PiN`, `mFaRecoveryCode`) would split inside a credential
    // word. Judge the delimiter-only (fully lowercased) spelling with every
    // rule too, failing closed: a camelCase name whose joined lowercase form
    // is a credential compound is treated as one. It only allocates when the
    // key has an uppercase letter.
    classify_credential_class_segments(key)
        || (key.bytes().any(|byte| byte.is_ascii_uppercase())
            && classify_credential_class_segments(&key.to_ascii_lowercase()))
}

fn classify_credential_class_segments(key: &str) -> bool {
    let mut sensitive = false;
    let mut in_key_context = false;
    let mut previous_is_pass = false;
    let mut previous_is_bare_key = false;
    let mut in_mfa_context = false;
    let mut in_token_credential_context = false;
    for_each_metadata_key_segment(key, |segment| {
        if sensitive {
            return;
        }
        let mut stack = [0u8; CLASSIFIER_STACK_SEGMENT_BYTES];
        let heap;
        let lower: &str = if segment.len() <= CLASSIFIER_STACK_SEGMENT_BYTES {
            let buffer = &mut stack[..segment.len()];
            buffer.copy_from_slice(segment.as_bytes());
            buffer.make_ascii_lowercase();
            // Segments are ASCII alphanumeric runs (see the segmenter), so the
            // lowercased bytes are valid UTF-8.
            match std::str::from_utf8(buffer) {
                Ok(lower) => lower,
                Err(_) => return,
            }
        } else {
            heap = segment.to_ascii_lowercase();
            heap.as_str()
        };
        // `pass` + `phrase` / `code` / `word` split across segments
        // (`passPhrase`, `pass_code`); `pass_through` stays visible.
        sensitive = lowered_segment_is_credential(lower, in_key_context)
            || (previous_is_pass
                && ["phrase", "code", "word", "wd", "key"]
                    .iter()
                    .any(|word| lower.starts_with(word)))
            // `mfa` + `code` / `seed` / … split across segments (`mfa_seed`).
            || (in_mfa_context && names_mfa_material(lower))
            || lower
                .find("mfa")
                .is_some_and(|offset| names_mfa_material(&lower[offset + "mfa".len()..]));
        sensitive = sensitive
            || is_credential_token_plural(lower, in_token_credential_context)
            // Reverse order across segments: `key_private`, `x-key-signing`.
            || (previous_is_bare_key && opens_key_context(lower));
        in_token_credential_context |= opens_token_credential_context(lower);
        previous_is_pass = ends_credential_pass(lower);
        previous_is_bare_key = is_bare_key_segment(lower);
        in_mfa_context |= lower.contains("mfa");
        // Once a qualifier appears, the context stays open for the rest of
        // the key: a later `key` segment is key material.
        in_key_context |= opens_key_context(lower);
    });
    sensitive
}

/// `api` + `key` / concatenated `apikey` credential spellings.
///
/// Covers delimiter forms (`api_key`, `api-key`), concatenated (`apikey`), and
/// acronym camelCase (`APIKey` → segments `API` + `Key`). Does not treat bare
/// `key` / `cache_key` / metric counters as sensitive.
fn is_sensitive_api_key_metadata_key(key: &str) -> bool {
    let mut has_api = false;
    let mut has_key = false;
    let mut has_apikey = false;

    for_each_metadata_key_segment(key, |segment| {
        if segment.eq_ignore_ascii_case("apikey") {
            has_apikey = true;
        }
        if segment.eq_ignore_ascii_case("api") {
            has_api = true;
        }
        if segment.eq_ignore_ascii_case("key") {
            has_key = true;
        }
    });

    has_apikey || (has_api && has_key)
}

/// Returns true when the key is request-private deduplication lifecycle state
/// that must be removed before an in-process transaction summary is built.
///
/// Fail-closed across case, delimiter, and camelCase spellings of the reserved
/// `_dedup_*` namespace: a leading `_` whose first alphanumeric segment is
/// `dedup` (ASCII case-insensitive). Canonical producer names still use
/// [`INTERNAL_ONLY_METADATA_KEY_PREFIX`]; this matcher is the shared
/// observability contract if residual lifecycle keys appear under any of those
/// spellings. Non-prefixed names (`dedup_key`, `request_dedup_*`) and longer
/// first segments (`_deduplication`) stay observable.
pub fn is_dedup_internal_metadata_key(key: &str) -> bool {
    if !key.as_bytes().first().is_some_and(|byte| *byte == b'_') {
        return false;
    }

    // Fast path for the canonical / case-folded `_dedup_*` prefix.
    if key
        .as_bytes()
        .get(..INTERNAL_ONLY_METADATA_KEY_PREFIX.len())
        .is_some_and(|prefix| {
            prefix.eq_ignore_ascii_case(INTERNAL_ONLY_METADATA_KEY_PREFIX.as_bytes())
        })
    {
        return true;
    }

    // Normalized spellings (`_dedup-…`, `_DedupRedisLockToken`, …): leading `_`
    // with first segment exactly `dedup`.
    let mut first_segment_is_dedup: Option<bool> = None;
    for_each_metadata_key_segment(key, |segment| {
        if first_segment_is_dedup.is_none() {
            first_segment_is_dedup = Some(segment.eq_ignore_ascii_case("dedup"));
        }
    });
    first_segment_is_dedup == Some(true)
}

/// Returns true when the key is an internal mesh-metrics plan or lifecycle
/// marker under the reserved `mesh.metrics.*` namespace (ASCII case-insensitive).
pub fn is_mesh_metrics_internal_metadata_key(key: &str) -> bool {
    key.as_bytes()
        .get(..INTERNAL_ONLY_MESH_METRICS_PREFIX.len())
        .is_some_and(|prefix| {
            prefix.eq_ignore_ascii_case(INTERNAL_ONLY_MESH_METRICS_PREFIX.as_bytes())
        })
}

/// Returns true when the key must never appear in external transaction-log /
/// audit projections.
///
/// This is the serialization/schema contract. Summary construction uses
/// [`is_dedup_internal_metadata_key`] for the earlier in-process strip and
/// retains `mesh.metrics.*` until built-in observers consume it.
pub fn is_internal_only_metadata_key(key: &str) -> bool {
    is_mesh_metrics_internal_metadata_key(key)
        || is_dedup_internal_metadata_key(key)
        || is_grpc_web_request_trailers_metadata_key(key)
}

/// Returns true for the gRPC-Web request-trailer staging container
/// (ASCII case-insensitive). See
/// [`INTERNAL_ONLY_GRPC_WEB_REQUEST_TRAILERS_KEY`].
pub fn is_grpc_web_request_trailers_metadata_key(key: &str) -> bool {
    key.eq_ignore_ascii_case(INTERNAL_ONLY_GRPC_WEB_REQUEST_TRAILERS_KEY)
}

/// Strip request-deduplication lifecycle keys before building an in-process
/// transaction summary.
///
/// Shared by `clone_log_metadata` and any other summary construction path so
/// `_dedup_*` coordination state cannot reach a logger even if a producer wrote
/// the legacy names into the public metadata map. Mesh metrics coordination keys
/// are intentionally retained here so built-in observers can consume disable and
/// tag-override plans before external serialization omits them.
pub fn strip_dedup_internal_metadata<MS: std::hash::BuildHasher>(
    metadata: &mut HashMap<String, String, MS>,
) {
    metadata.retain(|key, _| !is_dedup_internal_metadata_key(key));
}

/// Returns true when the given metadata key matches any sensitive substring
/// from `DEFAULT_SENSITIVE_METADATA_KEYS` plus the supplied operator extras
/// (case-insensitive). The lower-level entry point used by tests; production
/// callers should use [`is_sensitive_metadata_key`].
pub fn is_sensitive_metadata_key_with_extras(key: &str, extras: &[String]) -> bool {
    if is_internal_only_metadata_key(key) {
        // Internal-only keys are omitted before serialization; treat them as
        // sensitive so schema compile-time rejection / static_fields checks
        // also fail closed if an operator tries to project them explicitly.
        return true;
    }
    is_sensitive_name_by_listed_rules_with_extras(key, extras)
        || is_credential_class_metadata_key(key)
}

/// The listed-name rules only: the default substrings, the token and API-key
/// segment classifiers, and the operator extras, without the credential-class
/// classifier.
fn is_sensitive_name_by_listed_rules_with_extras(key: &str, extras: &[String]) -> bool {
    DEFAULT_SENSITIVE_METADATA_KEYS
        .iter()
        .any(|needle| contains_ascii_case_insensitive(key, needle))
        || is_sensitive_token_metadata_key(key)
        || is_sensitive_api_key_metadata_key(key)
        || extras
            .iter()
            .any(|needle| contains_ascii_case_insensitive(key, needle))
}

/// Sensitivity floor for names that are NOT transaction metadata keys: admin
/// plugin-config field names and free-text debug lines.
///
/// Those inputs carry ordinary configuration vocabulary (`session_ttl_seconds`,
/// `allowed_signature_algorithms`, `max_sessions_per_principal`) or prose,
/// where the credential-class classifier would hide non-secret values. They
/// keep the listed rules; the config projection layers its own schema-driven
/// and name-based rules on top. Metadata, header-tag and log-schema checks use
/// [`is_sensitive_metadata_key`].
pub fn is_sensitive_name_by_listed_rules(key: &str) -> bool {
    if is_internal_only_metadata_key(key) {
        return true;
    }
    is_sensitive_name_by_listed_rules_with_extras(key, extra_redacted_keys())
}

/// Returns true when the given metadata key is sensitive against the global
/// (env-driven) extras list.
pub fn is_sensitive_metadata_key(key: &str) -> bool {
    is_sensitive_metadata_key_with_extras(key, extra_redacted_keys())
}

/// Returns true when the key matches an operator-supplied sensitive substring.
///
/// This narrower entry point lets credential-admission boundaries honor
/// `FERRUM_LOG_REDACT_METADATA_KEYS` without inheriting the built-in log
/// redactor's deliberately broad substring rules.
pub(crate) fn is_operator_sensitive_metadata_key(key: &str) -> bool {
    extra_redacted_keys()
        .iter()
        .any(|needle| contains_ascii_case_insensitive(key, needle))
}

/// Serde `serialize_with` adapter for `HashMap<String, String>` metadata
/// fields on log summary structs. Replaces the value with
/// `REDACTED_PLACEHOLDER` for any key that is not allowlisted or that the
/// deny layer matches ([`metadata_value_is_redacted`]).
/// Internal-only lifecycle keys are omitted entirely. Non-sensitive keys pass
/// through unchanged.
///
/// The serialized order is the natural HashMap iteration order — same as the
/// default `Serialize` impl for `HashMap`. Logs are not sorted by key today,
/// so this preserves existing dashboard semantics.
pub fn serialize_redacted_metadata<MS: std::hash::BuildHasher, S>(
    metadata: &HashMap<String, String, MS>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    RedactedMetadata(metadata).serialize(serializer)
}

/// Serializable borrowed view used by manual summary serializers and schema
/// views. Keeping this wrapper here preserves one redaction implementation for
/// every transaction-log sink.
pub struct RedactedMetadata<'a, MS = std::collections::hash_map::RandomState>(
    pub &'a HashMap<String, String, MS>,
);

impl<MS: std::hash::BuildHasher> Serialize for RedactedMetadata<'_, MS> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let metadata = self.0;
        let emit_count = metadata
            .keys()
            .filter(|key| !is_internal_only_metadata_key(key))
            .count();
        let mut map = serializer.serialize_map(Some(emit_count))?;
        for (key, value) in metadata {
            if is_internal_only_metadata_key(key) {
                continue;
            }
            if metadata_value_is_redacted(key) {
                map.serialize_entry(key, REDACTED_PLACEHOLDER)?;
            } else {
                map.serialize_entry(key, value)?;
            }
        }
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_keys_match_case_insensitively() {
        let extras: Vec<String> = Vec::new();
        assert!(is_sensitive_metadata_key_with_extras(
            "authorization",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras(
            "Authorization",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras(
            "AUTHORIZATION",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras("Cookie", &extras));
        assert!(is_sensitive_metadata_key_with_extras("Set-Cookie", &extras));
        assert!(is_sensitive_metadata_key_with_extras("X-Api-Key", &extras));
        assert!(is_sensitive_metadata_key_with_extras(
            "X-Auth-Token",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras(
            "X-CSRF-Token",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras(
            "session_token",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras(
            "user_password",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras("api_secret", &extras));
        assert!(is_sensitive_metadata_key_with_extras("Bearer", &extras));
        assert!(is_sensitive_metadata_key_with_extras(
            "sse:last_event_id",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras(
            "Last-Event-ID",
            &extras
        ));
    }

    #[test]
    fn substring_match_catches_prefixed_or_suffixed_keys() {
        // Custom plugins often namespace keys, so substring beats exact match.
        let extras: Vec<String> = Vec::new();
        assert!(is_sensitive_metadata_key_with_extras(
            "downstream_authorization",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras(
            "legacy.cookie.value",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras(
            "auth.bearer.value",
            &extras
        ));
        // `x-api-key` (hyphenated) only matches when the key uses hyphens.
        assert!(is_sensitive_metadata_key_with_extras("X-API-KEY", &extras));
    }

    #[test]
    fn token_secret_keys_match_without_redacting_token_metrics() {
        let extras: Vec<String> = Vec::new();

        for key in [
            "token",
            "token_value",
            "session_token_v2",
            "access_token",
            "refreshToken",
            "id-token",
            "apiToken",
            "csrf_token",
            "auth.session.token",
        ] {
            assert!(
                is_sensitive_metadata_key_with_extras(key, &extras),
                "{key} should be redacted"
            );
        }

        for key in [
            "ai_total_tokens",
            "ai_prompt_tokens",
            "ai_completion_tokens",
            "llm_total_tokens",
            "completion_tokens",
        ] {
            assert!(
                !is_sensitive_metadata_key_with_extras(key, &extras),
                "{key} should remain visible"
            );
        }
    }

    #[test]
    fn token_segmentation_preserves_camel_case_and_non_ascii_boundaries() {
        let extras: Vec<String> = Vec::new();
        assert!(is_sensitive_metadata_key_with_extras(
            "refreshToken",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras(
            "sessionétoken",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras("APIToken", &extras));
        assert!(is_sensitive_metadata_key_with_extras("APIKey", &extras));
    }

    #[test]
    fn api_key_spellings_match_without_redacting_token_metrics() {
        let extras: Vec<String> = Vec::new();

        for key in [
            "api_key",
            "api-key",
            "apikey",
            "APIKey",
            "API_KEY",
            "x-api-key",
            "openai_api_key",
            "APIToken",
        ] {
            assert!(
                is_sensitive_metadata_key_with_extras(key, &extras),
                "{key} should be redacted"
            );
        }

        for key in [
            "ai_total_tokens",
            "ai_prompt_tokens",
            "cache_key",
            "routing_key",
            "api_response_count",
            "keyboard_layout",
        ] {
            assert!(
                !is_sensitive_metadata_key_with_extras(key, &extras),
                "{key} should remain visible"
            );
        }
    }

    #[test]
    fn internal_only_dedup_keys_are_sensitive_and_omitted_on_serialize() {
        let extras: Vec<String> = Vec::new();
        for key in [
            "_dedup_key",
            "_dedup_fingerprint",
            "_dedup_local_inflight_token",
            "_dedup_redis_lock_token",
            "_DEDUP_REDIS_LOCK_TOKEN",
            "_DeDuP_Local_Inflight_Token",
            "_dedup-redis-lock-token",
            "_DedupRedisLockToken",
        ] {
            assert!(
                is_internal_only_metadata_key(key),
                "{key} must be internal-only"
            );
            assert!(
                is_sensitive_metadata_key_with_extras(key, &extras),
                "{key} must fail closed for schema / static field checks"
            );
        }
        for key in [
            "dedup_key",
            "request_dedup_key",
            "_deduplication",
            "cache_key",
        ] {
            assert!(
                !is_internal_only_metadata_key(key),
                "{key} must not be internal-only"
            );
        }

        let mut metadata = HashMap::new();
        metadata.insert("_dedup_key".to_string(), "idem-secret".to_string());
        metadata.insert("_dedup_fingerprint".to_string(), "fp-secret".to_string());
        metadata.insert(
            "_dedup_local_inflight_token".to_string(),
            "local-secret".to_string(),
        );
        metadata.insert(
            "_dedup_redis_lock_token".to_string(),
            "redis-secret".to_string(),
        );
        metadata.insert(
            "_DEDUP_REDIS_LOCK_TOKEN".to_string(),
            "upper-redis-secret".to_string(),
        );
        metadata.insert(
            "_DedupRedisLockToken".to_string(),
            "camel-redis-secret".to_string(),
        );
        metadata.insert("trace_id".to_string(), "abc-123".to_string());
        // A reviewed built-in dedup-adjacent key (exact allowlist), so the
        // control stays visible while `_dedup_*` lifecycle keys are omitted.
        metadata.insert(
            "request_deduplication.replayed".to_string(),
            "visible-control".to_string(),
        );

        let json = serde_json::to_string(&MetadataWrapper(&metadata)).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["trace_id"], "abc-123");
        assert_eq!(parsed["request_deduplication.replayed"], "visible-control");
        for key in [
            "_dedup_key",
            "_dedup_fingerprint",
            "_dedup_local_inflight_token",
            "_dedup_redis_lock_token",
            "_DEDUP_REDIS_LOCK_TOKEN",
            "_DedupRedisLockToken",
        ] {
            assert!(
                parsed.get(key).is_none(),
                "{key} must be omitted from log projection, got: {json}"
            );
        }
        for leaked in [
            "idem-secret",
            "fp-secret",
            "local-secret",
            "redis-secret",
            "upper-redis-secret",
            "camel-redis-secret",
        ] {
            assert!(
                !json.contains(leaked),
                "lifecycle value leaked from projection"
            );
        }
    }

    #[test]
    fn non_sensitive_keys_pass_through() {
        let extras: Vec<String> = Vec::new();
        assert!(!is_sensitive_metadata_key_with_extras(
            "correlation_id",
            &extras
        ));
        assert!(!is_sensitive_metadata_key_with_extras("trace_id", &extras));
        assert!(!is_sensitive_metadata_key_with_extras(
            "request_id",
            &extras
        ));
        assert!(!is_sensitive_metadata_key_with_extras(
            "backend_resolved_ip",
            &extras
        ));
        assert!(!is_sensitive_metadata_key_with_extras(
            "response_size_bytes",
            &extras
        ));
        assert!(!is_sensitive_metadata_key_with_extras(
            "ai_total_tokens",
            &extras
        ));
        assert!(!is_sensitive_metadata_key_with_extras("", &extras));
    }

    #[test]
    fn extras_match_case_insensitively() {
        let extras = parse_extras_list("custom_field, MY-SECRET ,session_id");
        assert_eq!(
            extras,
            vec![
                "custom_field".to_string(),
                "my-secret".to_string(),
                "session_id".to_string()
            ]
        );
        assert!(is_sensitive_metadata_key_with_extras(
            "custom_field",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras(
            "CUSTOM_FIELD",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras(
            "ns.my-secret.value",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras("session_id", &extras));
        assert!(!is_sensitive_metadata_key_with_extras(
            "benign_key",
            &extras
        ));
    }

    #[test]
    fn parse_extras_skips_empty_and_whitespace_entries() {
        let extras = parse_extras_list(" , a , , b ,  ");
        assert_eq!(extras, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn serialize_redacts_default_sensitive_keys() {
        let mut metadata = HashMap::new();
        metadata.insert("authorization".to_string(), "Bearer secret".to_string());
        metadata.insert("trace_id".to_string(), "abc-123".to_string());

        let json = match serde_json::to_string(&MetadataWrapper(&metadata)) {
            Ok(json) => json,
            Err(error) => panic!("metadata serialization failed: {error}"),
        };

        assert!(
            json.contains(r#""authorization":"[REDACTED]""#),
            "authorization value should be redacted, got: {}",
            json
        );
        assert!(
            !json.contains("Bearer secret"),
            "raw bearer value must not leak, got: {}",
            json
        );
        assert!(
            json.contains(r#""trace_id":"abc-123""#),
            "trace_id should pass through, got: {}",
            json
        );
    }

    /// Test-only newtype wrapper so we can exercise `serialize_redacted_metadata`
    /// directly without depending on `TransactionSummary`'s full schema.
    struct MetadataWrapper<'a>(&'a HashMap<String, String>);
    impl<'a> serde::Serialize for MetadataWrapper<'a> {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            serialize_redacted_metadata(self.0, s)
        }
    }

    // ── contains_ascii_case_insensitive edge cases ───────────────────────

    #[test]
    fn contains_ascii_case_insensitive_empty_needle_returns_false() {
        assert!(!contains_ascii_case_insensitive("anything", ""));
    }

    #[test]
    fn contains_ascii_case_insensitive_needle_longer_than_haystack() {
        assert!(!contains_ascii_case_insensitive("ab", "abc"));
    }

    #[test]
    fn contains_ascii_case_insensitive_exact_match() {
        assert!(contains_ascii_case_insensitive("secret", "secret"));
        assert!(contains_ascii_case_insensitive("SECRET", "secret"));
        assert!(contains_ascii_case_insensitive("Secret", "secret"));
    }

    #[test]
    fn contains_ascii_case_insensitive_partial_match() {
        assert!(contains_ascii_case_insensitive("my_secret_key", "secret"));
        assert!(contains_ascii_case_insensitive("MY_SECRET_KEY", "secret"));
    }

    #[test]
    fn contains_ascii_case_insensitive_no_match() {
        assert!(!contains_ascii_case_insensitive("request_id", "secret"));
    }

    #[test]
    fn contains_ascii_case_insensitive_both_empty() {
        // Empty needle is always false by design (nothing to match).
        assert!(!contains_ascii_case_insensitive("", ""));
    }

    // ── key segmentation direct tests ────────────────────────────────────

    #[test]
    fn segments_camel_case_correctly() {
        let mut segments = Vec::new();
        for_each_metadata_key_segment("refreshToken", |s| segments.push(s.to_string()));
        assert_eq!(segments, vec!["refresh", "Token"]);
    }

    #[test]
    fn segments_underscore_delimited_key() {
        let mut segments = Vec::new();
        for_each_metadata_key_segment("api_key_value", |s| segments.push(s.to_string()));
        assert_eq!(segments, vec!["api", "key", "value"]);
    }

    #[test]
    fn segments_hyphen_delimited_key() {
        let mut segments = Vec::new();
        for_each_metadata_key_segment("x-auth-token", |s| segments.push(s.to_string()));
        assert_eq!(segments, vec!["x", "auth", "token"]);
    }

    #[test]
    fn segments_dot_delimited_key() {
        let mut segments = Vec::new();
        for_each_metadata_key_segment("auth.session.token", |s| segments.push(s.to_string()));
        assert_eq!(segments, vec!["auth", "session", "token"]);
    }

    #[test]
    fn segments_mixed_delimiters() {
        let mut segments = Vec::new();
        for_each_metadata_key_segment("ns.myToken_value", |s| segments.push(s.to_string()));
        assert_eq!(segments, vec!["ns", "my", "Token", "value"]);
    }

    #[test]
    fn segments_acronym_then_camel_case_split() {
        // `APIToken` / `APIKey` split the leading acronym from the final
        // capitalized word so credential classifiers see `api` + `token` /
        // `api` + `key`.
        let mut token_segments = Vec::new();
        for_each_metadata_key_segment("APIToken", |s| token_segments.push(s.to_string()));
        assert_eq!(token_segments, vec!["API", "Token"]);

        let mut key_segments = Vec::new();
        for_each_metadata_key_segment("APIKey", |s| key_segments.push(s.to_string()));
        assert_eq!(key_segments, vec!["API", "Key"]);
    }

    #[test]
    fn segments_single_character_key() {
        let mut segments = Vec::new();
        for_each_metadata_key_segment("a", |s| segments.push(s.to_string()));
        assert_eq!(segments, vec!["a"]);
    }

    #[test]
    fn segments_empty_key() {
        let mut segments = Vec::new();
        for_each_metadata_key_segment("", |s| segments.push(s.to_string()));
        assert!(segments.is_empty());
    }

    #[test]
    fn segments_only_delimiters() {
        let mut segments = Vec::new();
        for_each_metadata_key_segment("---___...", |s| segments.push(s.to_string()));
        assert!(segments.is_empty());
    }

    #[test]
    fn segments_non_ascii_boundary() {
        // Non-ASCII chars act as delimiters between ASCII segments.
        let mut segments = Vec::new();
        for_each_metadata_key_segment("sessionétoken", |s| segments.push(s.to_string()));
        assert_eq!(segments, vec!["session", "token"]);
    }

    #[test]
    fn segments_trailing_non_ascii() {
        let mut segments = Vec::new();
        for_each_metadata_key_segment("tokenü", |s| segments.push(s.to_string()));
        assert_eq!(segments, vec!["token"]);
    }

    #[test]
    fn segments_leading_non_ascii() {
        let mut segments = Vec::new();
        for_each_metadata_key_segment("ütokené", |s| segments.push(s.to_string()));
        assert_eq!(segments, vec!["token"]);
    }

    #[test]
    fn segments_digits_treated_as_lowercase() {
        // Digit → uppercase transition splits, matching camelCase behavior.
        let mut segments = Vec::new();
        for_each_metadata_key_segment("token2Value", |s| segments.push(s.to_string()));
        assert_eq!(segments, vec!["token2", "Value"]);
    }

    // ── is_sensitive_token_metadata_key direct tests ─────────────────────

    #[test]
    fn bare_token_is_sensitive() {
        assert!(is_sensitive_token_metadata_key("token"));
    }

    #[test]
    fn token_with_value_descriptor_is_sensitive() {
        // "value" is a TOKEN_VALUE_SEGMENTS entry, so token+value is still
        // sensitive (single token segment + all others are value descriptors).
        assert!(is_sensitive_token_metadata_key("token_value"));
        assert!(is_sensitive_token_metadata_key("token_hash"));
        assert!(is_sensitive_token_metadata_key("token_sha256"));
    }

    #[test]
    fn token_with_any_context_segment_is_sensitive() {
        for key in [
            "access_token",
            "vendor_token",
            "openaiToken",
            "deployment.token",
        ] {
            assert!(
                is_sensitive_token_metadata_key(key),
                "{key} should be sensitive"
            );
        }
    }

    #[test]
    fn token_with_non_sensitive_context_is_not_sensitive() {
        // "total" is neither a context segment nor a value descriptor.
        assert!(!is_sensitive_token_metadata_key("total_tokens"));
        assert!(!is_sensitive_token_metadata_key("ai_completion_tokens"));
        assert!(!is_sensitive_token_metadata_key("prompt_tokens"));
    }

    #[test]
    fn no_token_segment_is_not_sensitive() {
        assert!(!is_sensitive_token_metadata_key("password"));
        assert!(!is_sensitive_token_metadata_key("secret_key"));
        assert!(!is_sensitive_token_metadata_key(""));
    }

    // ── each default key substring individually ──────────────────────────

    #[test]
    fn each_default_sensitive_key_individually_redacts() {
        let extras: Vec<String> = Vec::new();
        for default_key in DEFAULT_SENSITIVE_METADATA_KEYS {
            assert!(
                is_sensitive_metadata_key_with_extras(default_key, &extras),
                "bare default key {default_key:?} should be sensitive"
            );
            // Prefixed
            let prefixed = format!("my_{default_key}");
            assert!(
                is_sensitive_metadata_key_with_extras(&prefixed, &extras),
                "prefixed key {prefixed:?} should be sensitive"
            );
            // Suffixed
            let suffixed = format!("{default_key}_value");
            assert!(
                is_sensitive_metadata_key_with_extras(&suffixed, &extras),
                "suffixed key {suffixed:?} should be sensitive"
            );
            // Uppercased
            let upper = default_key.to_ascii_uppercase();
            assert!(
                is_sensitive_metadata_key_with_extras(&upper, &extras),
                "uppercased key {upper:?} should be sensitive"
            );
        }
    }

    // ── additional case-insensitivity tests ──────────────────────────────

    #[test]
    fn title_case_x_api_key_redacts() {
        let extras: Vec<String> = Vec::new();
        assert!(is_sensitive_metadata_key_with_extras("X-Api-Key", &extras));
    }

    #[test]
    fn mixed_case_bearer_redacts() {
        let extras: Vec<String> = Vec::new();
        assert!(is_sensitive_metadata_key_with_extras("bEaReR", &extras));
    }

    // ── operator-supplied extras ─────────────────────────────────────────

    #[test]
    fn multiple_comma_separated_extras_all_redact() {
        let extras = parse_extras_list("corp-key, internal-id, x-trace");
        assert!(is_sensitive_metadata_key_with_extras("corp-key", &extras));
        assert!(is_sensitive_metadata_key_with_extras(
            "internal-id",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras("x-trace", &extras));
    }

    #[test]
    fn extras_are_case_insensitive_on_match() {
        let extras = parse_extras_list("MyCustom");
        assert!(is_sensitive_metadata_key_with_extras("mycustom", &extras));
        assert!(is_sensitive_metadata_key_with_extras("MYCUSTOM", &extras));
        assert!(is_sensitive_metadata_key_with_extras(
            "prefix_MyCustom_suffix",
            &extras
        ));
    }

    #[test]
    fn extras_do_not_interfere_with_defaults() {
        let extras = parse_extras_list("custom1");
        // Defaults still work with extras present.
        assert!(is_sensitive_metadata_key_with_extras(
            "authorization",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras("password", &extras));
        // And the custom still works.
        assert!(is_sensitive_metadata_key_with_extras("custom1", &extras));
    }

    // ── edge cases: empty and degenerate inputs ─────────────────────────

    #[test]
    fn empty_key_is_not_sensitive() {
        let extras: Vec<String> = Vec::new();
        assert!(!is_sensitive_metadata_key_with_extras("", &extras));
    }

    #[test]
    fn key_is_only_the_sensitive_substring() {
        let extras: Vec<String> = Vec::new();
        assert!(is_sensitive_metadata_key_with_extras("secret", &extras));
        assert!(is_sensitive_metadata_key_with_extras("password", &extras));
        assert!(is_sensitive_metadata_key_with_extras("bearer", &extras));
        assert!(is_sensitive_metadata_key_with_extras("cookie", &extras));
        assert!(is_sensitive_metadata_key_with_extras("token", &extras));
    }

    #[test]
    fn sensitive_key_with_empty_value_still_redacted_in_serialization() {
        let mut metadata = HashMap::new();
        metadata.insert("authorization".to_string(), String::new());

        let json = serde_json::to_string(&MetadataWrapper(&metadata)).unwrap();
        assert!(
            json.contains(r#""authorization":"[REDACTED]""#),
            "even an empty value should be replaced with [REDACTED], got: {}",
            json
        );
        // The empty string should NOT appear as the value.
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["authorization"], "[REDACTED]");
    }

    #[test]
    fn request_metadata_is_not_sensitive() {
        // "requestMetadata" segments to ["request", "Metadata"], neither of
        // which is a default sensitive substring nor a token context segment.
        let extras: Vec<String> = Vec::new();
        assert!(!is_sensitive_metadata_key_with_extras(
            "requestMetadata",
            &extras
        ));
    }

    // ── serialization: multiple sensitive keys ───────────────────────────

    #[test]
    fn multiple_sensitive_keys_all_redacted_independently() {
        let mut metadata = HashMap::new();
        metadata.insert("authorization".to_string(), "Bearer secret-1".to_string());
        metadata.insert("cookie".to_string(), "sid=abc".to_string());
        metadata.insert("password".to_string(), "hunter2".to_string());
        metadata.insert("request_id".to_string(), "visible".to_string());
        metadata.insert("safe_key".to_string(), "unlisted".to_string());

        let json = serde_json::to_string(&MetadataWrapper(&metadata)).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["authorization"], "[REDACTED]");
        assert_eq!(parsed["cookie"], "[REDACTED]");
        assert_eq!(parsed["password"], "[REDACTED]");
        assert_eq!(parsed["request_id"], "visible");
        // Not allowlisted: redacted by default (issue #6619).
        assert_eq!(parsed["safe_key"], "[REDACTED]");

        for leaked in ["secret-1", "sid=abc", "hunter2"] {
            assert!(
                !json.contains(leaked),
                "sensitive value {leaked:?} leaked: {json}"
            );
        }
    }

    // ── fail-closed allowlist (issue #6619) ──────────────────────────────

    #[test]
    fn builtin_allowlist_is_exact_keys_and_fixed_grammar_families() {
        for key in [
            "mesh.source.workload",
            "grpc_web_mode",
            "compression:algorithm",
            "request_id",
            "ai_total_tokens",
            "trace_id",
            "namespace",
            "waf.action",
            "grpc_web.instance.7.mode",
            "correlation_id.instance.x-request-id",
            "ai_semantic_firewall.request.rule_ids",
            "ai_semantic_cache.12.cache_status",
            "ai_prompt_compressor.instances.3.tokens_saved",
            "ai_ratelimit_remaining#42",
        ] {
            assert!(is_builtin_safe_metadata_name(key), "{key}");
        }
        // Unknown names beneath a built-in prefix are not allowlisted.
        for key in [
            "mesh.vault_blob",
            "mesh.projectpinopaque",
            "mcp.custom_blob",
            "grpc_web.instance.7.secret_blob",
            "ai_semantic_cache.12.cache_key",
            "ai_semantic_cache.x.cache_status",
            "ai_ratelimit_remaining#x",
            "correlation_id.instance.a.b",
            "request_body",
            "response_body",
            "custom_field",
            "gpgpass_phrase",
            "key_private",
            "vault_blob",
        ] {
            assert!(!is_builtin_safe_metadata_name(key), "{key}");
        }
    }

    #[test]
    fn payload_keys_are_never_emitted_whatever_the_allowlist() {
        let none: Vec<String> = Vec::new();
        let parsed = parse_safe_metadata_keys(Some(
            "request_body, response_body, request*, response*, *".into(),
        ));
        assert_eq!(parsed.rejected, vec!["request_body", "response_body"]);
        for key in ["request_body", "response_body", "REQUEST_BODY"] {
            assert!(
                metadata_value_is_redacted_with(key, &parsed.accepted, &none),
                "{key}"
            );
            let exact = vec![key.to_ascii_lowercase()];
            assert!(metadata_value_is_redacted_with(key, &exact, &none), "{key}");
        }
    }

    #[test]
    fn unknown_names_are_redacted_by_default_and_deny_beats_allow() {
        let none: Vec<String> = Vec::new();
        // Adversarial spellings the classifier has missed in review rounds:
        // all redacted by default because they are not allowlisted.
        for key in [
            "gpgpass_phrase",
            "key_private",
            "privateKeY",
            "hsm_pin\u{e9}",
            "vault_blob",
            "x-key-private",
        ] {
            assert!(metadata_value_is_redacted_with(key, &none, &none), "{key}");
        }
        assert!(!metadata_value_is_redacted_with("request_id", &none, &none));

        let parsed = parse_safe_metadata_keys(Some(
            "tenant_tier, Tenant.*, session_id, key_private".into(),
        ));
        assert_eq!(parsed.accepted, vec!["tenant_tier", "tenant.*"]);
        assert_eq!(parsed.rejected, vec!["session_id", "key_private"]);
        assert!(!metadata_value_is_redacted_with(
            "TENANT_TIER",
            &parsed.accepted,
            &none
        ));
        assert!(!metadata_value_is_redacted_with(
            "tenant.region",
            &parsed.accepted,
            &none
        ));
        assert!(metadata_value_is_redacted_with(
            "tenant_region",
            &parsed.accepted,
            &none
        ));
        // A built-in or allowlisted name the deny layer matches stays redacted.
        let session = vec!["mesh.session_id".to_string()];
        assert!(metadata_value_is_redacted_with(
            "mesh.session_id",
            &session,
            &none
        ));
        let extras = vec!["tier".to_string()];
        assert!(metadata_value_is_redacted_with(
            "tenant_tier",
            &parsed.accepted,
            &extras
        ));
    }

    // ── serialization: empty metadata map ────────────────────────────────

    #[test]
    fn serialize_empty_metadata_map() {
        let metadata: HashMap<String, String> = HashMap::new();
        let json = serde_json::to_string(&MetadataWrapper(&metadata)).unwrap();
        assert_eq!(json, "{}");
    }

    // ── serialization: original map not modified ─────────────────────────

    #[test]
    fn serialize_does_not_modify_original_map() {
        let mut metadata = HashMap::new();
        metadata.insert("authorization".to_string(), "Bearer leak-me".to_string());
        metadata.insert("trace_id".to_string(), "t-1".to_string());

        // Serialize (which redacts).
        let _json = serde_json::to_string(&MetadataWrapper(&metadata)).unwrap();

        // Original map must be untouched.
        assert_eq!(metadata["authorization"], "Bearer leak-me");
        assert_eq!(metadata["trace_id"], "t-1");
    }

    // ── parse_extras_list edge cases ─────────────────────────────────────

    #[test]
    fn parse_extras_empty_string() {
        let extras = parse_extras_list("");
        assert!(extras.is_empty());
    }

    #[test]
    fn parse_extras_single_entry() {
        let extras = parse_extras_list("custom");
        assert_eq!(extras, vec!["custom".to_string()]);
    }

    #[test]
    fn parse_extras_preserves_hyphens_and_underscores() {
        let extras = parse_extras_list("my-key, my_key");
        assert_eq!(extras, vec!["my-key".to_string(), "my_key".to_string()]);
    }

    // ── delimiter-based segmentation for token detection ─────────────────

    #[test]
    fn underscore_delimited_token_key_is_sensitive() {
        let extras: Vec<String> = Vec::new();
        assert!(is_sensitive_metadata_key_with_extras(
            "access_token",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras("csrf_token", &extras));
    }

    #[test]
    fn hyphen_delimited_token_key_is_sensitive() {
        let extras: Vec<String> = Vec::new();
        assert!(is_sensitive_metadata_key_with_extras("id-token", &extras));
        assert!(is_sensitive_metadata_key_with_extras("auth-token", &extras));
    }

    #[test]
    fn dot_delimited_token_key_is_sensitive() {
        let extras: Vec<String> = Vec::new();
        assert!(is_sensitive_metadata_key_with_extras(
            "auth.session.token",
            &extras
        ));
    }

    #[test]
    fn camel_case_token_key_is_sensitive() {
        let extras: Vec<String> = Vec::new();
        assert!(is_sensitive_metadata_key_with_extras(
            "refreshToken",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras(
            "accessToken",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras(
            "sessionToken",
            &extras
        ));
    }

    #[test]
    fn acronym_api_token_and_api_key_are_sensitive() {
        let extras: Vec<String> = Vec::new();
        assert!(is_sensitive_metadata_key_with_extras("APIToken", &extras));
        assert!(is_sensitive_metadata_key_with_extras("APIKey", &extras));
        assert!(is_sensitive_metadata_key_with_extras("apikey", &extras));
        assert!(is_sensitive_metadata_key_with_extras("api_key", &extras));
        assert!(is_sensitive_metadata_key_with_extras("api-key", &extras));
    }

    // ── REDACTED_PLACEHOLDER value ───────────────────────────────────────

    #[test]
    fn redacted_placeholder_is_expected_string() {
        assert_eq!(REDACTED_PLACEHOLDER, "[REDACTED]");
    }
}

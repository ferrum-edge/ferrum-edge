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
//! `ai_total_tokens` stay visible.
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
pub fn strip_dedup_internal_metadata(metadata: &mut HashMap<String, String>) {
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
    if DEFAULT_SENSITIVE_METADATA_KEYS
        .iter()
        .any(|needle| contains_ascii_case_insensitive(key, needle))
        || is_sensitive_token_metadata_key(key)
        || is_sensitive_api_key_metadata_key(key)
    {
        return true;
    }
    extras
        .iter()
        .any(|needle| contains_ascii_case_insensitive(key, needle))
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
/// `REDACTED_PLACEHOLDER` for any key that matches a sensitive substring.
/// Internal-only lifecycle keys are omitted entirely. Non-sensitive keys pass
/// through unchanged.
///
/// The serialized order is the natural HashMap iteration order — same as the
/// default `Serialize` impl for `HashMap`. Logs are not sorted by key today,
/// so this preserves existing dashboard semantics.
pub fn serialize_redacted_metadata<S>(
    metadata: &HashMap<String, String>,
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
pub struct RedactedMetadata<'a>(pub &'a HashMap<String, String>);

impl Serialize for RedactedMetadata<'_> {
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
            if is_sensitive_metadata_key(key) {
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
        metadata.insert(
            "request_dedup_key".to_string(),
            "visible-control".to_string(),
        );

        let json = serde_json::to_string(&MetadataWrapper(&metadata)).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["trace_id"], "abc-123");
        assert_eq!(parsed["request_dedup_key"], "visible-control");
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
        metadata.insert("safe_key".to_string(), "visible".to_string());

        let json = serde_json::to_string(&MetadataWrapper(&metadata)).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["authorization"], "[REDACTED]");
        assert_eq!(parsed["cookie"], "[REDACTED]");
        assert_eq!(parsed["password"], "[REDACTED]");
        assert_eq!(parsed["safe_key"], "visible");

        for leaked in ["secret-1", "sid=abc", "hunter2"] {
            assert!(
                !json.contains(leaked),
                "sensitive value {leaked:?} leaked: {json}"
            );
        }
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

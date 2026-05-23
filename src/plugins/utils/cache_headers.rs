//! Shared response-header sanitization for caching plugins.
//!
//! Plugins that store and replay backend responses (e.g.,
//! [`ai_semantic_cache`](crate::plugins::ai_semantic_cache),
//! [`request_deduplication`](crate::plugins::request_deduplication)) MUST
//! strip per-response identity, per-request trace identifiers, and
//! per-request rate-limit counters before persisting the response.
//! Otherwise a cache hit replays the original consumer's session cookies,
//! auth tokens, trace IDs, and rate-limit quota to every subsequent client
//! sharing the cache key — a session-hijack / state-leak vector.
//!
//! This module centralizes the header lists so all caching plugins agree
//! on what is unsafe to replay; any future addition (new auth scheme,
//! new tracing header) is picked up by every caller automatically.
//!
//! Hop-by-hop headers (RFC 9110 §7.6.1: `connection`, `keep-alive`,
//! `proxy-authenticate`, `proxy-connection`, `te`, `trailer`,
//! `transfer-encoding`, `upgrade`) are intentionally NOT listed here —
//! they are stripped upstream by the proxy response-collection paths
//! (`collect_response_headers`, `collect_hyper_response_headers`,
//! `grpc_proxy`, `http3/server`) before `on_final_response_body` runs,
//! so they cannot reach a caching plugin.

use std::collections::HashMap;

/// Exact-match sensitive response headers. Comparisons are ASCII
/// case-insensitive (RFC 9110 §5.1). See [`SENSITIVE_HEADER_PREFIXES`] for
/// families that must match by prefix instead (provider rate-limit
/// variants, multi-header B3 tracing).
const SENSITIVE_EXACT_HEADERS: &[&str] = &[
    // Per-response identity / session state.
    "set-cookie",
    "set-cookie2",
    "authorization",
    "www-authenticate",
    "x-api-key",
    "x-amz-security-token",
    "x-amz-request-id",
    "x-amz-apigw-id",
    "x-amzn-request-id",
    "x-amzn-requestid",
    "x-amzn-trace-id",
    // Per-request trace identifiers — replaying these would splice the
    // original request's trace into every subsequent cache hit.
    "x-request-id",
    "x-correlation-id",
    "x-trace-id",
    "traceparent",
    "tracestate",
    // Zipkin B3 single-header format (RFC-less; defined by openzipkin/b3-propagation).
    // Multi-header B3 (`x-b3-traceid`, `x-b3-spanid`, `x-b3-parentspanid`,
    // `x-b3-sampled`, `x-b3-flags`) is covered by the `x-b3-` prefix below.
    "b3",
    // Per-request retry signal — the stored value reflects the original
    // response's retry timing and is misleading on a cache hit.
    "retry-after",
];

/// Case-insensitive prefixes for sensitive header families. These exist
/// because providers emit suffixed variants that an exact-match list
/// cannot enumerate safely:
///
/// - `x-ratelimit-` covers the IETF-draft canonical names
///   (`x-ratelimit-limit`, `-remaining`, `-reset`) AND provider variants
///   like OpenAI's `x-ratelimit-limit-requests`, `-limit-tokens`,
///   `-remaining-requests`, `-remaining-tokens`, `-reset-requests`,
///   `-reset-tokens`.
/// - `x-ai-ratelimit-` covers Ferrum Edge's own `ai_rate_limiter` output
///   (`-limit`, `-remaining`, `-window`, `-usage`) and future additions.
/// - `anthropic-ratelimit-` covers Anthropic's rate-limit family
///   (`anthropic-ratelimit-requests-limit`, `-tokens-remaining`, etc.).
/// - `x-b3-` covers the multi-header B3 tracing variant
///   (`x-b3-traceid`, `-spanid`, `-parentspanid`, `-sampled`, `-flags`).
const SENSITIVE_HEADER_PREFIXES: &[&str] = &[
    "x-ratelimit-",
    "x-ai-ratelimit-",
    "anthropic-ratelimit-",
    "x-b3-",
];

/// Case-insensitive check for whether a header name is sensitive.
/// Uses byte-slice `eq_ignore_ascii_case` to avoid a per-call
/// `to_ascii_lowercase` allocation. Prefix match is safe on byte
/// boundaries because all prefixes are ASCII.
pub fn is_sensitive_header(name: &str) -> bool {
    if SENSITIVE_EXACT_HEADERS
        .iter()
        .any(|s| name.eq_ignore_ascii_case(s))
    {
        return true;
    }
    let name_bytes = name.as_bytes();
    SENSITIVE_HEADER_PREFIXES.iter().any(|prefix| {
        let prefix_bytes = prefix.as_bytes();
        name_bytes.len() >= prefix_bytes.len()
            && name_bytes[..prefix_bytes.len()].eq_ignore_ascii_case(prefix_bytes)
    })
}

/// Strip security-sensitive headers from a response header map before the
/// cache stores or replays it.
pub fn sanitize_cached_headers(headers: &HashMap<String, String>) -> HashMap<String, String> {
    headers
        .iter()
        .filter(|(name, _)| !is_sensitive_header(name))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_cached_headers_strips_security_sensitive_keys() {
        // Cached responses must never replay per-response identity (cookies,
        // auth tokens, trace IDs) or per-request rate-limit counters to a
        // different consumer. The stripper is case-insensitive because HTTP
        // header names are case-insensitive.
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("Set-Cookie".to_string(), "session=abc123".to_string());
        headers.insert("authorization".to_string(), "Bearer xyz".to_string());
        headers.insert("X-Request-Id".to_string(), "req-12345-abcdef".to_string());
        headers.insert("X-Amz-Request-Id".to_string(), "aws-req-123".to_string());
        headers.insert("X-Amz-Apigw-Id".to_string(), "api-gw-123".to_string());
        headers.insert("X-Amzn-Request-Id".to_string(), "amzn-req-123".to_string());
        headers.insert("X-Amzn-Trace-Id".to_string(), "Root=1-abc".to_string());
        headers.insert("X-AI-RateLimit-Remaining".to_string(), "42".to_string());
        headers.insert("retry-after".to_string(), "30".to_string());
        headers.insert("x-custom-app-header".to_string(), "keep-me".to_string());

        let sanitized = sanitize_cached_headers(&headers);
        // Safe headers are retained
        assert_eq!(
            sanitized.get("content-type").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(
            sanitized.get("x-custom-app-header").map(String::as_str),
            Some("keep-me")
        );
        // Sensitive headers are stripped, regardless of case
        assert!(!sanitized.contains_key("Set-Cookie"));
        assert!(!sanitized.contains_key("authorization"));
        assert!(!sanitized.contains_key("X-Request-Id"));
        assert!(!sanitized.contains_key("X-Amz-Request-Id"));
        assert!(!sanitized.contains_key("X-Amz-Apigw-Id"));
        assert!(!sanitized.contains_key("X-Amzn-Request-Id"));
        assert!(!sanitized.contains_key("X-Amzn-Trace-Id"));
        assert!(!sanitized.contains_key("X-AI-RateLimit-Remaining"));
        assert!(!sanitized.contains_key("retry-after"));
    }

    #[test]
    fn sanitize_cached_headers_strips_provider_ratelimit_suffix_variants() {
        // Providers emit rate-limit headers with request/token suffixes
        // (OpenAI: x-ratelimit-*-requests / -tokens; Anthropic:
        // anthropic-ratelimit-requests-* / -tokens-*). Exact-match against
        // a canonical list would miss these and replay the original
        // consumer's quota to every cache hit. Prefix matching catches the
        // whole family.
        let mut headers = HashMap::new();
        // OpenAI-style (exact canonical + suffix variants).
        headers.insert("x-ratelimit-limit".to_string(), "3500".to_string());
        headers.insert("x-ratelimit-limit-requests".to_string(), "3500".to_string());
        headers.insert("X-RateLimit-Limit-Tokens".to_string(), "90000".to_string());
        headers.insert(
            "x-ratelimit-remaining-requests".to_string(),
            "3499".to_string(),
        );
        headers.insert("x-ratelimit-reset-tokens".to_string(), "6ms".to_string());
        // Anthropic family.
        headers.insert(
            "anthropic-ratelimit-requests-limit".to_string(),
            "50".to_string(),
        );
        headers.insert(
            "anthropic-ratelimit-tokens-remaining".to_string(),
            "39000".to_string(),
        );
        // Ferrum Edge's own ai_rate_limiter (covered by x-ai-ratelimit-).
        headers.insert("x-ai-ratelimit-usage".to_string(), "12".to_string());
        // B3 multi-header tracing (x-b3-) and single-header (b3).
        headers.insert(
            "X-B3-TraceId".to_string(),
            "80f198ee56343ba864fe8b2a57d3eff7".to_string(),
        );
        headers.insert("x-b3-sampled".to_string(), "1".to_string());
        headers.insert("b3".to_string(), "80f198ee-e457912e-1".to_string());
        // Safe headers that share neighbouring namespaces but must not match.
        headers.insert("x-ai-cache-status".to_string(), "HIT".to_string());
        headers.insert(
            "x-ratelimited-by".to_string(), // no trailing dash — different prefix
            "upstream".to_string(),
        );
        headers.insert("content-type".to_string(), "application/json".to_string());

        let sanitized = sanitize_cached_headers(&headers);
        // All rate-limit / tracing variants stripped.
        assert!(!sanitized.contains_key("x-ratelimit-limit"));
        assert!(!sanitized.contains_key("x-ratelimit-limit-requests"));
        assert!(!sanitized.contains_key("X-RateLimit-Limit-Tokens"));
        assert!(!sanitized.contains_key("x-ratelimit-remaining-requests"));
        assert!(!sanitized.contains_key("x-ratelimit-reset-tokens"));
        assert!(!sanitized.contains_key("anthropic-ratelimit-requests-limit"));
        assert!(!sanitized.contains_key("anthropic-ratelimit-tokens-remaining"));
        assert!(!sanitized.contains_key("x-ai-ratelimit-usage"));
        assert!(!sanitized.contains_key("X-B3-TraceId"));
        assert!(!sanitized.contains_key("x-b3-sampled"));
        assert!(!sanitized.contains_key("b3"));
        // Near-miss names that share a neighbouring namespace are retained.
        assert_eq!(
            sanitized.get("x-ai-cache-status").map(String::as_str),
            Some("HIT"),
        );
        assert_eq!(
            sanitized.get("x-ratelimited-by").map(String::as_str),
            Some("upstream"),
        );
        assert_eq!(
            sanitized.get("content-type").map(String::as_str),
            Some("application/json"),
        );
    }
}

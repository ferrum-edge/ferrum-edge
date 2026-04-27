//! Canonical hop-by-hop header strip predicates for the request and response
//! paths. RFC 9110 §7.6.1 names two disjoint sets — request-direction and
//! response-direction — and the proxy must apply the right one at each
//! boundary. Centralising the predicates here keeps the protocol dispatchers
//! (reqwest, direct H2 pool, gRPC pool, native H3 pool, H3 cross-protocol
//! bridge, H3 frontend response writer) from drifting; previous copies in five
//! sites already disagreed and one — the H3 outbound writer — only stripped
//! four of the eight RFC-mandated names.
//!
//! The names below are lowercase. Hyper normalises header names per HTTP/2
//! and HTTP/3 (RFC 9113 §8.2.2 / RFC 9114 §4.2), and the proxy's plugin
//! pipeline lowercases keys at admission, so callers may match against these
//! predicates without a separate normalisation step.

/// Returns `true` for headers that must NOT be forwarded on a backend
/// request. This is the union of:
///
/// - **RFC 9110 §7.6.1 hop-by-hop headers (request-direction set):**
///   `connection`, `keep-alive`, `proxy-authorization`, `proxy-connection`,
///   `te`, `trailer`, `transfer-encoding`, `upgrade`.
///
/// - **`content-length`:** managed by the transport layer. Reqwest
///   recomputes it from the body, hyper H2 frames the body via DATA frames
///   so any forwarded value is informational only, h3 likewise frames via
///   QUIC streams. Forwarding an upstream value risks disagreeing with the
///   actual body length when a request_transformer plugin mutated the body
///   without correcting the header — the backend may reject the mismatch
///   per RFC 9110 §8.6.
///
/// - **`x-ferrum-original-content-encoding`:** internal Ferrum marker used
///   by the compression plugin to track the pre-compression encoding;
///   never forward to the backend.
///
/// `name` is expected to be lowercase.
#[inline]
pub fn is_backend_request_strip_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "content-length"
            | "keep-alive"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "x-ferrum-original-content-encoding"
    )
}

/// In-place strip of every backend-request hop-by-hop header from a
/// `http::HeaderMap`. Equivalent to `headers.retain(|n, _| !is_backend_request_strip_header(n.as_str()))`,
/// except that `http::HeaderMap` does not expose `retain`, so we collect
/// the matching keys with the small-vec optimisation in mind (typical
/// strip count is 0-2 per request — `connection` and maybe `te` /
/// `proxy-connection` from misbehaving clients).
pub fn strip_backend_request_headers(headers: &mut http::HeaderMap) {
    let to_remove: Vec<http::HeaderName> = headers
        .keys()
        .filter(|name| is_backend_request_strip_header(name.as_str()))
        .cloned()
        .collect();
    for name in to_remove {
        headers.remove(&name);
    }
}

/// Returns `true` for headers that must NOT be forwarded on a backend
/// response, per RFC 9110 §7.6.1 (response-direction hop-by-hop set).
///
/// Note that this set differs from the request-direction set:
/// `proxy-authenticate` is response-only, `proxy-authorization` is
/// request-only. `content-length` is preserved on responses because the
/// downstream client uses it for framing.
///
/// `name` is expected to be lowercase.
#[inline]
pub fn is_backend_response_strip_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_strip_covers_rfc_9110_hop_by_hop_request_set() {
        for name in [
            "connection",
            "keep-alive",
            "proxy-authorization",
            "proxy-connection",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
        ] {
            assert!(
                is_backend_request_strip_header(name),
                "RFC 9110 §7.6.1 request hop-by-hop header `{}` must be stripped",
                name
            );
        }
    }

    #[test]
    fn request_strip_covers_transport_managed_and_internal_markers() {
        assert!(is_backend_request_strip_header("content-length"));
        assert!(is_backend_request_strip_header(
            "x-ferrum-original-content-encoding"
        ));
    }

    #[test]
    fn request_strip_does_not_strip_proxy_authenticate() {
        // proxy-authenticate is response-only per RFC 9110 §7.6.1; on the
        // request path it is a custom header and must pass through.
        assert!(!is_backend_request_strip_header("proxy-authenticate"));
    }

    #[test]
    fn request_strip_passes_normal_headers() {
        for name in [
            "host",
            "accept",
            "user-agent",
            "x-forwarded-for",
            "authorization",
            "cookie",
            "content-type",
        ] {
            assert!(
                !is_backend_request_strip_header(name),
                "non-hop-by-hop header `{}` must pass through",
                name
            );
        }
    }

    #[test]
    fn response_strip_covers_rfc_9110_hop_by_hop_response_set() {
        for name in [
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-connection",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
        ] {
            assert!(
                is_backend_response_strip_header(name),
                "RFC 9110 §7.6.1 response hop-by-hop header `{}` must be stripped",
                name
            );
        }
    }

    #[test]
    fn response_strip_does_not_strip_proxy_authorization() {
        // proxy-authorization is request-only; on responses it would be a
        // custom header and must pass through.
        assert!(!is_backend_response_strip_header("proxy-authorization"));
    }

    #[test]
    fn response_strip_does_not_strip_content_length() {
        // Responses preserve content-length so the downstream client can
        // frame the body. Only the request side strips it (transport
        // recomputes there).
        assert!(!is_backend_response_strip_header("content-length"));
    }

    #[test]
    fn response_strip_passes_normal_headers() {
        for name in [
            "content-type",
            "content-length",
            "set-cookie",
            "cache-control",
            "etag",
            "location",
        ] {
            assert!(
                !is_backend_response_strip_header(name),
                "non-hop-by-hop response header `{}` must pass through",
                name
            );
        }
    }
}

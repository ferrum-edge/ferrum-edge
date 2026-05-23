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
/// - **`x-grpc-web-mode`:** internal grpc_web plugin marker used only between
///   request header and body plugin phases; never forward to the backend.
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
            | "x-grpc-web-mode"
    )
}

/// Returns true for request metadata headers that Ferrum regenerates before
/// sending to HTTP backends.
///
/// These are not hop-by-hop headers, but copying the client-supplied field and
/// then adding Ferrum's canonical value creates duplicate metadata. In
/// particular, duplicated `X-Forwarded-For` can make a backend observe the
/// untrusted client value twice after normal comma folding.
#[inline]
pub fn is_proxy_generated_forwarding_header(name: &str) -> bool {
    matches!(
        name,
        "x-forwarded-for" | "x-forwarded-proto" | "x-forwarded-host"
    )
}

/// Parse the lowercased header names listed in any `Connection` header(s),
/// per RFC 9110 §7.6.1. Walks every value of `Connection`, splits each value
/// by `,`, trims OWS, lowercases, parses to `HeaderName`, deduplicates.
///
/// Returns an empty `Vec` when `Connection` is absent or every list element
/// is malformed / unparseable as a header name. Unparseable elements are
/// silently skipped (no panic, no error) so a single bad token cannot
/// blow up the strip pass — RFC 9110 mandates strip on a best-effort basis.
///
/// Hyper rejects `Connection` headers in HTTP/2 and HTTP/3 (RFC 9113 §8.2.2,
/// RFC 9114 §4.2), so this helper is only meaningful on the HTTP/1.1 path.
/// Calling it on H2/H3 maps is a no-op (no `Connection` value to walk).
///
/// This is called BEFORE the canonical hop-by-hop strip so the listed names
/// are captured before `connection` itself is removed by the static
/// allowlist.
pub fn parse_connection_listed_headers(headers: &http::HeaderMap) -> Vec<http::HeaderName> {
    // Typical: 0 listed names (Connection just carries `close` or `keep-alive`,
    // which the static strip handles via `keep-alive`/Connection itself).
    // Reserve a small upper bound to avoid rehashing on the rare case of a
    // multi-value list.
    let mut out: Vec<http::HeaderName> = Vec::new();
    for value in headers.get_all(http::header::CONNECTION).iter() {
        let Ok(s) = value.to_str() else {
            // Non-ASCII / non-visible bytes — RFC 9110 §5.5 says field values
            // are printable ASCII / OWS, so anything else is malformed and we
            // skip the value entirely (matching the spec's best-effort tone).
            continue;
        };
        for token in s.split(',') {
            let trimmed = token.trim();
            if trimmed.is_empty() {
                continue;
            }
            // The static strip already handles `connection`, `keep-alive`,
            // `close`, and the rest of the canonical hop-by-hop set, so we
            // could skip them here as a micro-optimisation. We don't —
            // `HeaderMap::remove` of a name that isn't present is O(1) and
            // the dedup pass below means any name only appears once. Skipping
            // would just add a branch.
            //
            // Note: `close` is NOT a valid `HeaderName` (it's a *connection
            // option*, not a header), so `HeaderName::from_bytes` will reject
            // it and we move on.
            //
            // We lowercase via `HeaderName`'s case-insensitive parse: the
            // `HeaderName` API normalises ASCII case on construction, so the
            // returned name is suitable for comparison against lowercase
            // string keys elsewhere in the proxy.
            let Ok(name) = http::HeaderName::from_bytes(trimmed.as_bytes()) else {
                continue;
            };
            if !out.contains(&name) {
                out.push(name);
            }
        }
    }
    out
}

/// In-place strip of every header named in the `Connection` field, per
/// RFC 9110 §7.6.1. Companion to [`strip_backend_request_headers`] — call
/// this BEFORE the canonical strip so the listed names are captured before
/// `connection` itself is removed.
///
/// For convenience [`strip_backend_request_headers`] already calls this
/// helper as its first step; direct callers only need to invoke it
/// when working with a `HeaderMap` outside the request-build pipeline.
pub fn strip_connection_listed_headers(headers: &mut http::HeaderMap) {
    // Snapshot first — we cannot iterate `Connection` while mutating the
    // map. The Vec is empty when no `Connection` header is present, making
    // this a near-zero-cost no-op for the common case (most clients omit
    // `Connection` entirely on H1.1).
    let listed = parse_connection_listed_headers(headers);
    for name in listed {
        headers.remove(&name);
    }
}

/// String-flavored counterpart to [`parse_connection_listed_headers`] for
/// dispatch sites that iterate a materialised `&HashMap<String, String>`
/// (e.g. `proxy::proxy_to_backend_retry`, the H3 client builders, the
/// H3 server cross-protocol bridge). Returns the listed header names in
/// lowercase ASCII.
///
/// Ferrum normally stores lowercase keys after admission, but this helper also
/// accepts mixed-case `Connection` map entries because plugins can synthesize
/// headers outside the original HTTP parser.
///
/// Unparseable list elements are skipped (no panic). Empty / absent
/// `Connection` returns an empty `Vec`.
pub fn parse_connection_listed_from_str_map(
    headers: &std::collections::HashMap<String, String>,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    // The materialised request map folds multi-valued headers with `, `
    // (see the request handler). Walk every case variant defensively so a
    // plugin-added `Connection` does not bypass listed-header stripping.
    for value in headers.iter().filter_map(|(name, value)| {
        name.eq_ignore_ascii_case("connection")
            .then_some(value.as_str())
    }) {
        for token in value.split(',') {
            let trimmed = token.trim();
            if trimmed.is_empty() {
                continue;
            }
            // Validate as a header name to reject garbage tokens (e.g. `close`,
            // `keep-alive` strip themselves; arbitrary smuggling attempts like
            // `\r\nX-Foo:` get rejected here). Lowercase the result for the
            // caller's convenience — it matches the plugin pipeline's lowercase
            // key invariant.
            let Ok(name) = http::HeaderName::from_bytes(trimmed.as_bytes()) else {
                continue;
            };
            let lower = name.as_str().to_owned();
            if !out.contains(&lower) {
                out.push(lower);
            }
        }
    }
    out
}

/// In-place strip of every backend-request hop-by-hop header from a
/// `http::HeaderMap`, including any header NAMED in the request's
/// `Connection` field (RFC 9110 §7.6.1).
///
/// The Connection-listed strip runs FIRST — we must snapshot the listed
/// names before `connection` itself is removed by the static allowlist. The
/// Vec collected for the static strip covers the typical 0-2 names per
/// request (`connection` and maybe `te` / `proxy-connection` from
/// misbehaving clients). `http::HeaderMap` does not expose `retain`, so we
/// collect the matching keys with the small-vec optimisation in mind.
pub fn strip_backend_request_headers(headers: &mut http::HeaderMap) {
    // RFC 9110 §7.6.1 Connection-listed strip MUST run before the canonical
    // strip so the `Connection` header value is still present and we can
    // walk it. This protects against `Connection: X-Sensitive` smuggling
    // where the client (or an upstream intermediary) names a header that
    // would otherwise pass through the static allowlist.
    strip_connection_listed_headers(headers);

    let to_remove: Vec<http::HeaderName> = headers
        .keys()
        .filter(|name| is_backend_request_strip_header(name.as_str()))
        .cloned()
        .collect();
    for name in to_remove {
        headers.remove(&name);
    }
}

/// In-place strip of every backend-request hop-by-hop header from a
/// `http::HeaderMap`, then synthesise the gRPC-required `te: trailers`
/// directive.
///
/// gRPC over HTTP/2 ([gRPC HTTP/2 spec][grpc-http2]) defines `te:
/// trailers` as a mandatory request header. Many gRPC servers (notably
/// `grpc-go`) reject requests missing it as evidence of a non-gRPC-aware
/// proxy in the path, so the proxy MUST forward it on every gRPC backend
/// request. The generic [`strip_backend_request_headers`] removes `te`
/// alongside the rest of the RFC 9110 §7.6.1 hop-by-hop set (correct for
/// HTTP/2 generally, where only `te: trailers` is even legal per RFC
/// 9113 §8.2.2), so the gRPC paths must re-establish the header after
/// stripping. We synthesise it unconditionally rather than preserving
/// the client's value because:
///
/// - Per RFC 9113 §8.2.2 the only TE value an HTTP/2 client may send is
///   `trailers`, so any preserved value would be `trailers` anyway.
/// - Some clients (or earlier proxies) silently drop `te` despite gRPC
///   requiring it; synthesising guarantees the gRPC backend's strict
///   check passes.
/// - Anything other than `trailers` would itself be a protocol
///   violation.
///
/// Mirrors the pre-PR-511 effective behaviour for valid gRPC clients
/// (their `te: trailers` previously survived the partial 2-header strip)
/// and now works correctly even when the client omitted it.
///
/// [grpc-http2]: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md
pub fn strip_backend_request_headers_for_grpc(headers: &mut http::HeaderMap) {
    strip_backend_request_headers(headers);
    headers.insert(http::header::TE, http::HeaderValue::from_static("trailers"));
}

/// Merge plugin/proxy headers on top of `headers` and then run the
/// gRPC-specific backend strip on the union. This is the canonical
/// order for gRPC dispatch — stripping BEFORE the merge would let any
/// client-supplied hop-by-hop header survive, because `proxy_headers`
/// is the full materialised request map (`ctx.headers`) and not just
/// plugin deltas. The merge step would re-insert `proxy-authorization`,
/// `proxy-connection`, `te`, `trailer`, `transfer-encoding`,
/// `content-length`, etc. straight back into the outbound map.
///
/// Encapsulating the merge-then-strip dance in one helper means both
/// gRPC entry points (`proxy_grpc_request_streaming` and
/// `proxy_grpc_request_core`) share a single tested implementation;
/// neither can call the steps in the wrong order.
pub fn merge_proxy_headers_and_strip_for_grpc(
    headers: &mut http::HeaderMap,
    proxy_headers: &std::collections::HashMap<String, String>,
) {
    for (k, v) in proxy_headers {
        if let (Ok(name), Ok(val)) = (
            http::HeaderName::from_bytes(k.as_bytes()),
            http::HeaderValue::from_str(v),
        ) {
            headers.insert(name, val);
        }
    }
    strip_backend_request_headers_for_grpc(headers);
}

/// Returns `true` for headers that must NOT be forwarded on a backend
/// response, per RFC 9110 §7.6.1 (response-direction hop-by-hop set).
///
/// Note that this set differs from the request-direction set:
/// `proxy-authenticate` is response-only, `proxy-authorization` is
/// request-only. `content-length` is preserved on responses because the
/// downstream client uses it for framing.
///
/// **Trailers**: this same predicate MUST be applied to backend response
/// **trailers** (RFC 9110 §6.5 distinct concept). gRPC encodes
/// `grpc-status` / `grpc-message` as trailers, and a misbehaving backend
/// can put hop-by-hop directives (`connection: close`,
/// `proxy-authenticate`, `keep-alive`, `transfer-encoding`, `upgrade`)
/// in the trailer map. Hyper's H2 trailer encoder rejects some hop-by-hop
/// names at the frame layer but `proxy-authenticate`, `proxy-connection`,
/// and `keep-alive` are not blocked, so the proxy must filter them
/// itself. Applied at:
///   - `grpc_proxy::proxy_grpc_request_core` buffered-path trailer
///     collection loop.
///   - `proxy::body::StripHopByHopTrailers` wrapper interposed before
///     `Coalescing<Incoming>` on the streaming path.
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

// NOTE: There is no `strip_connection_listed_response_headers` helper
// because no response dispatch site holds a `&mut HeaderMap` long enough
// to need it — they all collect from `&HeaderMap` into a
// `HashMap<String, String>` and apply the strip in the same pass via
// `parse_connection_listed_headers`. If a future caller needs in-place
// removal on a response `HeaderMap`, just call
// `parse_connection_listed_headers` and `remove` each returned name.

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
    fn proxy_generated_forwarding_header_filter_covers_x_forwarded_family() {
        assert!(is_proxy_generated_forwarding_header("x-forwarded-for"));
        assert!(is_proxy_generated_forwarding_header("x-forwarded-proto"));
        assert!(is_proxy_generated_forwarding_header("x-forwarded-host"));
        assert!(!is_proxy_generated_forwarding_header("forwarded"));
        assert!(!is_proxy_generated_forwarding_header("via"));
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

    #[test]
    fn grpc_request_strip_synthesises_te_trailers_when_client_omitted_it() {
        // Some clients / earlier proxies drop `te` despite gRPC requiring
        // `te: trailers`. The gRPC-specific strip must always end with the
        // header set so the backend's strict check passes.
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/grpc"),
        );
        strip_backend_request_headers_for_grpc(&mut headers);
        assert_eq!(
            headers.get(http::header::TE),
            Some(&http::HeaderValue::from_static("trailers")),
            "gRPC strip must synthesise te: trailers even when missing",
        );
    }

    #[test]
    fn grpc_request_strip_replaces_invalid_te_with_trailers() {
        // A client sending `te: gzip` (invalid in HTTP/2 per RFC 9113
        // §8.2.2) would normally reach the backend if we only stripped
        // `connection` and `transfer-encoding` (the pre-PR-511 behaviour).
        // After this PR, the canonical strip removes any `te` value, then
        // the gRPC helper re-inserts the spec-compliant `trailers`.
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::TE, http::HeaderValue::from_static("gzip"));
        strip_backend_request_headers_for_grpc(&mut headers);
        assert_eq!(
            headers.get(http::header::TE),
            Some(&http::HeaderValue::from_static("trailers")),
            "gRPC strip must overwrite a non-`trailers` TE value",
        );
    }

    #[test]
    fn grpc_request_strip_preserves_te_trailers_for_valid_clients() {
        // The valid-client case: an H2 gRPC client sent `te: trailers`.
        // After strip + synthesise, the same value remains. This is the
        // pre-PR-511 effective behaviour, now restored.
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::TE, http::HeaderValue::from_static("trailers"));
        strip_backend_request_headers_for_grpc(&mut headers);
        assert_eq!(
            headers.get(http::header::TE),
            Some(&http::HeaderValue::from_static("trailers")),
            "gRPC strip must preserve te: trailers from valid clients",
        );
    }

    #[test]
    fn grpc_merge_then_strip_blocks_hop_by_hop_from_plugin_headers() {
        // Regression: previously the gRPC paths stripped `parts.headers`
        // and THEN merged `proxy_headers` on top, letting any
        // client-supplied (or plugin-set) hop-by-hop header survive the
        // strip. `proxy_headers` is the full materialised request map
        // (`ctx.headers`) — not just plugin deltas — so a client that
        // sent `proxy-authorization: Bearer leak` would have it forwarded
        // to the gRPC backend. The helper must merge first and strip
        // second, applying the predicate to the union.
        let mut headers = http::HeaderMap::new();
        // Original request headers (e.g. from `parts.headers`) — these
        // would have been stripped under the old order. Include a
        // benign header to confirm normal headers pass through.
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/grpc"),
        );

        // Materialised request headers (what `proxy_headers` carries
        // through the dispatch pipeline). Includes a hop-by-hop set the
        // client supplied — the bug was these survived the strip.
        let mut proxy_headers = std::collections::HashMap::new();
        proxy_headers.insert("proxy-authorization".to_string(), "Bearer leak".to_string());
        proxy_headers.insert("proxy-connection".to_string(), "close".to_string());
        proxy_headers.insert("connection".to_string(), "keep-alive".to_string());
        proxy_headers.insert("transfer-encoding".to_string(), "chunked".to_string());
        proxy_headers.insert("content-length".to_string(), "999".to_string());
        proxy_headers.insert("te".to_string(), "gzip".to_string()); // bogus client TE
        proxy_headers.insert("authorization".to_string(), "Bearer keep".to_string());

        merge_proxy_headers_and_strip_for_grpc(&mut headers, &proxy_headers);

        // Hop-by-hop and transport-managed headers must be gone even
        // though they came in via proxy_headers.
        assert!(
            headers.get("proxy-authorization").is_none(),
            "proxy-authorization from proxy_headers must be stripped post-merge"
        );
        assert!(headers.get("proxy-connection").is_none());
        assert!(headers.get(http::header::CONNECTION).is_none());
        assert!(headers.get(http::header::TRANSFER_ENCODING).is_none());
        assert!(headers.get(http::header::CONTENT_LENGTH).is_none());

        // `te` was set to a bogus value by the client; strip removes it,
        // gRPC synthesise restores `trailers`.
        assert_eq!(
            headers.get(http::header::TE),
            Some(&http::HeaderValue::from_static("trailers")),
            "gRPC strip must overwrite the proxy_headers TE value with `trailers`"
        );

        // Non-hop-by-hop headers from proxy_headers are forwarded.
        assert_eq!(
            headers.get(http::header::AUTHORIZATION),
            Some(&http::HeaderValue::from_static("Bearer keep"))
        );
        assert_eq!(
            headers.get(http::header::CONTENT_TYPE),
            Some(&http::HeaderValue::from_static("application/grpc"))
        );
    }

    #[test]
    fn grpc_merge_then_strip_synthesises_te_when_no_one_sent_it() {
        // Neither the original headers nor proxy_headers carry `te`;
        // the helper must still synthesise `te: trailers` after the
        // merge+strip dance.
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/grpc"),
        );
        let proxy_headers: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();

        merge_proxy_headers_and_strip_for_grpc(&mut headers, &proxy_headers);

        assert_eq!(
            headers.get(http::header::TE),
            Some(&http::HeaderValue::from_static("trailers"))
        );
    }

    // -----------------------------------------------------------------
    // RFC 9110 §7.6.1 Connection-listed hop-by-hop strip — request and
    // response directions. The Connection header lets either party name
    // ADDITIONAL hop-by-hop headers; the proxy must remove every one of
    // them before forwarding.
    // -----------------------------------------------------------------

    #[test]
    fn connection_listed_strip_removes_single_named_header() {
        // `Connection: x-foo` — the simplest case. `x-foo` must be
        // stripped from the request; the static allowlist alone would not
        // know to remove it.
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static("x-foo"),
        );
        headers.insert("x-foo", http::HeaderValue::from_static("secret"));
        headers.insert("x-keep", http::HeaderValue::from_static("ok"));

        strip_backend_request_headers(&mut headers);

        assert!(
            headers.get("x-foo").is_none(),
            "Connection-listed header `x-foo` must be stripped per RFC 9110 §7.6.1"
        );
        assert_eq!(
            headers.get("x-keep"),
            Some(&http::HeaderValue::from_static("ok")),
            "non-listed headers must pass through"
        );
        // `connection` itself is removed by the canonical static strip.
        assert!(headers.get(http::header::CONNECTION).is_none());
    }

    #[test]
    fn connection_listed_strip_removes_multiple_named_headers() {
        // `Connection: x-foo, x-bar` — comma-separated list semantics.
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static("x-foo, x-bar"),
        );
        headers.insert("x-foo", http::HeaderValue::from_static("secret-a"));
        headers.insert("x-bar", http::HeaderValue::from_static("secret-b"));
        headers.insert("x-keep", http::HeaderValue::from_static("ok"));

        strip_backend_request_headers(&mut headers);

        assert!(headers.get("x-foo").is_none());
        assert!(headers.get("x-bar").is_none());
        assert_eq!(
            headers.get("x-keep"),
            Some(&http::HeaderValue::from_static("ok"))
        );
    }

    #[test]
    fn connection_listed_strip_is_case_insensitive() {
        // `Connection: X-Foo, KEEP-ALIVE` — mixed case must still strip.
        // HeaderName normalises ASCII case on construction so the
        // comparison is naturally case-insensitive.
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static("X-Foo, KEEP-ALIVE"),
        );
        headers.insert("x-foo", http::HeaderValue::from_static("secret"));
        headers.insert("keep-alive", http::HeaderValue::from_static("timeout=30"));

        strip_backend_request_headers(&mut headers);

        assert!(
            headers.get("x-foo").is_none(),
            "case-insensitive Connection-listed strip must remove `x-foo`"
        );
        // `keep-alive` is doubly stripped (canonical + Connection-listed);
        // either path removes it.
        assert!(headers.get("keep-alive").is_none());
    }

    #[test]
    fn connection_listed_strip_handles_garbage_tokens_without_panic() {
        // Malformed list elements (empty, whitespace-only, illegal name
        // characters) must not panic. Parseable elements are still stripped.
        // `HeaderValue::from_static` rejects raw control bytes, so we use
        // visible-ASCII garbage tokens that `HeaderName::from_bytes` will
        // refuse: `:` is not a valid token char per RFC 9110 §5.6.2, and
        // a leading `\r\n` would be illegal — we exercise the simpler
        // "syntactically invalid" path here.
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            // Leading/trailing comma + whitespace + a token containing
            // colon (forbidden in header names).
            http::HeaderValue::from_static(", , x-foo, bad:token, x-bar,"),
        );
        headers.insert("x-foo", http::HeaderValue::from_static("a"));
        headers.insert("x-bar", http::HeaderValue::from_static("b"));
        headers.insert("x-keep", http::HeaderValue::from_static("c"));

        strip_backend_request_headers(&mut headers);

        // Parseable tokens are stripped.
        assert!(headers.get("x-foo").is_none());
        assert!(headers.get("x-bar").is_none());
        // Unrelated header survives.
        assert_eq!(
            headers.get("x-keep"),
            Some(&http::HeaderValue::from_static("c"))
        );
    }

    #[test]
    fn connection_listed_strip_handles_empty_value() {
        // `Connection:` with an empty value is a no-op — nothing to
        // strip beyond the canonical predicate.
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONNECTION, http::HeaderValue::from_static(""));
        headers.insert("x-keep", http::HeaderValue::from_static("ok"));

        strip_backend_request_headers(&mut headers);

        // `connection` is removed by the canonical strip; `x-keep` stays.
        assert!(headers.get(http::header::CONNECTION).is_none());
        assert_eq!(
            headers.get("x-keep"),
            Some(&http::HeaderValue::from_static("ok"))
        );
    }

    #[test]
    fn connection_listed_strip_walks_multiple_connection_headers() {
        // Per RFC 9110 §5.3, multiple field lines for the same header name
        // are equivalent to a single comma-folded value. `HeaderMap::append`
        // preserves both values; `parse_connection_listed_headers` walks
        // them all.
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::CONNECTION,
            http::HeaderValue::from_static("x-foo"),
        );
        headers.append(
            http::header::CONNECTION,
            http::HeaderValue::from_static("x-bar, x-baz"),
        );
        headers.insert("x-foo", http::HeaderValue::from_static("a"));
        headers.insert("x-bar", http::HeaderValue::from_static("b"));
        headers.insert("x-baz", http::HeaderValue::from_static("c"));
        headers.insert("x-keep", http::HeaderValue::from_static("d"));

        strip_backend_request_headers(&mut headers);

        assert!(headers.get("x-foo").is_none(), "x-foo from value 1");
        assert!(headers.get("x-bar").is_none(), "x-bar from value 2");
        assert!(headers.get("x-baz").is_none(), "x-baz from value 2");
        assert_eq!(
            headers.get("x-keep"),
            Some(&http::HeaderValue::from_static("d"))
        );
    }

    #[test]
    fn parse_connection_listed_headers_returns_empty_when_absent() {
        let headers = http::HeaderMap::new();
        assert!(parse_connection_listed_headers(&headers).is_empty());
    }

    #[test]
    fn parse_connection_listed_headers_dedups() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::CONNECTION,
            http::HeaderValue::from_static("x-foo, x-foo"),
        );
        headers.append(
            http::header::CONNECTION,
            http::HeaderValue::from_static("X-FOO"),
        );
        let listed = parse_connection_listed_headers(&headers);
        assert_eq!(
            listed.len(),
            1,
            "dedup must collapse case-variant duplicates"
        );
        assert_eq!(listed[0].as_str(), "x-foo");
    }

    #[test]
    fn parse_connection_listed_from_str_map_returns_empty_when_absent() {
        let headers: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        assert!(parse_connection_listed_from_str_map(&headers).is_empty());
    }

    #[test]
    fn parse_connection_listed_from_str_map_handles_comma_folded_values() {
        // The HTTP request handler folds multi-valued headers into a single
        // comma-separated string. This helper must walk that single value.
        let mut headers = std::collections::HashMap::new();
        headers.insert(
            "connection".to_string(),
            "x-foo, X-Bar, , x-foo".to_string(),
        );
        let listed = parse_connection_listed_from_str_map(&headers);
        // x-foo dedup + x-bar → 2 names, both lowercase, in iteration order.
        assert_eq!(listed.len(), 2);
        assert!(listed.contains(&"x-foo".to_string()));
        assert!(listed.contains(&"x-bar".to_string()));
    }

    #[test]
    fn parse_connection_listed_from_str_map_accepts_mixed_case_connection_keys() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("Connection".to_string(), "x-foo".to_string());
        headers.insert("CONNECTION".to_string(), "X-Bar, x-foo".to_string());

        let listed = parse_connection_listed_from_str_map(&headers);

        assert_eq!(listed.len(), 2);
        assert!(listed.contains(&"x-foo".to_string()));
        assert!(listed.contains(&"x-bar".to_string()));
    }

    #[test]
    fn parse_connection_listed_from_str_map_skips_garbage_tokens() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("connection".to_string(), "x-foo, \x01, , x-bar".to_string());
        let listed = parse_connection_listed_from_str_map(&headers);
        assert_eq!(listed.len(), 2);
        assert!(listed.contains(&"x-foo".to_string()));
        assert!(listed.contains(&"x-bar".to_string()));
    }

    #[test]
    fn response_strip_pipeline_removes_connection_listed_names() {
        // Backend smuggling defence: a backend that names a header in
        // `Connection` cannot route it past the proxy. This test exercises
        // the pattern that every response-direction dispatch site uses —
        // `parse_connection_listed_headers` to snapshot, plus the
        // canonical `is_backend_response_strip_header` predicate.
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static("x-internal-token, close"),
        );
        headers.insert("x-internal-token", http::HeaderValue::from_static("leak"));
        headers.insert("x-public", http::HeaderValue::from_static("ok"));

        // Snapshot the listed names (the dispatch sites do this before the
        // collect-and-strip loop).
        let listed = parse_connection_listed_headers(&headers);
        assert!(
            listed.iter().any(|n| n.as_str() == "x-internal-token"),
            "Connection-listed parse must surface the smuggled name"
        );
        for name in &listed {
            headers.remove(name);
        }
        // Then run the canonical response strip — mirrors the dispatch
        // sites that compose the two passes.
        let to_remove: Vec<http::HeaderName> = headers
            .keys()
            .filter(|n| is_backend_response_strip_header(n.as_str()))
            .cloned()
            .collect();
        for name in to_remove {
            headers.remove(&name);
        }

        assert!(headers.get("x-internal-token").is_none());
        assert!(headers.get(http::header::CONNECTION).is_none());
        assert_eq!(
            headers.get("x-public"),
            Some(&http::HeaderValue::from_static("ok"))
        );
    }

    #[test]
    fn grpc_merge_then_strip_honors_connection_listed() {
        // Composability check: the gRPC pipeline runs through
        // `merge_proxy_headers_and_strip_for_grpc`, which delegates to
        // `strip_backend_request_headers`. Anything named in the merged
        // `Connection` header — whether it came from the original request
        // or from `proxy_headers` — must be stripped.
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/grpc"),
        );

        let mut proxy_headers = std::collections::HashMap::new();
        proxy_headers.insert("connection".to_string(), "x-internal-token".to_string());
        proxy_headers.insert("x-internal-token".to_string(), "leak".to_string());
        proxy_headers.insert("x-keep".to_string(), "ok".to_string());

        merge_proxy_headers_and_strip_for_grpc(&mut headers, &proxy_headers);

        assert!(
            headers.get("x-internal-token").is_none(),
            "Connection-listed header must be stripped from gRPC requests"
        );
        assert_eq!(
            headers.get("x-keep"),
            Some(&http::HeaderValue::from_static("ok")),
            "unrelated proxy_headers entries must still be forwarded"
        );
        // gRPC pipeline always synthesises te: trailers afterwards.
        assert_eq!(
            headers.get(http::header::TE),
            Some(&http::HeaderValue::from_static("trailers"))
        );
    }

    #[test]
    fn grpc_request_strip_still_removes_other_hop_by_hop_headers() {
        // Smoke check: the gRPC helper must NOT regress the rest of the
        // RFC 9110 §7.6.1 strip — only `te` is special-cased.
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static("keep-alive"),
        );
        headers.insert(
            "proxy-authorization",
            http::HeaderValue::from_static("Bearer xyz"),
        );
        headers.insert("proxy-connection", http::HeaderValue::from_static("close"));
        headers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("42"),
        );
        strip_backend_request_headers_for_grpc(&mut headers);
        assert!(headers.get(http::header::CONNECTION).is_none());
        assert!(headers.get("proxy-authorization").is_none());
        assert!(headers.get("proxy-connection").is_none());
        assert!(headers.get(http::header::CONTENT_LENGTH).is_none());
    }
}

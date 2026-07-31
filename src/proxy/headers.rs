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
//!
//! Secondary-request builders (`request_mirror`, `load_testing`) call the
//! hot-path predicates below directly (via
//! [`is_secondary_request_strip_header`]), so newly added strip arms are
//! honored automatically. The `*_NAMES` consts are the same inventory as the
//! predicates — generated together — and exist for documentation and tests
//! that enumerate the closed set, not as a second allowlist that must be kept
//! in sync by hand.

/// Expand one closed header-name inventory into both a `&[&str]` const and the
/// matching hot-path `matches!` predicate so documentation inventories cannot
/// drift from the predicate arms.
macro_rules! define_header_name_set {
    (
        $(#[$const_meta:meta])*
        $const_vis:vis const $const_name:ident;
        $(#[$fn_meta:meta])*
        $fn_vis:vis fn $fn_name:ident;
        [$($name:literal),+ $(,)?]
    ) => {
        $(#[$const_meta])*
        $const_vis const $const_name: &[&str] = &[$($name),+];

        $(#[$fn_meta])*
        #[inline]
        $fn_vis fn $fn_name(name: &str) -> bool {
            matches!(name, $($name)|+)
        }
    };
}

define_header_name_set! {
    // Public inventory is consumed by library tests, not the binary target.
    #[allow(dead_code)]
    /// Closed set of lowercase names stripped by
    /// [`is_backend_request_strip_header`]. Secondary-request builders call that
    /// predicate directly; this const is the shared inventory for docs/tests.
    pub const BACKEND_REQUEST_STRIP_HEADER_NAMES;
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
    pub fn is_backend_request_strip_header;
    [
        "connection",
        "content-length",
        "keep-alive",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "x-ferrum-original-content-encoding",
        "x-grpc-web-mode",
    ]
}

define_header_name_set! {
    // Public inventory is consumed by library tests, not the binary target.
    #[allow(dead_code)]
    /// Closed set of lowercase proxy-owned forwarding identity headers stripped
    /// before Ferrum regenerates them on primary dispatch (and before secondary
    /// request builders copy the materialised map).
    pub const PROXY_GENERATED_FORWARDING_HEADER_NAMES;
    /// Returns true for request metadata headers that Ferrum regenerates before
    /// sending to HTTP backends.
    ///
    /// These are not hop-by-hop headers, but copying the client-supplied field and
    /// then adding Ferrum's canonical value creates duplicate metadata. In
    /// particular, duplicated `X-Forwarded-For` can make a backend observe the
    /// untrusted client value twice after normal comma folding.
    ///
    /// RFC 7239 `Forwarded` is gated by [`is_proxy_owned_forwarding_header`] —
    /// Ferrum regenerates it only when `FERRUM_ADD_FORWARDED_HEADER` is enabled,
    /// so the always-on inventory stays limited to the `X-Forwarded-*` family.
    pub fn is_proxy_generated_forwarding_header;
    ["x-forwarded-for", "x-forwarded-proto", "x-forwarded-host"]
}

/// Returns true when an inbound forwarding-identity header must be omitted from
/// the outbound backend request because Ferrum will regenerate it.
///
/// Always covers the `X-Forwarded-*` family ([`is_proxy_generated_forwarding_header`]).
/// When `add_forwarded_header` is true, also covers RFC 7239 `forwarded` so a
/// client-supplied value cannot precede or coexist with the gateway-owned
/// element — reqwest `RequestBuilder::header` appends, and H3 builders push into
/// a `Vec`, so failing to strip first makes backend-visible shape flip across
/// capability-path changes.
///
/// Primary dispatch maps normally carry lowercase names (hyper/`HeaderName`),
/// but plugin-synthesised mixed-case keys can appear in the string `HashMap`.
/// Ownership matching is ASCII case-insensitive and allocation-free so a
/// hostile `Forwarded` / `X-Forwarded-For` / `FORWARDED` key cannot bypass the
/// strip and precede the gateway-owned element on append/`Vec`-push transports.
///
/// Hot path: lowercase names hit the exact `matches!` inventory (or the
/// lowercase `forwarded` compare) with no scan. The case-insensitive XFF sweep
/// runs only when the name carries an uppercase ASCII byte.
#[inline]
pub fn is_proxy_owned_forwarding_header(name: &str, add_forwarded_header: bool) -> bool {
    if is_proxy_generated_forwarding_header(name) {
        return true;
    }
    if add_forwarded_header && name.eq_ignore_ascii_case("forwarded") {
        return true;
    }
    // Mixed-case plugin keys bypass the lowercase-only XFF inventory above.
    // Mirror the cross-protocol skip hot-path shape: uppercase gate first.
    name.bytes().any(|b| b.is_ascii_uppercase())
        && (name.eq_ignore_ascii_case("x-forwarded-for")
            || name.eq_ignore_ascii_case("x-forwarded-proto")
            || name.eq_ignore_ascii_case("x-forwarded-host"))
}

/// Whether client `Host` / authority should survive secondary-request filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecondaryRequestHostPolicy {
    /// Drop client `Host` so the outbound HTTP client derives authority from
    /// the target URL (shadow / mirror destinations).
    Strip,
    /// Keep `Host` for host-based routing when the synthetic request re-enters
    /// the gateway (load-testing loopback and peer fan-out).
    Preserve,
}

/// Returns `true` when a materialised request header must not be copied onto a
/// Ferrum-generated secondary request (mirror, load-test synthetic/fan-out).
///
/// Applies the primary backend-request strip set, every proxy forwarding
/// identity header (the `X-Forwarded-*` family and RFC 7239 `Forwarded`),
/// RFC 9110 `Connection`-listed names (snapshot must be taken via
/// [`parse_connection_listed_from_str_map`] before filtering), and the
/// caller-selected [`SecondaryRequestHostPolicy`].
///
/// Secondary requests do not regenerate Ferrum's forwarding identity. Strip
/// `Forwarded` unconditionally, just as the secondary boundary already strips
/// `X-Forwarded-*`, so a client-supplied identity cannot reach a mirror or
/// synthetic/fan-out target even when primary RFC 7239 generation is disabled.
///
/// Comparison is ASCII case-insensitive so plugin-synthesised mixed-case keys
/// cannot bypass the boundary.
#[inline]
pub fn is_secondary_request_strip_header(
    name: &str,
    connection_listed: &[String],
    host_policy: SecondaryRequestHostPolicy,
) -> bool {
    let name_lower = name.to_ascii_lowercase();
    if host_policy == SecondaryRequestHostPolicy::Strip && name_lower == "host" {
        return true;
    }
    if connection_listed.iter().any(|listed| listed == &name_lower) {
        return true;
    }
    is_backend_request_strip_header(&name_lower)
        || is_proxy_generated_forwarding_header(&name_lower)
        || name_lower == "forwarded"
}

/// Filter a materialised request header map for a Ferrum-generated secondary
/// request, honoring the same outbound protocol boundary as primary backend
/// dispatch.
///
/// `extra_exclude` removes additional plugin-control names (for example
/// load-testing trigger/fan-out headers) after the canonical strip. `Host`
/// handling is selected via [`SecondaryRequestHostPolicy`].
///
/// Connection-listed names are snapshotted first so dynamic hop-by-hop tokens
/// are removed even though `connection` itself is stripped by the static set.
pub fn filter_secondary_request_headers(
    headers: &std::collections::HashMap<String, String>,
    host_policy: SecondaryRequestHostPolicy,
    extra_exclude: &[&str],
) -> Vec<(String, String)> {
    let connection_listed = parse_connection_listed_from_str_map(headers);
    headers
        .iter()
        .filter(|(name, _)| {
            if extra_exclude
                .iter()
                .any(|excluded| name.eq_ignore_ascii_case(excluded))
            {
                return false;
            }
            !is_secondary_request_strip_header(name, &connection_listed, host_policy)
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// After generic secondary-request stripping, re-synthesise gRPC's mandatory
/// `te: trailers` when the outbound request is native gRPC.
///
/// Uses the same delimiter-aware classifier as primary dispatch
/// ([`crate::proxy::backend_dispatch::is_native_grpc_content_type`]): exact
/// `application/grpc`, `application/grpc+…`, or parameters / trailing OWS —
/// not a bare prefix match that would treat `application/grpcfoo` or
/// `application/grpc-web` as gRPC.
///
/// Mirrors [`strip_backend_request_headers_for_grpc`] for builders that work
/// from a materialised `Vec<(String, String)>` rather than `http::HeaderMap`.
/// Callers must use an HTTP/2-capable target for native gRPC; HTTP/1.1 is not a
/// supported native-gRPC mirror transport.
pub fn synthesize_grpc_te_trailers_if_needed(headers: &mut Vec<(String, String)>) {
    let is_grpc = headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-type") && content_type_is_grpc(value)
    });
    if !is_grpc {
        return;
    }
    headers.retain(|(name, _)| !name.eq_ignore_ascii_case("te"));
    headers.push(("te".to_string(), "trailers".to_string()));
}

/// Allocation-free native-gRPC media-type check for secondary-request builders.
#[inline]
fn content_type_is_grpc(value: &str) -> bool {
    crate::proxy::backend_dispatch::is_native_grpc_content_type(value.as_bytes())
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
    // The materialised request map folds repeated non-cookie headers with
    // `, ` (see the request handler). Walk every case variant defensively
    // so a plugin-added `Connection` does not bypass listed-header stripping.
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

/// Remove reserved gateway-asserted headers from a request `HeaderMap`.
///
/// `x-consumer-username` / `x-consumer-custom-id` are injected by the gateway
/// only after a principal is resolved and are documented as "never trusted
/// from clients". `x-geo-country` is likewise emitted only after a successful
/// GeoIP lookup. `HeaderMap::remove` clears every value for the case-insensitive
/// name, so any client-supplied casing or duplication is dropped.
fn strip_reserved_gateway_assertion_headers(headers: &mut http::HeaderMap) {
    headers.remove("x-consumer-username");
    headers.remove("x-consumer-custom-id");
    headers.remove("x-geo-country");
}

/// Whether the materialized single-value view still represents the exact raw
/// field-line sequence. Keeping the raw lines in that case preserves repeated
/// gRPC metadata (including `-bin` metadata) instead of collapsing it into one
/// comma-folded field. A plugin mutation no longer matches and therefore still
/// replaces the raw values below.
fn raw_header_values_match_materialized(
    headers: &http::HeaderMap,
    name: &http::HeaderName,
    expected: &str,
) -> bool {
    let mut values = headers.get_all(name).iter();
    let Some(first) = values.next() else {
        return false;
    };
    let Ok(first) = first.to_str() else {
        return false;
    };
    let Some(mut remaining) = expected.strip_prefix(first) else {
        return false;
    };
    let separator = crate::plugins::repeated_request_header_separator(name.as_str());
    for value in values {
        let Ok(value) = value.to_str() else {
            return false;
        };
        let Some(after_separator) = remaining.strip_prefix(separator) else {
            return false;
        };
        let Some(after_value) = after_separator.strip_prefix(value) else {
            return false;
        };
        remaining = after_value;
    }
    remaining.is_empty()
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
/// Reserved gateway-asserted headers (`x-consumer-username`,
/// `x-consumer-custom-id`, and `x-geo-country`) are stripped from the raw base
/// map FIRST, before the merge. The native gRPC path uses the raw inbound
/// `HeaderMap` as its merge base (unlike the reqwest / direct-H2 /
/// WebSocket paths, which build the outbound map from the sanitised
/// `ctx.headers`), so a forged client value would otherwise survive when
/// no principal or GeoIP assertion is resolved — `proxy_headers` then carries
/// no authoritative key to overwrite it. Removing these fields before the merge
/// closes the spoof while still letting a genuinely gateway-asserted
/// value (present in `proxy_headers` only after successful auth) layer
/// back on and reach the backend.
///
/// Encapsulating the merge-then-strip dance in one helper means both
/// gRPC entry points (`proxy_grpc_request_streaming` and
/// `proxy_grpc_request_core`) share a single tested implementation;
/// neither can call the steps in the wrong order.
pub fn merge_proxy_headers_and_strip_for_grpc(
    headers: &mut http::HeaderMap,
    proxy_headers: &std::collections::HashMap<String, String>,
) {
    // Drop client-supplied reserved assertion headers from the raw base BEFORE
    // the merge, so a verified gateway value carried in `proxy_headers`
    // (post-auth) is layered back on and preserved.
    strip_reserved_gateway_assertion_headers(headers);

    for (k, v) in proxy_headers {
        let Ok(name) = http::HeaderName::from_bytes(k.as_bytes()) else {
            continue;
        };
        if raw_header_values_match_materialized(headers, &name, v) {
            continue;
        }
        if let Ok(val) = http::HeaderValue::from_str(v) {
            headers.insert(name, val);
        }
    }
    strip_backend_request_headers_for_grpc(headers);
}

/// Returns `true` for headers that must NOT cross the backend-response trust
/// boundary: the RFC 9110 §7.6.1 response-direction hop-by-hop set plus
/// Ferrum-owned internal response control fields.
///
/// Note that this set differs from the request-direction set:
/// `proxy-authenticate` is response-only, `proxy-authorization` is
/// request-only. `content-length` is preserved on responses because the
/// downstream client uses it for framing.
///
/// This boundary also strips Ferrum-owned response control fields. Those
/// fields are injected only after backend response collection and must never
/// be accepted from an untrusted backend: otherwise a backend could forge
/// internal provenance consumed by a later trusted plugin phase.
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
    ) || is_internal_response_control_header(name)
}

/// Ferrum-owned response fields used only between trusted proxy phases.
///
/// Use an ASCII-insensitive comparison because backend decoders normalize
/// names but plugin-produced maps can still contain mixed-case keys before the
/// final client-boundary sanitation pass.
#[inline]
fn is_internal_response_control_header(name: &str) -> bool {
    crate::plugins::grpc_web::is_internal_grpc_web_bridge_header(name)
}

/// Case-insensitive final-wire counterpart for plugin-produced response maps.
///
/// Keep the common lowercase path on the canonical match above. Only names
/// containing uppercase ASCII need the slower defensive comparison because
/// backend decoding already normalizes names while plugins may not.
#[inline]
fn is_client_response_hop_by_hop_header(name: &str) -> bool {
    if is_backend_response_strip_header(name) {
        return true;
    }
    if !name.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return false;
    }
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-authenticate")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailer")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("upgrade")
}

/// Whether a plugin-produced response map needs a final hop-by-hop strip.
/// A dynamic Connection-nominated field necessarily arrives with Connection,
/// so detecting the static field is sufficient to trigger the full pass.
pub(crate) fn has_client_response_hop_by_hop_headers(
    headers: &std::collections::HashMap<String, String>,
) -> bool {
    headers
        .keys()
        .any(|name| is_client_response_hop_by_hop_header(name))
}

/// In-place RFC 9110 §7.6.1 response-direction hop-by-hop trailer strip.
///
/// Shared by the H2 streaming wrapper (`proxy::body::StripHopByHopTrailers`)
/// and the H3 cross-protocol gRPC streaming bridge so the two trailer-strip
/// sites cannot drift. Mirrors the buffered helper
/// `grpc_proxy::collect_buffered_grpc_trailers`, which applies the same static
/// predicate.
///
/// No `Connection`-listed strip is applied: these trailers come off an H2/H3
/// backend, where a `Connection` header cannot survive frame decoding
/// (RFC 9113 §8.2.2), so `parse_connection_listed_headers` would be a no-op —
/// and the buffered/streaming-wrapper paths likewise apply only the static
/// predicate, so omitting it keeps all three sites identical.
pub(crate) fn strip_response_hop_by_hop_trailers(trailers: &mut http::HeaderMap) {
    let to_remove: Vec<http::HeaderName> = trailers
        .keys()
        .filter(|name| is_backend_response_strip_header(name.as_str()))
        .cloned()
        .collect();
    for name in to_remove {
        trailers.remove(&name);
    }
}

/// Closed set of response header destinations that plugins must not configure
/// as write targets. Framing (`content-length`, `transfer-encoding`,
/// `trailer`) and connection control (`connection`, `upgrade`, …) are owned by
/// the gateway's final protocol boundary, not by `response_transformer` /
/// `response_mock` static rules.
///
/// `remove` of these names remains allowed (it is a no-op after origin strip).
/// Rename sources may still name them so a rule can move a value *away* from a
/// protocol-managed field; only the rename *destination* is rejected.
pub const PROTOCOL_MANAGED_PLUGIN_RESPONSE_DESTINATION_NAMES: &[&str] = &[
    "connection",
    "content-length",
    "keep-alive",
    "proxy-authenticate",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Case-insensitive membership in
/// [`PROTOCOL_MANAGED_PLUGIN_RESPONSE_DESTINATION_NAMES`].
#[inline]
pub fn is_protocol_managed_plugin_response_destination(name: &str) -> bool {
    let lower = if name.bytes().any(|b| b.is_ascii_uppercase()) {
        std::borrow::Cow::Owned(name.to_ascii_lowercase())
    } else {
        std::borrow::Cow::Borrowed(name)
    };
    PROTOCOL_MANAGED_PLUGIN_RESPONSE_DESTINATION_NAMES.contains(&lower.as_ref())
}

/// How the final client-wire boundary should derive `Content-Length`.
///
/// Hop-by-hop and Connection-listed fields are always stripped. Body framing
/// is then repaired from this hint so a plugin cannot leave a stale or hostile
/// length on the map after `after_proxy`.
#[derive(Debug, Clone, Copy)]
pub enum ClientResponseFraming {
    /// Buffered / synthetic body whose wire length is known. Sets
    /// `Content-Length` to `len` unless the status forbids a body (then
    /// strips it). Not for `HEAD` — use [`Self::Head`] so a backend
    /// representation length is preserved instead of inventing `0` from an
    /// empty wire body.
    ExactBody { status: u16, len: u64 },
    /// Ordinary streaming response whose final wire length is unknown at header
    /// time: `Content-Length` is removed outright.
    ///
    /// Nothing on this path can verify a length against the bytes that will
    /// actually be written, so a value surviving `after_proxy` is an unverified
    /// claim — and `security_headers.set`, `opa.deny_headers`, and any other
    /// operator-configured response writer can author a *syntactically valid*
    /// one. Preserving it would publish a framing lie: on an HTTP/1.1 chain a
    /// recipient that believes the length and one that reads to the connection
    /// close disagree about where the message ends, which is the request/response
    /// desync primitive this boundary exists to remove.
    ///
    /// Removing it is safe on every protocol Ferrum speaks: HTTP/1.1 falls back
    /// to chunked transfer-coding (or connection close), and HTTP/2 / HTTP/3
    /// frame the body with END_STREAM / FIN. Only the trusted [`Self::Head`]
    /// case may keep a representation length, and only because the gateway —
    /// not a plugin — established that the response carries no body at all.
    Streaming,
    /// `HEAD`, or a gateway-selected status that forbids a message body: the
    /// wire body is empty *by protocol*, so a surviving `Content-Length`
    /// describes the representation a `GET` would have returned rather than the
    /// bytes on the wire and cannot desync framing.
    ///
    /// Preserves one valid decimal `Content-Length` when the status may carry a
    /// body, canonicalizes its key spelling, drops invalid values, and drops the
    /// field entirely (including every case variant) when the status forbids a
    /// body.
    ///
    /// This variant is chosen STRUCTURALLY — from the trusted request method and
    /// the gateway-selected status — never from a response header name or value,
    /// and never from a caller-supplied boolean that a future call site could
    /// forget to derive.
    Head { status: u16 },
    /// Native gRPC trailers-only error: HTTP 200 with terminal metadata in the
    /// header block and no DATA frames. gRPC never frames with
    /// `Content-Length`, and the body is empty by construction, so the field is
    /// removed outright — neither invented as `0` (which would break the
    /// trailers-only frame sequence clients expect) nor preserved from a
    /// plugin-authored value (which would be a framing lie on an empty body).
    ///
    /// The `Content-Length` outcome now coincides with [`Self::Streaming`], but
    /// the variant is kept distinct because the two assert different things:
    /// `Streaming` says "the length is not yet knowable", while `TrailersOnly`
    /// says "there are no DATA frames at all and gRPC never frames with
    /// `Content-Length`". Collapsing them would make a future length-bearing
    /// relaxation of one silently apply to the other.
    TrailersOnly,
}

/// Trusted body-omission signal for a final reject / synthetic response writer.
///
/// Derived only from the request method and the gateway-selected status through
/// the shared synthetic-response wire contract
/// ([`crate::plugins::utils::synthetic_response::synthetic_response_omits_body`]).
/// It must never be inferred from response header names or values: plugins and
/// backends control those, and that is exactly the input the protocol-framing
/// advisory covers.
///
/// The default is deliberately [`Self::WireBody`] — the fail-closed choice. A
/// caller that forgets to derive the signal publishes an authoritative exact
/// length instead of preserving an attacker-authored one; the worst outcome is
/// a `HEAD` reject losing its representation length, never a smuggling primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RejectBodyDisposition {
    /// Ordinary HTTP reject (including failed WebSocket handshakes): the final
    /// body slice *is* the wire representation, so its length is authoritative —
    /// including zero. Any plugin-authored `Content-Length` is replaced.
    #[default]
    WireBody,
    /// `HEAD`, or a status that forbids a message body. The shared contract
    /// ([`crate::plugins::utils::synthetic_response::prepare_synthetic_response_wire`])
    /// already emptied the body and established (or stripped) the representation
    /// `Content-Length`; only that length may survive. An empty wire body here
    /// must not be turned into `Content-Length: 0`.
    OmittedByProtocol,
}

impl RejectBodyDisposition {
    /// Derive the disposition from the trusted request method and the final
    /// gateway-selected status.
    #[inline]
    pub fn for_request(method: &str, status: u16) -> Self {
        use crate::plugins::utils::synthetic_response::synthetic_response_omits_body;
        if synthetic_response_omits_body(method, status) {
            Self::OmittedByProtocol
        } else {
            Self::WireBody
        }
    }
}

/// Which trailer-section semantics one reconciliation is applying.
///
/// This is the ONLY thing that can exempt a trailer field name, and it is chosen
/// STRUCTURALLY by each call site from the dispatch it already committed to —
/// never from the trailer's own name, and never from a request header a client
/// controls. A plain response therefore cannot buy protection for a field by
/// calling it `grpc-status`; that would hand any backend a one-word bypass of
/// the response-header policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TrailerSectionKind {
    /// Plain HTTP/HTTP-3 response trailers. Every field is ordinary
    /// backend-supplied response metadata and NO field name is exempt —
    /// `grpc-status` included.
    PlainResponse,
    /// A native gRPC TERMINAL trailer section, on a dispatch the gateway itself
    /// selected as native gRPC.
    ///
    /// Only the three reserved fields
    /// (`grpc-status` / `grpc-message` / `grpc-status-details-bin`) carry
    /// protocol-required RPC outcome; dropping or rewriting them would destroy
    /// the client's view of the call, so they survive governance unconditionally.
    /// EVERY other field in that section is gRPC application metadata — exactly
    /// what GHSA-r78v-rc86-6r86 reports as bypassing `response_transformer` —
    /// and is governed exactly like a plain trailer field, including the
    /// fail-closed `Unbounded` arm.
    NativeGrpcTerminal,
}

impl TrailerSectionKind {
    /// Whether this field is protocol-required terminal status that generic
    /// response-header governance must not touch.
    ///
    /// `http::HeaderName::as_str` is always lowercase, so the exact-match
    /// inventory shared with the buffered gRPC paths
    /// (`grpc_proxy::is_reserved_grpc_terminal_metadata`) is authoritative here.
    /// It is an EXACT three-name set, not a `grpc-` prefix: `grpc-encoding`,
    /// `grpc-accept-encoding`, and any other `grpc-`-named field are application
    /// metadata and stay governed.
    fn field_is_reserved(self, field: &str) -> bool {
        match self {
            Self::PlainResponse => false,
            Self::NativeGrpcTerminal => {
                crate::proxy::grpc_proxy::is_reserved_grpc_terminal_metadata(field)
            }
        }
    }
}

impl ClientResponseFraming {
    /// Framing for a final reject/synthetic writer whose body bytes are already
    /// final.
    ///
    /// An ordinary empty reject resolves to `ExactBody { len: 0 }` so the
    /// canonical `Content-Length: 0` replaces anything a mutable response hook
    /// left behind. Only a trusted [`RejectBodyDisposition::OmittedByProtocol`]
    /// selects [`Self::Head`], where a `HEAD` representation length must survive
    /// untouched.
    ///
    /// A non-empty `body_len` always wins: the caller is about to write those
    /// bytes, so claiming the protocol omitted the body would publish a length
    /// that does not match the wire. That keeps a caller which derived the
    /// disposition without running
    /// [`crate::plugins::utils::synthetic_response::prepare_synthetic_response_wire`]
    /// framed correctly instead of length-less.
    #[inline]
    pub fn for_final_reject(
        status: u16,
        body_len: usize,
        disposition: RejectBodyDisposition,
    ) -> Self {
        match disposition {
            RejectBodyDisposition::OmittedByProtocol if body_len == 0 => Self::Head { status },
            _ => Self::ExactBody {
                status,
                len: body_len as u64,
            },
        }
    }

    /// Framing for a fully buffered client response whose body bytes are final.
    ///
    /// Shared by the H1/H2 buffered writer, the native HTTP/3 buffered writer,
    /// and the HTTP/3 cross-protocol bridge so the three cannot drift: on a
    /// buffered path the gateway holds the exact wire body, so a stale or
    /// plugin-authored `Content-Length` is replaced rather than preserved.
    ///
    /// `HEAD` is the one exception — its wire body is empty by protocol while
    /// `Content-Length` still describes the representation a `GET` would return,
    /// so [`Self::Head`] keeps the backend value instead of overwriting it
    /// with `0`.
    #[inline]
    pub fn for_buffered_response(method: &str, status: u16, body_len: usize) -> Self {
        if request_method_omits_response_body(method) {
            Self::Head { status }
        } else {
            Self::ExactBody {
                status,
                len: body_len as u64,
            }
        }
    }

    /// Framing for a **streaming** plain-HTTP client response whose final wire
    /// length is not knowable at header-write time.
    ///
    /// Shared by every H1/H2/H3 streaming writer so the ordinary-vs-`HEAD`
    /// distinction is derived once, from the trusted request method, instead of
    /// being spelled out per call site. An ordinary response resolves to
    /// [`Self::Streaming`] and therefore loses any `Content-Length` that
    /// survived `after_proxy`; only `HEAD` resolves to [`Self::Head`], where the
    /// wire body is empty by protocol and a valid representation length may
    /// stand.
    ///
    /// Native gRPC (and gRPC-Web translation) must NOT use this: gRPC has no
    /// `HEAD` and never frames with `Content-Length`, so those writers pass
    /// [`Self::Streaming`] / [`Self::TrailersOnly`] directly.
    #[inline]
    pub fn for_streaming_response(method: &str, status: u16) -> Self {
        if request_method_omits_response_body(method) {
            Self::Head { status }
        } else {
            Self::Streaming
        }
    }

    /// Framing for a fully buffered **gRPC** response whose body bytes are final.
    ///
    /// An empty body means the response carries no DATA frames at all: either a
    /// genuine native Trailers-Only response, or a gRPC error a plugin reject
    /// produced in `after_proxy`, `on_response_body`, or `on_final_response_body`
    /// (all three normalize to `body: []` with the plugin's own header map).
    /// gRPC never frames with `Content-Length`, so the field is removed outright
    /// — never invented as `0`, never preserved from a plugin-authored map.
    ///
    /// Keying on the final body rather than on which hook produced it is what
    /// makes this total: the reject arms do not share a single flag, so any
    /// phase-based discriminator silently misses the ones it does not enumerate.
    ///
    /// A non-empty buffered body publishes its exact length. gRPC has no `HEAD`,
    /// so there is no representation-length case to preserve here.
    #[inline]
    pub fn for_buffered_grpc(status: u16, body_len: usize) -> Self {
        if body_len == 0 {
            Self::TrailersOnly
        } else {
            Self::ExactBody {
                status,
                len: body_len as u64,
            }
        }
    }
}

/// Whether a plugin-produced map needs the full wire sanitizer for `framing`.
///
/// Hot paths that can share an immutable header map use this to avoid cloning
/// when the map is already clean and framing requires no `Content-Length`
/// rewrite.
pub fn needs_client_response_wire_sanitization(
    headers: &std::collections::HashMap<String, String>,
    framing: ClientResponseFraming,
) -> bool {
    if has_client_response_hop_by_hop_headers(headers)
        || headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("content-length") && name != "content-length")
    {
        return true;
    }
    match framing {
        ClientResponseFraming::ExactBody { status, len } => {
            if status_forbids_response_body(status) {
                headers.contains_key("content-length")
            } else {
                !headers
                    .get("content-length")
                    .is_some_and(|value| canonical_content_length_matches(value, len))
            }
        }
        ClientResponseFraming::Head { status } => {
            if status_forbids_response_body(status) {
                headers
                    .keys()
                    .any(|name| name.eq_ignore_ascii_case("content-length"))
            } else {
                preserved_content_length_needs_repair(headers)
            }
        }
        ClientResponseFraming::Streaming | ClientResponseFraming::TrailersOnly => headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("content-length")),
    }
}

/// Whether an existing value is already the exact canonical spelling
/// [`set_content_length_header`] would write for `expected`.
///
/// Stricter than [`is_wire_valid_content_length`]: a leading zero is legal on
/// the wire but is not what `u64::to_string()` produces, so `041` is reported as
/// needing repair to keep the "already canonical" fast path honest.
#[inline]
fn canonical_content_length_matches(value: &str, expected: u64) -> bool {
    let bytes = value.as_bytes();
    is_wire_valid_content_length(value)
        && (bytes.len() == 1 || bytes[0] != b'0')
        && value.parse::<u64>() == Ok(expected)
}

/// Statuses that must not carry a message body (RFC 9110 §6.4.1 / §15.2).
///
/// Delegates to the shared synthetic-response wire contract rather than
/// re-listing the statuses. The two halves of the reject boundary must agree:
/// [`RejectBodyDisposition::for_request`] derives its omission signal from
/// [`crate::plugins::utils::synthetic_response::synthetic_response_omits_body`]
/// (which is built on the same predicate), and
/// [`ClientResponseFraming::for_final_reject`] hands the result here for the
/// actual `Content-Length` decision. A second copy of the status list would let
/// those two disagree the moment either side gains a status — and a disposition
/// that says "omitted" paired with a framing repair that says "body allowed"
/// preserves exactly the plugin-authored length this boundary exists to remove.
#[inline]
fn status_forbids_response_body(status: u16) -> bool {
    crate::plugins::utils::synthetic_response::status_forbids_response_body(status)
}

/// Methods whose response never carries content bytes (`HEAD`).
///
/// Delegates to the same shared contract as [`status_forbids_response_body`] so
/// the framing constructors and [`RejectBodyDisposition::for_request`] cannot
/// disagree about which requests are allowed to keep a representation length.
#[inline]
fn request_method_omits_response_body(method: &str) -> bool {
    crate::plugins::utils::synthetic_response::request_method_omits_response_body(method)
}

/// Whether a value is a legal `Content-Length` field value for the wire.
///
/// RFC 9110 §8.6 defines `Content-Length = 1*DIGIT`, so acceptance must be an
/// explicit ASCII-digit check — **not** `parse::<u64>()` alone. Rust's integer
/// `FromStr` accepts a leading `+`, so a plugin-authored `Content-Length: +42`
/// parses successfully while being malformed on the wire: a recipient may read
/// it as `42`, as `0`, or reject the message, and disagreeing intermediaries on
/// an H1 chain is exactly the framing-desync primitive this boundary exists to
/// remove. Overflowing values (more digits than `u64` holds) are likewise
/// refused because the gateway cannot represent, compare, or repair them.
///
/// Leading zeroes remain accepted: `1*DIGIT` permits them and the value is
/// unambiguous, so a valid backend spelling is preserved rather than rewritten.
#[inline]
fn is_wire_valid_content_length(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u64>().is_ok()
}

fn preserved_content_length_needs_repair(
    headers: &std::collections::HashMap<String, String>,
) -> bool {
    let mut count = 0usize;
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        count += 1;
        // `is_wire_valid_content_length` subsumes the old trim comparison:
        // a digits-only value cannot carry leading or trailing whitespace.
        if count > 1 || name != "content-length" || !is_wire_valid_content_length(value) {
            return true;
        }
    }
    false
}

/// Preserve already-safe `content-length` key/value storage — including
/// parseable leading-zero values — and repair only invalid or ambiguous
/// storage. Multiple case variants are duplicate `Content-Length` fields
/// once converted to an HTTP HeaderMap, so fail closed by removing all of them.
///
/// Already-safe common path: exactly one lowercase `content-length` whose value
/// is a bare `1*DIGIT` string under the same acceptance policy as
/// [`is_wire_valid_content_length`] is left untouched — no remove or reinsert
/// allocation. Leading zeroes remain accepted (and preserved) because
/// `1*DIGIT` permits them.
///
/// Repair only rehomes a value that is still an unambiguous decimal length once
/// surrounding whitespace is removed. A spelling that is not `1*DIGIT` after
/// trimming (a signed `+42`, a non-numeric string, an overflowing run of
/// digits) is dropped outright rather than reinterpreted: the gateway has no way
/// to verify the claim, and omitting the field leaves the response correctly
/// framed by the protocol's own end-of-body signal.
///
/// Reached only from [`ClientResponseFraming::Head`] — the sole arm that
/// preserves a caller-supplied length at all.
fn canonicalize_preserved_content_length(headers: &mut std::collections::HashMap<String, String>) {
    // Hot path: nothing to repair — keep existing key/value storage.
    if !preserved_content_length_needs_repair(headers) {
        return;
    }
    let mut parsed = None;
    let mut count = 0usize;
    for (name, value) in headers.iter() {
        if !name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        count += 1;
        let trimmed = value.trim();
        let value = is_wire_valid_content_length(trimmed)
            .then(|| trimmed.parse::<u64>().ok())
            .flatten();
        if count == 1 {
            parsed = value;
        } else {
            parsed = None;
        }
    }
    if count == 0 {
        return;
    }
    remove_content_length_header(headers);
    if count == 1
        && let Some(len) = parsed
    {
        headers.insert("content-length".to_string(), len.to_string());
    }
}

/// Remove every `Content-Length` case variant from a plugin/backend string map.
///
/// [`ClientResponseFraming::Streaming`] now removes the field itself, so callers
/// on paths that replace or retranslate the body (native H3 gRPC streaming,
/// gRPC-Web translation, stream inspectors, deadline replacement) use this only
/// to drop a length that internal accounting must not read either — the
/// gateway's own `content_length_header_value` captures happen *after* those
/// omissions, and a stale backend length there would misclassify a truncated or
/// retranslated body. It remains mandatory before
/// [`ClientResponseFraming::Head`], which still preserves a valid value.
#[inline]
pub fn remove_content_length_header(headers: &mut std::collections::HashMap<String, String>) {
    headers.retain(|name, _| !name.eq_ignore_ascii_case("content-length"));
}

/// The declared `Content-Length` the final wire boundary considers unambiguous,
/// captured for the gateway's own accounting *before*
/// [`ClientResponseFraming::Streaming`] removes the field.
///
/// Streaming writers still need a backend-declared length internally — H3
/// graceful-close completeness classification, the direct-H2 large-response
/// coalescer bypass, response body preallocation. Those reads used to happen
/// against the post-sanitization map, so this reproduces exactly what that map
/// would have held: `None` unless there is exactly one `Content-Length` case
/// variant whose trimmed value is a `1*DIGIT` decimal that fits `u64`, and
/// `None` for any status that forbids a message body.
///
/// It is deliberately NOT [`content_length_header_value`], which returns the
/// first `parse()`-able variant: that accepts a signed `+42` and silently picks
/// one of several conflicting duplicates, neither of which may inform gateway
/// truncation decisions.
pub fn preserved_response_content_length(
    headers: &std::collections::HashMap<String, String>,
    status: u16,
) -> Option<u64> {
    if status_forbids_response_body(status) {
        return None;
    }
    let mut found = None;
    let mut count = 0usize;
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        count += 1;
        if count > 1 {
            // Duplicate field once converted to a HeaderMap — fail closed.
            return None;
        }
        let trimmed = value.trim();
        if !is_wire_valid_content_length(trimmed) {
            return None;
        }
        found = trimmed.parse::<u64>().ok();
    }
    found
}

fn set_content_length_header(headers: &mut std::collections::HashMap<String, String>, len: u64) {
    // Hot path: exactly one lowercase canonical Content-Length whose untrimmed
    // decimal value already matches the trusted length — preserve existing
    // key/value storage instead of remove+reinsert allocation.
    if headers
        .get("content-length")
        .is_some_and(|value| canonical_content_length_matches(value, len))
        && !headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("content-length") && name != "content-length")
    {
        return;
    }
    remove_content_length_header(headers);
    headers.insert("content-length".to_string(), len.to_string());
}

/// Outcome of a case-insensitive lookup into a plugin-facing header map.
///
/// Plugins may synthesize several case variants of one field name (`x-name`
/// alongside `X-Name`), and a `HashMap` yields them in arbitrary order.
/// Collapsing that to "whichever variant iteration reached first" would let the
/// trailer reconciliation compare against a copy the policy never touched and
/// miss the changed or added duplicate, so ambiguity is a distinct outcome
/// rather than a value — and every ambiguous transition is treated as governed.
#[derive(Debug, PartialEq, Eq)]
enum CaseInsensitiveHeader<'a> {
    /// No key in the map matches the field name.
    Absent,
    /// Exactly one key matches; this is its value.
    Unique(&'a str),
    /// Two or more case variants match, so no single value represents the field.
    Ambiguous,
}

/// Case-insensitive lookup into a plugin-facing header map. Plugins may
/// synthesize mixed-case keys, so the trailer reconciliation cannot rely on the
/// map being normalized — and must not silently pick one of several variants.
fn find_header_value_ci<'a>(
    headers: &'a std::collections::HashMap<String, String>,
    name: &str,
) -> CaseInsensitiveHeader<'a> {
    let mut found: Option<&'a str> = None;
    for (key, value) in headers {
        if !key.eq_ignore_ascii_case(name) {
            continue;
        }
        if found.is_some() {
            return CaseInsensitiveHeader::Ambiguous;
        }
        found = Some(value.as_str());
    }
    match found {
        Some(value) => CaseInsensitiveHeader::Unique(value),
        None => CaseInsensitiveHeader::Absent,
    }
}

/// Owned pre-policy form of [`CaseInsensitiveHeader`]. Carried inside the
/// `pub(crate)` witness, so it shares that visibility.
#[derive(Debug)]
pub(crate) enum PrePolicyHeaderValue {
    Absent,
    Unique(String),
    Ambiguous,
}

impl PrePolicyHeaderValue {
    fn capture(lookup: CaseInsensitiveHeader<'_>) -> Self {
        match lookup {
            CaseInsensitiveHeader::Absent => Self::Absent,
            CaseInsensitiveHeader::Unique(value) => Self::Unique(value.to_string()),
            CaseInsensitiveHeader::Ambiguous => Self::Ambiguous,
        }
    }

    /// Whether the field is PROVABLY unchanged between capture and the client
    /// boundary. Only two transitions qualify: absent stayed absent, and a
    /// single value stayed the same single value. Anything else — an appearing
    /// or disappearing field, a changed value, or duplicate case variants on
    /// either side — is unproven and therefore governed.
    fn is_unchanged(&self, now: &CaseInsensitiveHeader<'_>) -> bool {
        match (self, now) {
            (Self::Absent, CaseInsensitiveHeader::Absent) => true,
            (Self::Unique(before), CaseInsensitiveHeader::Unique(after)) => before == after,
            _ => false,
        }
    }
}

/// Backend values, captured before any response-header phase ran, for exactly
/// the field names a backend trailer section also carries.
///
/// The captured form is bounded by the TRAILER count rather than the header
/// count: the reconciliation only has to answer "did the response-header phases
/// change THIS name?", so a response without trailers allocates nothing at all.
pub(crate) enum ResponseTrailerPolicyWitness {
    /// Nothing was captured, so the reconciliation cannot prove the
    /// response-header phases left any field alone. Every trailer name is
    /// treated as mutated: callers without a witness fail closed instead of
    /// forwarding an unreconciled trailer section.
    Unproven,
    /// No response-header phase could run for this response, so no field can
    /// have changed. Preserves the issue #2941 pass-through for chains that
    /// cannot touch the response headers at all.
    NoHeaderPolicyPhase,
    /// `(trailer field name, pre-policy backend header value)`.
    PrePolicyValues(Vec<(http::HeaderName, PrePolicyHeaderValue)>),
}

impl ResponseTrailerPolicyWitness {
    /// Capture the pre-policy backend header value for every field name the
    /// backend also sent as a trailer. Call this before the first response-header
    /// phase (`after_proxy`) runs.
    pub(crate) fn capture(
        trailers: &http::HeaderMap,
        response_headers: &std::collections::HashMap<String, String>,
    ) -> Self {
        let mut observed = Vec::with_capacity(trailers.keys_len());
        for name in trailers.keys() {
            let lookup = find_header_value_ci(response_headers, name.as_str());
            observed.push((name.clone(), PrePolicyHeaderValue::capture(lookup)));
        }
        Self::PrePolicyValues(observed)
    }

    /// Whether the response-header phases changed this field between capture
    /// and the client boundary.
    ///
    /// A name absent from the witness fails closed: the only way that happens is
    /// a trailer field the capture never saw, which means the reconciliation
    /// cannot prove the chain left it alone.
    fn was_mutated(
        &self,
        name: &http::HeaderName,
        response_headers: &std::collections::HashMap<String, String>,
    ) -> bool {
        match self {
            Self::Unproven => true,
            Self::NoHeaderPolicyPhase => false,
            Self::PrePolicyValues(observed) => {
                let Some((_, before)) = observed.iter().find(|(known, _)| known == name) else {
                    // A trailer field the capture never saw. Unprovable, so
                    // governed.
                    return true;
                };
                let now = find_header_value_ci(response_headers, name.as_str());
                !before.is_unchanged(&now)
            }
        }
    }
}

/// Response-trailer governance for one request: config-time name/prefix unions
/// read once from the plugin cache, plus the request-resolved fail-closed arm,
/// threaded down the HTTP/3 relay helpers.
#[derive(Clone, Copy)]
pub(crate) struct ResponseTrailerGovernance<'a> {
    /// Union of `Plugin::response_trailer_policy()` exact names for this proxy
    /// and protocol, precomputed per reload.
    pub(crate) policy_names: &'a [String],
    /// Union of `Plugin::response_trailer_policy()` case-insensitive ASCII
    /// prefixes for this proxy and protocol, precomputed per reload.
    pub(crate) policy_prefixes: &'a [String],
    /// At least one plugin declared `ResponseTrailerPolicy::Unbounded`, or a
    /// plugin that declared `ResponseTrailerPolicy::RequestConditionalUnbounded`
    /// applies it to THIS request
    /// (`PluginCacheRequestView::unbounded_response_trailer_policy_applies`).
    pub(crate) unbounded: bool,
}

/// Allocation-free per-response ownership for the small, fixed set of
/// end-to-end fields written directly onto the plain streaming-HTTP/2 response
/// builder.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct GatewayOwnedResponseHeaders(u8);

#[derive(Clone, Copy, Debug)]
pub(crate) enum GatewayOwnedResponseHeader {
    Via = 1 << 0,
    AltSvc = 1 << 1,
    GatewayError = 1 << 2,
    GatewayUpstreamStatus = 1 << 3,
}

impl GatewayOwnedResponseHeaders {
    pub(crate) fn insert(&mut self, header: GatewayOwnedResponseHeader) {
        self.0 |= header as u8;
    }

    fn owns(self, field: &str) -> bool {
        let bit = match field {
            "via" => GatewayOwnedResponseHeader::Via as u8,
            "alt-svc" => GatewayOwnedResponseHeader::AltSvc as u8,
            "x-gateway-error" => GatewayOwnedResponseHeader::GatewayError as u8,
            "x-gateway-upstream-status" => GatewayOwnedResponseHeader::GatewayUpstreamStatus as u8,
            _ => return false,
        };
        self.0 & bit != 0
    }

    /// Build the bitset from field names. Production callers use
    /// [`Self::insert`] at the point of each builder write; this name-driven
    /// form exists so external tests can reach the real name-to-variant mapping
    /// through [`crate::_test_support`] rather than restating it.
    #[allow(dead_code)] // Bin target omits lib::_test_support; external tests call via that seam.
    pub(crate) fn from_names(names: &[String]) -> Self {
        let mut owned = Self::default();
        for name in names {
            let header = if name.eq_ignore_ascii_case("via") {
                Some(GatewayOwnedResponseHeader::Via)
            } else if name.eq_ignore_ascii_case("alt-svc") {
                Some(GatewayOwnedResponseHeader::AltSvc)
            } else if name.eq_ignore_ascii_case("x-gateway-error") {
                Some(GatewayOwnedResponseHeader::GatewayError)
            } else if name.eq_ignore_ascii_case("x-gateway-upstream-status") {
                Some(GatewayOwnedResponseHeader::GatewayUpstreamStatus)
            } else {
                None
            };
            if let Some(header) = header {
                owned.insert(header);
            }
        }
        owned
    }
}

/// The backend's response headers as a STREAMING relay saw them before its
/// response-header phases ran.
///
/// A streaming relay cannot use the buffered capture: the initial HEADERS frame
/// is on the wire long before the backend's trailer section exists, so the set
/// of trailer field names is unknown at capture time. Retaining the pre-policy
/// map instead keeps the evidence bounded by the response's own header count —
/// one clone per streaming RESPONSE, never per frame — and defers the
/// per-trailer-name comparison to the trailer boundary, where it is bounded by
/// the trailer count exactly as on the buffered path.
pub(crate) enum PrePolicyResponseHeaders {
    /// No evidence retained; the witness fails closed.
    Unproven,
    /// No response-header phase can run for this response.
    NoHeaderPolicyPhase,
    /// Pre-policy backend header map.
    Snapshot(std::collections::HashMap<String, String>),
}

impl PrePolicyResponseHeaders {
    /// Decide what evidence a streaming relay needs, and capture only that.
    ///
    /// * An `Unbounded` chain drops the whole reconcilable trailer section no
    ///   matter what the headers did, so no evidence could change the outcome
    ///   and none is retained.
    /// * A chain with no response-header phase (`header_phases_can_mutate` is
    ///   false) cannot have changed anything, so the snapshot would be a clone
    ///   compared against itself. Callers must fold their own CORE response-header
    ///   mutations into that flag, not just the plugin chain — the HTTP/3 relays
    ///   pass `true` when they will synthesize a default `content-type`, because
    ///   that field goes on the wire exactly like a plugin write.
    /// * Otherwise the snapshot is the only way to tell a policy mutation from
    ///   an untouched backend field once the trailers arrive.
    pub(crate) fn capture_for_streaming(
        response_headers: &std::collections::HashMap<String, String>,
        governance: ResponseTrailerGovernance<'_>,
        header_phases_can_mutate: bool,
    ) -> Self {
        if governance.unbounded {
            Self::Unproven
        } else if header_phases_can_mutate {
            Self::Snapshot(response_headers.clone())
        } else {
            Self::NoHeaderPolicyPhase
        }
    }

    fn witness(&self, trailers: &http::HeaderMap) -> ResponseTrailerPolicyWitness {
        match self {
            Self::Unproven => ResponseTrailerPolicyWitness::Unproven,
            Self::NoHeaderPolicyPhase => ResponseTrailerPolicyWitness::NoHeaderPolicyPhase,
            Self::Snapshot(pre_policy) => {
                ResponseTrailerPolicyWitness::capture(trailers, pre_policy)
            }
        }
    }
}

/// Owned, self-contained form of the streaming trailer-policy boundary, for
/// relays whose trailer frame is produced by a BODY that outlives the request
/// handler.
///
/// The native-HTTP/3 relays reconcile inline, so they can borrow the handler's
/// final header map and pre-policy snapshot ([`ResponseTrailerGovernance`] +
/// [`PrePolicyResponseHeaders`]). A streaming HTTP/2 response instead hands its
/// body to hyper and returns: the backend TRAILERS frame is read minutes later,
/// on a different task, long after `handle_proxy_request_inner`'s locals are
/// gone. This struct is what the body carries instead — the same three inputs,
/// owned.
///
/// Construction is once per governed streaming RESPONSE (one header-map clone
/// for `final_headers`, one for the pre-policy snapshot, one `Arc` bump each for
/// the precomputed policy names and prefixes, plus an allocation-free bitset of
/// builder fields this response actually wrote). Never per body frame: the body
/// wrapper only touches this on the single TRAILERS frame, and the
/// reconciliation itself is bounded by the trailer count exactly as on the
/// buffered path.
pub(crate) struct StreamingResponseTrailerGovernor {
    /// The response headers exactly as they went on the wire, after every
    /// response-header phase AND the gateway's own builder-only writes.
    final_headers: std::collections::HashMap<String, String>,
    /// Evidence captured before the first response-header phase ran.
    pre_policy: PrePolicyResponseHeaders,
    /// Config-time union of `Plugin::response_trailer_policy()` names, shared
    /// from the plugin cache generation (no per-request allocation).
    policy_names: std::sync::Arc<Vec<String>>,
    /// Config-time union of `Plugin::response_trailer_policy()` prefixes,
    /// shared from the plugin cache generation.
    policy_prefixes: std::sync::Arc<Vec<String>>,
    /// End-to-end gateway builder fields this response actually wrote
    /// (`via`, `alt-svc`, `x-gateway-error`, `x-gateway-upstream-status`).
    /// Owned and per-response so an exact-value pre-seeded backend header
    /// cannot hide the write from the mutation witness, and so a field the
    /// gateway did not write on this response stays ungoverned. Empty when
    /// none of those builder writes fired. Never includes hop-by-hop
    /// `connection`.
    gateway_owned_headers: GatewayOwnedResponseHeaders,
    /// Plain response trailers, or a native gRPC terminal section whose three
    /// reserved status fields survive governance. Fixed at construction from the
    /// dispatch the handler already chose — never from a trailer name.
    section: TrailerSectionKind,
    /// Request-resolved unbounded arm: an unconditional declaration or at
    /// least one request-conditional contributor that applies to this response.
    unbounded: bool,
}

impl StreamingResponseTrailerGovernor {
    pub(crate) fn new(
        final_headers: std::collections::HashMap<String, String>,
        pre_policy: PrePolicyResponseHeaders,
        policy_names: std::sync::Arc<Vec<String>>,
        policy_prefixes: std::sync::Arc<Vec<String>>,
        gateway_owned_headers: GatewayOwnedResponseHeaders,
        section: TrailerSectionKind,
        unbounded: bool,
    ) -> Self {
        Self {
            final_headers,
            pre_policy,
            policy_names,
            policy_prefixes,
            gateway_owned_headers,
            section,
            unbounded,
        }
    }

    /// Reconcile one backend trailer block against the retained boundary and
    /// report how many fields were dropped. Call AFTER hop-by-hop stripping so
    /// removed-field telemetry counts only policy-governed drops.
    pub(crate) fn reconcile(&self, trailers: &mut http::HeaderMap) -> usize {
        reconcile_streaming_backend_trailers(
            trailers,
            &self.final_headers,
            &self.pre_policy,
            ResponseTrailerGovernance {
                policy_names: self.policy_names.as_slice(),
                policy_prefixes: self.policy_prefixes.as_slice(),
                unbounded: self.unbounded,
            },
            self.gateway_owned_headers,
            self.section,
        )
    }
}

/// Streaming-relay entry point for
/// [`reconcile_backend_trailers_with_response_policy`].
///
/// Builds the per-trailer witness from the retained pre-policy snapshot and
/// applies the same governance rules the buffered path applies. Call it after
/// every response-header mutation for the path and immediately before
/// `send_trailers`.
///
/// `gateway_owned_headers` is the plain streaming-HTTP/2 builder-ownership bitset
/// (empty on the native-H3 relays, which fold gateway writes into the shared
/// header map before reconciling).
///
/// `section` selects reserved-field handling structurally — see
/// [`TrailerSectionKind`].
pub(crate) fn reconcile_streaming_backend_trailers(
    trailers: &mut http::HeaderMap,
    response_headers: &std::collections::HashMap<String, String>,
    pre_policy: &PrePolicyResponseHeaders,
    governance: ResponseTrailerGovernance<'_>,
    gateway_owned_headers: GatewayOwnedResponseHeaders,
    section: TrailerSectionKind,
) -> usize {
    let witness = pre_policy.witness(trailers);
    reconcile_backend_trailers_with_response_policy(
        trailers,
        response_headers,
        &witness,
        governance.policy_names,
        governance.policy_prefixes,
        gateway_owned_headers,
        section,
        governance.unbounded,
    )
}

/// Drop backend trailer fields that would re-open the response-header policy a
/// protocol path already applied, and report how many were dropped.
///
/// `after_proxy` and every later response-header phase see only the INITIAL
/// header map. A backend trailer carrying a governed field name arrives after
/// that boundary, so without this reconciliation it reintroduces exactly what
/// the policy removed — or contradicts what the policy set — on the wire. The
/// paths that cross it are the buffered native-HTTP/3 send path, the plain
/// native/refined HTTP/3 STREAMING relays, the plain direct-HTTP/2 streaming
/// relay, and — via [`TrailerSectionKind::NativeGrpcTerminal`] — every native
/// STREAMING gRPC relay (the direct-H2 gRPC pool path, the mesh-mTLS
/// `StreamingH2` relay, the H3-to-H2 cross-protocol gRPC bridge, and
/// `dispatch_grpc_native_h3`). The streaming families reach this function
/// through [`reconcile_streaming_backend_trailers`] — the H3 relays inline, the
/// H2 relays through the owned [`StreamingResponseTrailerGovernor`] their
/// response body carries.
///
/// Independent signals decide "governed", because none alone is sufficient:
///
/// * `policy_names` — the config-time union of `Plugin::response_trailer_policy()`
///   exact-name declarations. This is the only signal that can catch a policy
///   REMOVAL which was a NO-OP on the initial header map because the backend
///   sent the field only as a trailer, and an idempotent plugin write the
///   mutation witness cannot see.
/// * `policy_prefixes` — the config-time union of open-ended ASCII prefixes
///   (CORS `access-control-`). Catches trailer-only extension names a finite
///   write list never enumerates.
/// * `gateway_owned_headers` — per-response end-to-end fields the plain streaming
///   HTTP/2 builder actually wrote. Same idempotent-write shape as a plugin
///   declaration: folding the value into `final_headers` alone misses an
///   exact-value pre-seed.
/// * `witness` — the observed per-request mutation. This catches every realized
///   header change, including plugins that declare nothing (custom plugins, and
///   transforms published at request time).
///
/// `unbounded_policy` is the fail-closed arm for a chain containing a plugin
/// whose governed field set is not enumerable at config time: every field is
/// treated as governed.
///
/// The ONLY exemption is `section` — see [`TrailerSectionKind`]. On a
/// [`TrailerSectionKind::PlainResponse`] section there is no field-name
/// exemption of any kind, `grpc-*` names included: exempting a name there would
/// hand any backend a one-word bypass of the response-header policy. On a
/// [`TrailerSectionKind::NativeGrpcTerminal`] section — reachable only because
/// the gateway itself dispatched native gRPC — the three reserved terminal
/// fields survive so generic rules cannot corrupt protocol status, and
/// everything else in that section stays fully governed.
///
/// Removal is loop-until-absent so a trailer name repeated across several field
/// lines cannot leave a surviving duplicate behind.
#[allow(clippy::too_many_arguments)]
pub(crate) fn reconcile_backend_trailers_with_response_policy(
    trailers: &mut http::HeaderMap,
    response_headers: &std::collections::HashMap<String, String>,
    witness: &ResponseTrailerPolicyWitness,
    policy_names: &[String],
    policy_prefixes: &[String],
    gateway_owned_headers: GatewayOwnedResponseHeaders,
    section: TrailerSectionKind,
    unbounded_policy: bool,
) -> usize {
    let mut to_remove: Vec<http::HeaderName> = Vec::new();
    for name in trailers.keys() {
        let field = name.as_str();
        if section.field_is_reserved(field) {
            // Protocol-required native gRPC terminal status. Never governed:
            // dropping it would ship a truncated RPC with no outcome, and
            // rewriting it would report an outcome the backend never produced.
            continue;
        }
        let explicitly_named = policy_names
            .iter()
            .any(|policy| policy.eq_ignore_ascii_case(field));
        let prefix_owned = policy_prefixes.iter().any(|prefix| {
            field.len() >= prefix.len()
                && field.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
        });
        let gateway_owned = gateway_owned_headers.owns(field);
        let governed = explicitly_named
            || prefix_owned
            || gateway_owned
            || unbounded_policy
            || witness.was_mutated(name, response_headers);
        if governed {
            to_remove.push(name.clone());
        }
    }
    for name in &to_remove {
        while trailers.remove(name).is_some() {}
    }
    to_remove.len()
}

/// Strip response-direction hop-by-hop names from a plugin header map.
///
/// Used as the hop-by-hop half of the final client-wire boundary after
/// `after_proxy` hooks (which may reintroduce connection-specific fields such
/// as `Connection: keep-alive`) and before every H1/H2/H3 response builder.
/// Gateway-owned connection options (`Connection: close` during drain, WebSocket
/// `Upgrade`/`Connection`) are applied only after this strip returns.
/// Prefer [`sanitize_client_response_headers_for_wire`] when body framing is known.
pub fn strip_client_response_hop_by_hop_headers(
    headers: &mut std::collections::HashMap<String, String>,
) {
    // Snapshot Connection-nominated names before removing Connection itself.
    // Plugins can synthesize mixed-case keys, so both the static and dynamic
    // comparisons are case-insensitive at this final wire boundary.
    let connection_listed = parse_connection_listed_from_str_map(headers);
    headers.retain(|name, _| {
        !is_client_response_hop_by_hop_header(name)
            && !connection_listed
                .iter()
                .any(|listed| name.eq_ignore_ascii_case(listed))
    });
}

/// Authoritative final protocol-aware response-header sanitizer.
///
/// Runs after every mutable response hook and before every H1/H2/H3 builder:
/// strips hop-by-hop / Connection-listed fields, then derives or repairs
/// `Content-Length` from [`ClientResponseFraming`]. Does not touch trailer
/// frames (gRPC metadata); only the `Trailer` *header* is removed with the
/// hop-by-hop set.
pub fn sanitize_client_response_headers_for_wire(
    headers: &mut std::collections::HashMap<String, String>,
    framing: ClientResponseFraming,
) {
    strip_client_response_hop_by_hop_headers(headers);
    match framing {
        ClientResponseFraming::ExactBody { status, len } => {
            if status_forbids_response_body(status) {
                remove_content_length_header(headers);
            } else {
                set_content_length_header(headers, len);
            }
        }
        ClientResponseFraming::Head { status } => {
            if status_forbids_response_body(status) {
                remove_content_length_header(headers);
            } else {
                // HEAD: the wire body is empty by protocol, so a valid value is
                // a representation length that cannot desync framing. Preserve
                // one, canonicalizing the key/value and removing duplicate case
                // variants before HeaderMap construction.
                canonicalize_preserved_content_length(headers);
            }
        }
        // Ordinary streaming and trailers-only gRPC: nothing here can verify a
        // length against the bytes still to be written, so every case variant
        // goes — including a syntactically valid lowercase value a response hook
        // authored. See `ClientResponseFraming::Streaming`.
        ClientResponseFraming::Streaming | ClientResponseFraming::TrailersOnly => {
            remove_content_length_header(headers)
        }
    }
}

/// Sanitize then apply headers onto a response builder.
pub fn apply_sanitized_response_headers(
    builder: http::response::Builder,
    headers: &mut std::collections::HashMap<String, String>,
    framing: ClientResponseFraming,
) -> http::response::Builder {
    sanitize_client_response_headers_for_wire(headers, framing);
    apply_response_headers(builder, headers)
}

/// Append a cookie to the proxy's newline-separated multi-value representation.
/// [`apply_response_headers`] emits each line as a distinct `Set-Cookie` field.
pub fn append_set_cookie_header(
    headers: &mut std::collections::HashMap<String, String>,
    cookie: String,
) {
    if let Some(existing) = headers.get_mut("set-cookie") {
        if !existing.is_empty() {
            existing.push('\n');
        }
        existing.push_str(&cookie);
    } else {
        headers.insert("set-cookie".to_string(), cookie);
    }
}

/// Apply a response-header map onto a response builder, emitting each
/// newline-separated `set-cookie` value as its own header line.
///
/// `Set-Cookie` must not be folded into one value (RFC 6265), so the proxy keeps
/// multiple cookies newline-joined in the response-header map (see
/// `collect_response_headers_generic` and the sticky-session / OIDC
/// rolling-session appends). `HeaderValue::from_str` rejects the embedded
/// newline, so a joined value would otherwise drop the entire `set-cookie`
/// header. Every protocol response builder (H1, H2/gRPC, H3) routes through this
/// so they split cookies identically.
pub fn apply_response_headers(
    mut builder: http::response::Builder,
    headers: &std::collections::HashMap<String, String>,
) -> http::response::Builder {
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("set-cookie") {
            for cookie_val in v.split('\n') {
                if let Ok(val) = http::HeaderValue::from_str(cookie_val) {
                    builder = builder.header(http::header::SET_COOKIE, val);
                }
            }
        } else if let (Ok(name), Ok(val)) = (
            http::HeaderName::from_bytes(k.as_bytes()),
            http::HeaderValue::from_str(v),
        ) {
            builder = builder.header(name, val);
        }
    }
    builder
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
        assert!(is_backend_request_strip_header("x-grpc-web-mode"));
    }

    #[test]
    fn backend_request_strip_inventory_is_single_source() {
        // The const and predicate are expanded from one macro inventory; this
        // only pins the documented closed-set size so accidental inventory
        // edits remain visible in review. Secondary builders call the
        // predicates directly and do not re-list these names.
        assert_eq!(BACKEND_REQUEST_STRIP_HEADER_NAMES.len(), 11);
        assert_eq!(PROXY_GENERATED_FORWARDING_HEADER_NAMES.len(), 3);
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
    fn proxy_owned_forwarding_header_fail_closes_forwarded_when_regenerating() {
        // Fail-closed ownership: when Ferrum regenerates Forwarded, the client
        // value must be stripped on every transport before the gateway element
        // is written. When regeneration is off, client Forwarded may pass.
        assert!(is_proxy_owned_forwarding_header("forwarded", true));
        assert!(is_proxy_owned_forwarding_header("Forwarded", true));
        assert!(is_proxy_owned_forwarding_header("FORWARDED", true));
        assert!(!is_proxy_owned_forwarding_header("forwarded", false));
        assert!(!is_proxy_owned_forwarding_header("Forwarded", false));
        assert!(is_proxy_owned_forwarding_header("x-forwarded-for", false));
        assert!(is_proxy_owned_forwarding_header("x-forwarded-for", true));
        // Always-owned XFF family must also strip mixed-case plugin keys —
        // reqwest appends, so a bypassed `X-Forwarded-For` precedes Ferrum's.
        for name in [
            "X-Forwarded-For",
            "X-FORWARDED-FOR",
            "X-Forwarded-Proto",
            "X-Forwarded-Host",
        ] {
            assert!(
                is_proxy_owned_forwarding_header(name, false),
                "{name} must be owned regardless of regeneration flag"
            );
            assert!(is_proxy_owned_forwarding_header(name, true));
        }
        assert!(!is_proxy_owned_forwarding_header("via", true));
        assert!(!is_proxy_owned_forwarding_header("authorization", true));
        assert!(!is_proxy_owned_forwarding_header("X-Forwarded", true));
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
    fn response_strip_rejects_backend_forged_grpc_web_bridge_fields() {
        for name in [
            crate::plugins::grpc_web::HEADER_GRPC_WEB_TRAILER_NAMES,
            crate::plugins::grpc_web::HEADER_GRPC_WEB_SHADOWED_TRAILERS,
            "X-Ferrum-Grpc-Web-Trailer-Names",
            "X-Ferrum-Grpc-Web-Shadowed-Trailers",
        ] {
            assert!(
                is_backend_response_strip_header(name),
                "Ferrum-owned response control field `{name}` must be stripped"
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

    #[test]
    fn grpc_merge_drops_client_consumer_identity_when_no_principal() {
        // Security regression (consumer-identity spoofing): the native gRPC
        // path uses the RAW inbound HeaderMap as its merge base. A client can
        // forge `x-consumer-username` / `x-consumer-custom-id`; when no
        // principal is resolved, `proxy_headers` carries no such key, so
        // without a pre-merge strip the forged value would reach the gRPC
        // backend verbatim and be treated as a gateway-asserted principal.
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/grpc"),
        );
        headers.insert(
            http::HeaderName::from_static("x-consumer-username"),
            http::HeaderValue::from_static("admin"),
        );
        headers.insert(
            http::HeaderName::from_static("x-consumer-custom-id"),
            http::HeaderValue::from_static("0001"),
        );

        // No principal resolved -> proxy_headers has no identity keys.
        let proxy_headers: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();

        merge_proxy_headers_and_strip_for_grpc(&mut headers, &proxy_headers);

        assert!(
            headers.get("x-consumer-username").is_none(),
            "client-supplied x-consumer-username must not reach the gRPC backend"
        );
        assert!(
            headers.get("x-consumer-custom-id").is_none(),
            "client-supplied x-consumer-custom-id must not reach the gRPC backend"
        );
    }

    #[test]
    fn grpc_merge_replaces_client_consumer_identity_with_gateway_value() {
        // When a principal IS resolved, the gateway-asserted identity is
        // carried in `proxy_headers` and must layer on top of (replace) any
        // client-supplied value — never the forged one.
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::HeaderName::from_static("x-consumer-username"),
            http::HeaderValue::from_static("spoofed"),
        );
        headers.insert(
            http::HeaderName::from_static("x-consumer-custom-id"),
            http::HeaderValue::from_static("spoofed-id"),
        );

        let mut proxy_headers = std::collections::HashMap::new();
        proxy_headers.insert("x-consumer-username".to_string(), "real-user".to_string());
        proxy_headers.insert("x-consumer-custom-id".to_string(), "real-id".to_string());

        merge_proxy_headers_and_strip_for_grpc(&mut headers, &proxy_headers);

        assert_eq!(
            headers.get("x-consumer-username"),
            Some(&http::HeaderValue::from_static("real-user")),
            "gateway-asserted identity must replace the client value"
        );
        assert_eq!(
            headers.get("x-consumer-custom-id"),
            Some(&http::HeaderValue::from_static("real-id"))
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

    #[test]
    fn strip_response_hop_by_hop_trailers_removes_hop_by_hop_names() {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
        let hop_by_hop = [
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-connection",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
        ];
        for name in hop_by_hop {
            trailers.insert(name, http::HeaderValue::from_static("x"));
        }
        strip_response_hop_by_hop_trailers(&mut trailers);
        for name in hop_by_hop {
            assert!(
                trailers.get(name).is_none(),
                "hop-by-hop trailer `{name}` must be stripped"
            );
        }
        assert_eq!(
            trailers.get("grpc-status").and_then(|v| v.to_str().ok()),
            Some("0"),
            "grpc-status must be preserved"
        );
    }

    #[test]
    fn strip_response_hop_by_hop_trailers_preserves_grpc_and_custom_trailers() {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
        trailers.insert("grpc-message", http::HeaderValue::from_static("ok"));
        trailers.insert("x-custom-trailer", http::HeaderValue::from_static("v"));
        strip_response_hop_by_hop_trailers(&mut trailers);
        assert_eq!(trailers.len(), 3, "no legitimate trailers may be removed");
        assert!(trailers.get("grpc-status").is_some());
        assert!(trailers.get("grpc-message").is_some());
        assert!(trailers.get("x-custom-trailer").is_some());
    }

    #[test]
    fn strip_response_hop_by_hop_trailers_can_empty_an_all_hop_by_hop_map() {
        // The Finding-A scenario: a backend trailer frame of ONLY hop-by-hop
        // names strips down to empty, which is what drives the H3 bridge to
        // finalize the QUIC stream with finish() instead of leaking it open.
        let mut trailers = http::HeaderMap::new();
        trailers.insert(
            "proxy-authenticate",
            http::HeaderValue::from_static("Basic"),
        );
        trailers.insert("proxy-connection", http::HeaderValue::from_static("close"));
        strip_response_hop_by_hop_trailers(&mut trailers);
        assert!(
            trailers.is_empty(),
            "an all-hop-by-hop trailer frame must strip to empty"
        );
    }

    #[test]
    fn apply_response_headers_splits_newline_joined_set_cookie() {
        // Multiple Set-Cookie values are stored newline-joined; each must be
        // emitted as its own header line, otherwise `from_str` rejects the
        // embedded newline and the whole header (incl. the OIDC rolling cookie)
        // is dropped.
        let headers = std::collections::HashMap::from([
            (
                "set-cookie".to_string(),
                "backend=1; Path=/\nferrum_session=abc; HttpOnly".to_string(),
            ),
            ("x-other".to_string(), "v".to_string()),
        ]);
        let resp = apply_response_headers(http::Response::builder(), &headers)
            .body(())
            .expect("response builds");
        let cookies: Vec<&str> = resp
            .headers()
            .get_all(http::header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(cookies.len(), 2, "each cookie must be its own header line");
        assert!(cookies.contains(&"backend=1; Path=/"));
        assert!(cookies.contains(&"ferrum_session=abc; HttpOnly"));
        assert_eq!(
            resp.headers().get("x-other").and_then(|v| v.to_str().ok()),
            Some("v")
        );
    }

    #[test]
    fn protocol_managed_plugin_destinations_cover_framing_and_connection_control() {
        for name in [
            "Connection",
            "CONTENT-LENGTH",
            "keep-alive",
            "Proxy-Authenticate",
            "proxy-connection",
            "TE",
            "Trailer",
            "Transfer-Encoding",
            "Upgrade",
        ] {
            assert!(
                is_protocol_managed_plugin_response_destination(name),
                "{name} must be protocol-managed"
            );
        }
        assert!(!is_protocol_managed_plugin_response_destination("x-custom"));
        assert!(!is_protocol_managed_plugin_response_destination(
            "content-type"
        ));
    }

    #[test]
    fn sanitize_client_response_strips_hop_by_hop_connection_listed_and_repairs_length() {
        let mut headers = std::collections::HashMap::from([
            ("connection".to_string(), "close, x-internal".to_string()),
            ("x-internal".to_string(), "leak".to_string()),
            ("transfer-encoding".to_string(), "chunked".to_string()),
            ("content-length".to_string(), "999".to_string()),
            ("x-ok".to_string(), "1".to_string()),
        ]);
        sanitize_client_response_headers_for_wire(
            &mut headers,
            ClientResponseFraming::ExactBody {
                status: 200,
                len: 4,
            },
        );
        assert!(!headers.contains_key("connection"));
        assert!(!headers.contains_key("x-internal"));
        assert!(!headers.contains_key("transfer-encoding"));
        assert_eq!(headers.get("content-length").map(String::as_str), Some("4"));
        assert_eq!(headers.get("x-ok").map(String::as_str), Some("1"));
    }

    #[test]
    fn sanitize_client_response_strips_content_length_for_no_body_status() {
        let mut headers = std::collections::HashMap::from([
            ("content-length".to_string(), "12".to_string()),
            ("x-ok".to_string(), "1".to_string()),
        ]);
        sanitize_client_response_headers_for_wire(
            &mut headers,
            ClientResponseFraming::ExactBody {
                status: 204,
                len: 12,
            },
        );
        assert!(!headers.contains_key("content-length"));
        assert_eq!(headers.get("x-ok").map(String::as_str), Some("1"));
    }

    #[test]
    fn sanitize_head_strips_invalid_content_length_and_preserves_valid() {
        let mut bad = std::collections::HashMap::from([(
            "content-length".to_string(),
            "not-a-number".to_string(),
        )]);
        sanitize_client_response_headers_for_wire(
            &mut bad,
            ClientResponseFraming::Head { status: 200 },
        );
        assert!(!bad.contains_key("content-length"));

        let mut good =
            std::collections::HashMap::from([("content-length".to_string(), "42".to_string())]);
        sanitize_client_response_headers_for_wire(
            &mut good,
            ClientResponseFraming::Head { status: 200 },
        );
        assert_eq!(good.get("content-length").map(String::as_str), Some("42"));
    }

    #[test]
    fn sanitize_head_canonicalizes_one_mixed_case_length_and_drops_duplicates() {
        let mut mixed =
            std::collections::HashMap::from([("Content-Length".to_string(), " 42 ".to_string())]);
        sanitize_client_response_headers_for_wire(
            &mut mixed,
            ClientResponseFraming::Head { status: 200 },
        );
        assert_eq!(mixed.get("content-length").map(String::as_str), Some("42"));
        assert!(!mixed.contains_key("Content-Length"));

        let mut duplicates = std::collections::HashMap::from([
            ("content-length".to_string(), "42".to_string()),
            ("Content-Length".to_string(), "42".to_string()),
        ]);
        sanitize_client_response_headers_for_wire(
            &mut duplicates,
            ClientResponseFraming::Head { status: 200 },
        );
        assert!(
            !duplicates
                .keys()
                .any(|name| name.eq_ignore_ascii_case("content-length"))
        );
    }

    #[test]
    fn intentional_content_length_omit_before_streaming_sanitize_drops_mixed_case() {
        // Paths that must omit length (H3 gRPC streaming, gRPC-Web translation,
        // inspectors, deadline replacement) strip first so the gateway's own
        // `content_length_header_value` capture cannot read a stale backend
        // length; Streaming sanitization then drops any remaining variant.
        let mut headers = std::collections::HashMap::from([
            ("Content-Length".to_string(), "999".to_string()),
            ("x-ok".to_string(), "1".to_string()),
        ]);
        assert_eq!(preserved_response_content_length(&headers, 200), Some(999));
        remove_content_length_header(&mut headers);
        sanitize_client_response_headers_for_wire(&mut headers, ClientResponseFraming::Streaming);
        assert!(
            !headers
                .keys()
                .any(|name| name.eq_ignore_ascii_case("content-length")),
            "mixed-case Content-Length must not survive omit-then-Streaming sanitize"
        );
        assert_eq!(headers.get("x-ok").map(String::as_str), Some("1"));
        assert_eq!(preserved_response_content_length(&headers, 200), None);
    }

    #[test]
    fn sanitize_trailers_only_removes_every_content_length_variant() {
        let mut headers = std::collections::HashMap::from([
            ("Content-Length".to_string(), "999".to_string()),
            ("content-length".to_string(), "0".to_string()),
            ("grpc-status".to_string(), "7".to_string()),
        ]);
        assert!(needs_client_response_wire_sanitization(
            &headers,
            ClientResponseFraming::TrailersOnly
        ));
        sanitize_client_response_headers_for_wire(
            &mut headers,
            ClientResponseFraming::TrailersOnly,
        );
        assert!(
            !headers
                .keys()
                .any(|name| name.eq_ignore_ascii_case("content-length"))
        );
        assert_eq!(headers.get("grpc-status").map(String::as_str), Some("7"));

        let mut clean = std::collections::HashMap::new();
        clean.insert("grpc-status".to_string(), "7".to_string());
        assert!(!needs_client_response_wire_sanitization(
            &clean,
            ClientResponseFraming::TrailersOnly
        ));
    }

    #[test]
    fn exact_body_sanitization_predicate_accepts_only_canonical_matching_length() {
        let framing = ClientResponseFraming::ExactBody {
            status: 200,
            len: 42,
        };
        let canonical =
            std::collections::HashMap::from([("content-length".to_string(), "42".to_string())]);
        assert!(!needs_client_response_wire_sanitization(
            &canonical, framing
        ));

        for value in ["041", "042", "42 ", "+42", "41"] {
            let headers = std::collections::HashMap::from([(
                "content-length".to_string(),
                value.to_string(),
            )]);
            assert!(
                needs_client_response_wire_sanitization(&headers, framing),
                "{value:?} must be repaired"
            );
        }
    }
}

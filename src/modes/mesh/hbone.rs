//! Istio-flavored HBONE request metadata helpers.
//!
//! HBONE is HTTP/2 CONNECT over mTLS. Ferrum keeps this parsing boundary small
//! and explicit so future ambient transports can plug in beside it.
#![allow(dead_code)]

use std::collections::BTreeMap;

use http::{HeaderMap, Method, Version};
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};

use crate::identity::SpiffeId;

/// Istio convention for HBONE-capable listeners.
pub const ISTIO_HBONE_PORT: u16 = 15008;
pub const BAGGAGE_HEADER: &str = "baggage";
pub const HBONE_PROTOCOL: &str = "hbone";
/// `x-ferrum-mesh-protocol` value stamped on a datagram-over-HBONE CONNECT
/// (F3 §3.3 Stage 4). DISTINCT from [`HBONE_PROTOCOL`]: a `udp` CONNECT carries
/// length-delimited datagrams (see `crate::proxy::mesh_udp_frame`), not a raw
/// byte stream, so the destination MUST unframe it into a local `UdpSocket`
/// rather than byte-relaying it to a TCP backend. The two markers are mutually
/// exclusive; an OLD destination that predates Stage 4 sees an unrecognized
/// marker and `is_hbone_connect` returns `false`, so it 404s (fail-closed skew).
pub const UDP_PROTOCOL: &str = "udp";

/// Per-stream identity metadata carried by ambient HBONE requests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HboneIdentity {
    pub source_principal: Option<SpiffeId>,
    pub destination_principal: Option<SpiffeId>,
    pub baggage: BTreeMap<String, String>,
}

impl HboneIdentity {
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let baggage = parse_baggage(headers);
        Self::from_baggage(baggage)
    }

    pub fn from_baggage_header(raw: &str) -> Self {
        Self::from_baggage(parse_baggage_header(raw))
    }

    pub fn from_baggage_values<'a>(values: impl IntoIterator<Item = &'a str>) -> Self {
        Self::from_baggage(parse_baggage_values(values))
    }

    fn from_baggage(baggage: BTreeMap<String, String>) -> Self {
        let source_principal = first_baggage_value(
            &baggage,
            &[
                "source.principal",
                "source_principal",
                "source.identity",
                "source_identity",
                "src.identity",
                "src_identity",
            ],
        )
        .and_then(parse_spiffe);
        let destination_principal = first_baggage_value(
            &baggage,
            &[
                "destination.principal",
                "destination_principal",
                "destination.identity",
                "destination_identity",
                "dst.identity",
                "dst_identity",
            ],
        )
        .and_then(parse_spiffe);

        Self {
            source_principal,
            destination_principal,
            baggage,
        }
    }
}

/// Build the outbound W3C baggage header Ferrum uses when a gateway opens an
/// HBONE tunnel into the mesh. The receiver still validates this against the
/// authenticated SPIFFE peer before trusting it.
pub fn baggage_header_for_source(source: &SpiffeId) -> String {
    let encoded = utf8_percent_encode(source.as_str(), NON_ALPHANUMERIC).to_string();
    format!("source.principal={encoded}")
}

/// Detect an HBONE-*shaped* CONNECT stream from request parts.
///
/// HBONE is HTTP/2 CONNECT plus mTLS. This predicate only checks the wire
/// shape: an HTTP/2 CONNECT, optionally carrying an explicit
/// `x-ferrum-mesh-protocol`/`x-istio-protocol: hbone` marker used by early
/// clients and tests. A marker that is *present* but is anything other than
/// `hbone` — an unrecognized value, or a non-UTF-8 / unparseable one — is NOT
/// treated as markerless; it fails closed to the "neither" branch (see
/// [`is_udp_hbone_connect`]) so a malformed marker can never slip into the
/// byte-stream relay. It deliberately says nothing about the authenticated
/// peer — a bare HTTP/2 CONNECT looks identical on the wire whether or not the
/// mTLS handshake produced a SPIFFE peer identity.
///
/// Shape detection alone MUST NOT authorize relaying a CONNECT as an HBONE
/// tunnel: relaying byte-copies the stream straight to a backend, so a
/// marker-less CONNECT with no authenticated peer would otherwise become an
/// unauthenticated transparent TCP tunnel. Gate the relay on
/// [`is_authenticated_hbone_connect`] (or equivalently, require
/// `peer_spiffe_id.is_some()` at the relay site) — this function is only safe
/// for shape-dependent, non-relay decisions such as request-path normalization,
/// metadata tagging, and the body-buffering branch that preserves the upgrade
/// handle.
pub fn is_hbone_connect(method: &Method, version: Version, headers: &HeaderMap) -> bool {
    if method != Method::CONNECT || version != Version::HTTP_2 {
        return false;
    }
    match headers
        .get("x-ferrum-mesh-protocol")
        .or_else(|| headers.get("x-istio-protocol"))
    {
        // No marker at all → the markerless default IS byte-stream HBONE.
        None => true,
        // A PRESENT marker is byte-stream HBONE only if it parses as exactly
        // `hbone`. A present-but-unparseable (non-UTF-8 / non-visible-ASCII) or
        // otherwise unrecognized value is NOT treated as markerless — it fails
        // closed to the "neither" branch so a malformed marker can never collapse
        // into the byte-stream relay (the dispatcher then 405s the unrecognized
        // CONNECT). This keeps `is_hbone_connect`/`is_udp_hbone_connect` disjoint
        // AND exhaustive: header-absence and present-but-unrecognized are distinct.
        Some(value) => value
            .to_str()
            .ok()
            .is_some_and(|value| value.eq_ignore_ascii_case(HBONE_PROTOCOL)),
    }
}

/// Detect a datagram-over-HBONE CONNECT (F3 §3.3 Stage 4): an HTTP/2 CONNECT
/// carrying an EXPLICIT `x-ferrum-mesh-protocol: udp` (or `x-istio-protocol: udp`)
/// marker.
///
/// This is intentionally NARROWER than [`is_hbone_connect`]: where the HBONE
/// predicate accepts a marker-LESS CONNECT (`None` → byte-stream HBONE), the UDP
/// predicate requires the EXPLICIT `udp` marker. That keeps the two transports
/// disjoint — a bare CONNECT is byte-stream HBONE (`is_hbone_connect` true,
/// `is_udp_hbone_connect` false); a `udp`-marked CONNECT is datagram UDP
/// (`is_hbone_connect` FALSE because the marker isn't `hbone`,
/// `is_udp_hbone_connect` true). A destination that predates Stage 4 has no
/// `udp` branch, so a `udp` CONNECT falls through both its `is_hbone_connect`
/// check (false) and its (absent) UDP check → 404, the fail-closed skew posture.
///
/// Like [`is_hbone_connect`] this is a WIRE-SHAPE predicate only and says
/// nothing about the authenticated peer. The relay path must still require an
/// authenticated mesh peer (`peer_spiffe_id.is_some()`) before unframing a
/// `udp` CONNECT into a local socket — a marker alone never authorizes a tunnel.
pub fn is_udp_hbone_connect(method: &Method, version: Version, headers: &HeaderMap) -> bool {
    if method != Method::CONNECT || version != Version::HTTP_2 {
        return false;
    }
    headers
        .get("x-ferrum-mesh-protocol")
        .or_else(|| headers.get("x-istio-protocol"))
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case(UDP_PROTOCOL))
}

/// Predicate combining the [`is_hbone_connect`] wire shape **and** an
/// authenticated, trust-domain-verified peer SPIFFE identity
/// (`peer_spiffe_id.is_some()`).
///
/// This encodes the HBONE-relay authorization invariant but is **not** itself
/// the runtime gate. The relay enforces the authenticated-peer half inline in
/// `handle_hbone_request` (`src/proxy/hbone_proxy.rs`, the
/// `ctx.peer_spiffe_id.is_none()` reject); by the time the relay runs, the wire
/// shape has already been validated at dispatch (`is_hbone_connect_request`).
/// This function combines both halves in one place and is exercised at the
/// dispatch/test layer — keep it in sync with that inline relay check.
///
/// The mesh inbound mTLS/HBONE listener populates `peer_spiffe_id` (via the
/// `spiffe_identity` plugin or the node-waypoint identity path) only after the
/// peer cert's SAN trust domain has been validated against the local SVID
/// bundle plus federated bundles, so a present `peer_spiffe_id` is exactly "a
/// verified mesh peer terminated mTLS on this listener".
///
/// A bare (marker-less) CONNECT with no authenticated peer is **not** a valid
/// HBONE tunnel and must be rejected rather than silently relayed; an explicit
/// HBONE marker does not bypass this — a marker-bearing CONNECT from an
/// unauthenticated peer is rejected too. Honoring the marker without a verified
/// peer would let any client that can reach the listener assert "I am HBONE"
/// and obtain a transparent TCP tunnel.
pub fn is_authenticated_hbone_connect(
    method: &Method,
    version: Version,
    headers: &HeaderMap,
    peer_spiffe_id: Option<&SpiffeId>,
) -> bool {
    peer_spiffe_id.is_some() && is_hbone_connect(method, version, headers)
}

pub fn parse_baggage(headers: &HeaderMap) -> BTreeMap<String, String> {
    parse_baggage_values(
        headers
            .get_all(BAGGAGE_HEADER)
            .iter()
            .filter_map(|value| value.to_str().ok()),
    )
}

pub fn parse_baggage_header(raw: &str) -> BTreeMap<String, String> {
    let mut baggage = BTreeMap::new();
    parse_baggage_header_into(raw, &mut baggage);
    baggage
}

pub fn parse_baggage_values<'a>(
    values: impl IntoIterator<Item = &'a str>,
) -> BTreeMap<String, String> {
    let mut baggage = BTreeMap::new();
    for raw in values {
        parse_baggage_header_into(raw, &mut baggage);
    }
    baggage
}

fn parse_baggage_header_into(raw: &str, baggage: &mut BTreeMap<String, String>) {
    for member in split_baggage_members(raw) {
        let Some((key, value_and_params)) = split_once_quoted(member.trim(), '=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let value = unquote_baggage_value(
            split_once_quoted(value_and_params, ';')
                .map(|(value, _)| value)
                .unwrap_or(value_and_params)
                .trim(),
        );
        if value.is_empty() {
            continue;
        }
        baggage.insert(key.to_string(), decode_baggage_value(&value));
    }
}

fn split_baggage_members(raw: &str) -> Vec<&str> {
    split_quoted(raw, ',').unwrap_or_else(|| raw.split(',').collect())
}

fn split_quoted(raw: &str, delimiter: char) -> Option<Vec<&str>> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let mut escaped = false;

    for (idx, ch) in raw.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_quotes && ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
            continue;
        }
        if ch == delimiter && !in_quotes {
            parts.push(&raw[start..idx]);
            start = idx + ch.len_utf8();
        }
    }

    if in_quotes || escaped {
        return None;
    }

    parts.push(&raw[start..]);
    Some(parts)
}

fn split_once_quoted(raw: &str, delimiter: char) -> Option<(&str, &str)> {
    let mut in_quotes = false;
    let mut escaped = false;

    for (idx, ch) in raw.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_quotes && ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
            continue;
        }
        if ch == delimiter && !in_quotes {
            return Some((&raw[..idx], &raw[idx + ch.len_utf8()..]));
        }
    }

    None
}

fn unquote_baggage_value(value: &str) -> String {
    let Some(inner) = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    else {
        return value.to_string();
    };

    let mut unquoted = String::with_capacity(inner.len());
    let mut escaped = false;
    for ch in inner.chars() {
        if escaped {
            unquoted.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else {
            unquoted.push(ch);
        }
    }
    if escaped {
        unquoted.push('\\');
    }
    unquoted
}

fn decode_baggage_value(value: &str) -> String {
    percent_decode_str(value)
        .decode_utf8()
        .map(|decoded| decoded.into_owned())
        .unwrap_or_else(|_| value.to_string())
}

fn first_baggage_value<'a>(
    baggage: &'a BTreeMap<String, String>,
    keys: &[&str],
) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| baggage.get(*key).map(String::as_str))
}

fn parse_spiffe(value: &str) -> Option<SpiffeId> {
    SpiffeId::new(value).ok()
}

/// Apply [`filter_baggage_header`] in place to a `HashMap<String, String>` of
/// outbound headers. Removes the `baggage` key entirely when no members
/// survive. No-op when `key_prefixes` is empty or the map has no `baggage`
/// header.
///
/// This is the canonical entry point shared by every egress site
/// (HTTP/1.1+H2 dispatch in `proxy/mod.rs`, native HTTP/3 frontend in
/// `http3/server.rs`, WebSocket handshake header collection). Keep all
/// future egress points using this helper rather than re-implementing the
/// strip — divergent implementations are how reviewer P1/P2 issues happen.
pub fn strip_egress_baggage_in_map(
    headers: &mut std::collections::HashMap<String, String>,
    key_prefixes: &[String],
) {
    if key_prefixes.is_empty() {
        return;
    }
    let Some(key) = baggage_header_key_in_map(headers) else {
        return;
    };
    let Some(raw) = headers.get(&key) else {
        return;
    };
    let raw_owned = raw.clone();
    match filter_baggage_header(&raw_owned, key_prefixes) {
        Some(filtered) if filtered != raw_owned => {
            headers.insert(key, filtered);
        }
        None => {
            headers.remove(&key);
        }
        Some(_) => {}
    }
}

/// Case-insensitive baggage-header presence check for HashMap-shaped header
/// collections. Materialized request headers normally use lowercase keys, but
/// request-transforming plugins can add mixed-case header names; egress
/// stripping must still honor HTTP's case-insensitive header-name semantics.
#[inline]
pub fn has_baggage_header_in_map(headers: &std::collections::HashMap<String, String>) -> bool {
    headers.contains_key(BAGGAGE_HEADER)
        || headers
            .keys()
            .any(|key| key.eq_ignore_ascii_case(BAGGAGE_HEADER))
}

fn baggage_header_key_in_map(
    headers: &std::collections::HashMap<String, String>,
) -> Option<String> {
    if headers.contains_key(BAGGAGE_HEADER) {
        return Some(BAGGAGE_HEADER.to_string());
    }
    headers
        .keys()
        .find(|key| key.eq_ignore_ascii_case(BAGGAGE_HEADER))
        .cloned()
}

/// Apply [`filter_baggage_header`] in place to a `Vec<(String, String)>` of
/// outbound headers. WebSocket and other code paths that build header
/// collections as ordered Vecs use this helper. Removes any `baggage`
/// entries entirely when no members survive.
pub fn strip_egress_baggage_in_vec(headers: &mut Vec<(String, String)>, key_prefixes: &[String]) {
    if key_prefixes.is_empty() {
        return;
    }
    // WebSocket handshake collects via `collect_forwardable_headers` which
    // lowercases keys; match against the canonical lowercase header name.
    let mut idx = 0;
    while idx < headers.len() {
        if headers[idx].0.eq_ignore_ascii_case(BAGGAGE_HEADER) {
            let raw = std::mem::take(&mut headers[idx].1);
            match filter_baggage_header(&raw, key_prefixes) {
                Some(filtered) => {
                    headers[idx].1 = filtered;
                    idx += 1;
                }
                None => {
                    headers.remove(idx);
                }
            }
        } else {
            idx += 1;
        }
    }
}

/// Filter a W3C `baggage` header value, removing any member whose key starts
/// with one of the given prefixes. Member text — including any `;props`
/// segment — is preserved verbatim for survivors so end-to-end tracing
/// baggage round-trips unchanged. Splitting is quote-aware, so user-defined
/// baggage values such as `trace.note="x, y"` survive with their comma intact.
///
/// Returns `Some(filtered)` when at least one member survives. Returns `None`
/// when every member matched a prefix; the caller should remove the header
/// entirely rather than send `baggage: ` with an empty value.
///
/// `key_prefixes` empty → input is returned unchanged with no parse cost
/// (fast path for the default-disabled feature). Prefix matching is
/// case-sensitive on the key, since W3C baggage keys use the `token`
/// grammar (RFC 7230) which is also case-sensitive in baggage.
///
pub fn filter_baggage_header(raw: &str, key_prefixes: &[String]) -> Option<String> {
    if key_prefixes.is_empty() {
        return Some(raw.to_string());
    }
    let mut survivors: Vec<&str> = Vec::new();
    for member in split_baggage_members(raw) {
        let trimmed = member.trim();
        if trimmed.is_empty() {
            continue;
        }
        let key = match split_once_quoted(trimmed, '=') {
            Some((key, _)) => key.trim(),
            None => {
                // Malformed (no '='). Match the existing parser's
                // pass-through behavior — keep the original member.
                survivors.push(trimmed);
                continue;
            }
        };
        if key_prefixes.iter().any(|prefix| key.starts_with(prefix)) {
            continue;
        }
        survivors.push(trimmed);
    }
    if survivors.is_empty() {
        None
    } else {
        Some(survivors.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_http2_connect_as_hbone() {
        let headers = HeaderMap::new();
        assert!(is_hbone_connect(
            &Method::CONNECT,
            Version::HTTP_2,
            &headers
        ));
        assert!(!is_hbone_connect(&Method::GET, Version::HTTP_2, &headers));
        assert!(!is_hbone_connect(
            &Method::CONNECT,
            Version::HTTP_11,
            &headers
        ));
    }

    #[test]
    fn parses_source_and_destination_identity_from_baggage() {
        let mut headers = HeaderMap::new();
        headers.insert(
            BAGGAGE_HEADER,
            "source.principal=spiffe://cluster.local/ns/default/sa/client, \
             destination.principal=spiffe://cluster.local/ns/default/sa/server;meta=ignored"
                .parse()
                .expect("valid baggage header"),
        );

        let identity = HboneIdentity::from_headers(&headers);
        assert_eq!(
            identity.source_principal.as_ref().map(ToString::to_string),
            Some("spiffe://cluster.local/ns/default/sa/client".to_string())
        );
        assert_eq!(
            identity
                .destination_principal
                .as_ref()
                .map(ToString::to_string),
            Some("spiffe://cluster.local/ns/default/sa/server".to_string())
        );
    }

    #[test]
    fn parses_percent_encoded_identity_from_baggage() {
        let identity = HboneIdentity::from_baggage_header(
            "source.principal=spiffe%3A%2F%2Fcluster.local%2Fns%2Fdefault%2Fsa%2Fclient",
        );

        assert_eq!(
            identity.source_principal.as_ref().map(ToString::to_string),
            Some("spiffe://cluster.local/ns/default/sa/client".to_string())
        );
        assert_eq!(
            identity.baggage.get("source.principal").map(String::as_str),
            Some("spiffe://cluster.local/ns/default/sa/client")
        );
    }

    #[test]
    fn builds_source_baggage_header() {
        let id = SpiffeId::new("spiffe://cluster.local/ns/default/sa/gateway").unwrap();
        let header = baggage_header_for_source(&id);
        assert_eq!(
            HboneIdentity::from_baggage_header(&header)
                .source_principal
                .as_ref()
                .map(SpiffeId::as_str),
            Some("spiffe://cluster.local/ns/default/sa/gateway")
        );
        assert!(
            header.starts_with("source.principal=spiffe%3A%2F%2F"),
            "SPIFFE URI must be percent encoded for baggage transport"
        );
    }

    #[test]
    fn parses_baggage_quoted_value_with_comma() {
        let identity = HboneIdentity::from_baggage_header(
            "trace.note=\"alpha, beta\",source.principal=spiffe://cluster.local/ns/default/sa/client",
        );

        assert_eq!(
            identity.baggage.get("trace.note").map(String::as_str),
            Some("alpha, beta")
        );
        assert_eq!(
            identity.source_principal.as_ref().map(ToString::to_string),
            Some("spiffe://cluster.local/ns/default/sa/client".to_string())
        );
    }

    #[test]
    fn filter_baggage_header_empty_prefixes_returns_input_unchanged() {
        let prefixes: Vec<String> = Vec::new();
        assert_eq!(
            filter_baggage_header("a=1,b=2", &prefixes),
            Some("a=1,b=2".to_string())
        );
    }

    #[test]
    fn filter_baggage_header_strips_exact_prefix_and_keeps_others() {
        let prefixes = vec!["source.".to_string()];
        assert_eq!(
            filter_baggage_header("source.principal=spiffe://x,userid=alice", &prefixes,),
            Some("userid=alice".to_string())
        );
    }

    #[test]
    fn filter_baggage_header_drops_header_when_only_match_present() {
        let prefixes = vec!["source.".to_string()];
        assert_eq!(
            filter_baggage_header("source.principal=spiffe://x", &prefixes),
            None
        );
    }

    #[test]
    fn filter_baggage_header_preserves_props_on_survivors() {
        let prefixes = vec!["source.".to_string()];
        assert_eq!(
            filter_baggage_header(
                "userid=alice;ttl=300,source.principal=spiffe://x",
                &prefixes,
            ),
            Some("userid=alice;ttl=300".to_string())
        );
    }

    #[test]
    fn filter_baggage_header_preserves_quoted_comma_on_survivors() {
        let prefixes = vec!["source.".to_string()];
        assert_eq!(
            filter_baggage_header(
                "trace.note=\"alpha, beta\",source.principal=spiffe://x",
                &prefixes,
            ),
            Some("trace.note=\"alpha, beta\"".to_string())
        );
    }

    #[test]
    fn filter_baggage_header_strips_after_unterminated_quote() {
        let prefixes = vec!["source.".to_string()];
        assert_eq!(
            filter_baggage_header(
                "trace.note=\"alpha,source.principal=spiffe://x,userid=alice",
                &prefixes,
            ),
            Some("trace.note=\"alpha,userid=alice".to_string())
        );
    }

    #[test]
    fn filter_baggage_header_handles_whitespace_and_multiple_prefixes() {
        let prefixes = vec!["source.".to_string(), "destination.".to_string()];
        assert_eq!(
            filter_baggage_header(
                " source.principal=foo , destination.principal=bar , userid=alice ",
                &prefixes,
            ),
            Some("userid=alice".to_string())
        );
    }

    #[test]
    fn filter_baggage_header_keeps_malformed_members() {
        let prefixes = vec!["source.".to_string()];
        assert_eq!(
            filter_baggage_header("=novalue,a=1", &prefixes),
            Some("=novalue,a=1".to_string())
        );
    }

    #[test]
    fn filter_baggage_header_skips_empty_members() {
        let prefixes = vec!["source.".to_string()];
        // Two adjacent commas produce an empty member — should not appear in output.
        assert_eq!(
            filter_baggage_header("userid=alice,,source.principal=foo", &prefixes),
            Some("userid=alice".to_string())
        );
    }

    #[test]
    fn strip_egress_baggage_in_map_removes_matching_member() {
        let mut headers = std::collections::HashMap::from([
            (
                "baggage".to_string(),
                "source.principal=spiffe://x,userid=alice".to_string(),
            ),
            ("host".to_string(), "example.com".to_string()),
        ]);
        strip_egress_baggage_in_map(&mut headers, &["source.".to_string()]);
        assert_eq!(
            headers.get("baggage").map(String::as_str),
            Some("userid=alice")
        );
        assert_eq!(headers.get("host").map(String::as_str), Some("example.com"));
    }

    #[test]
    fn strip_egress_baggage_in_map_drops_header_when_only_match() {
        let mut headers = std::collections::HashMap::from([(
            "baggage".to_string(),
            "source.principal=spiffe://x".to_string(),
        )]);
        strip_egress_baggage_in_map(&mut headers, &["source.".to_string()]);
        assert!(!headers.contains_key("baggage"));
    }

    #[test]
    fn strip_egress_baggage_in_map_handles_case_insensitive_header_name() {
        let mut headers = std::collections::HashMap::from([(
            "Baggage".to_string(),
            "source.principal=spiffe://x,userid=alice".to_string(),
        )]);
        assert!(has_baggage_header_in_map(&headers));

        strip_egress_baggage_in_map(&mut headers, &["source.".to_string()]);

        assert_eq!(
            headers.get("Baggage").map(String::as_str),
            Some("userid=alice")
        );
        assert!(!headers.contains_key("baggage"));
    }

    #[test]
    fn strip_egress_baggage_in_map_drops_mixed_case_header_when_only_match() {
        let mut headers = std::collections::HashMap::from([(
            "Baggage".to_string(),
            "source.principal=spiffe://x".to_string(),
        )]);

        strip_egress_baggage_in_map(&mut headers, &["source.".to_string()]);

        assert!(!has_baggage_header_in_map(&headers));
    }

    #[test]
    fn strip_egress_baggage_in_map_no_op_when_prefixes_empty() {
        let mut headers = std::collections::HashMap::from([(
            "baggage".to_string(),
            "source.principal=spiffe://x".to_string(),
        )]);
        let prefixes: Vec<String> = Vec::new();
        strip_egress_baggage_in_map(&mut headers, &prefixes);
        assert_eq!(
            headers.get("baggage").map(String::as_str),
            Some("source.principal=spiffe://x")
        );
    }

    #[test]
    fn strip_egress_baggage_in_vec_removes_matching_member() {
        let mut headers = vec![
            ("host".to_string(), "example.com".to_string()),
            (
                "baggage".to_string(),
                "source.principal=spiffe://x,userid=alice".to_string(),
            ),
        ];
        strip_egress_baggage_in_vec(&mut headers, &["source.".to_string()]);
        assert_eq!(
            headers,
            vec![
                ("host".to_string(), "example.com".to_string()),
                ("baggage".to_string(), "userid=alice".to_string()),
            ]
        );
    }

    #[test]
    fn strip_egress_baggage_in_vec_drops_entry_when_no_member_survives() {
        let mut headers = vec![
            ("host".to_string(), "example.com".to_string()),
            (
                "baggage".to_string(),
                "source.principal=spiffe://x".to_string(),
            ),
        ];
        strip_egress_baggage_in_vec(&mut headers, &["source.".to_string()]);
        assert_eq!(
            headers,
            vec![("host".to_string(), "example.com".to_string())]
        );
    }

    #[test]
    fn strip_egress_baggage_in_vec_handles_case_insensitive_header_name() {
        // collect_forwardable_headers may emit lowercased keys; mixed case
        // shouldn't matter for the strip lookup.
        let mut headers = vec![
            ("Host".to_string(), "example.com".to_string()),
            (
                "Baggage".to_string(),
                "source.principal=spiffe://x".to_string(),
            ),
        ];
        strip_egress_baggage_in_vec(&mut headers, &["source.".to_string()]);
        assert_eq!(
            headers,
            vec![("Host".to_string(), "example.com".to_string())]
        );
    }

    #[test]
    fn strip_egress_baggage_in_vec_no_op_when_prefixes_empty() {
        let mut headers = vec![(
            "baggage".to_string(),
            "source.principal=spiffe://x".to_string(),
        )];
        let prefixes: Vec<String> = Vec::new();
        strip_egress_baggage_in_vec(&mut headers, &prefixes);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].1, "source.principal=spiffe://x");
    }

    #[test]
    fn parses_split_baggage_headers() {
        let mut headers = HeaderMap::new();
        headers.append(
            BAGGAGE_HEADER,
            "source.principal=spiffe://cluster.local/ns/default/sa/client"
                .parse()
                .expect("valid baggage header"),
        );
        headers.append(
            BAGGAGE_HEADER,
            "destination.principal=spiffe://cluster.local/ns/default/sa/server"
                .parse()
                .expect("valid baggage header"),
        );

        let identity = HboneIdentity::from_headers(&headers);

        assert_eq!(
            identity.source_principal.as_ref().map(ToString::to_string),
            Some("spiffe://cluster.local/ns/default/sa/client".to_string())
        );
        assert_eq!(
            identity
                .destination_principal
                .as_ref()
                .map(ToString::to_string),
            Some("spiffe://cluster.local/ns/default/sa/server".to_string())
        );
    }

    // ---------------------------------------------------------------
    // from_headers / baggage alias fallback tests
    // ---------------------------------------------------------------

    #[test]
    fn alias_source_principal_underscore_used_when_dotted_missing() {
        let identity = HboneIdentity::from_baggage_header(
            "source_principal=spiffe://cluster.local/ns/default/sa/client",
        );
        assert_eq!(
            identity.source_principal.as_ref().map(ToString::to_string),
            Some("spiffe://cluster.local/ns/default/sa/client".to_string())
        );
    }

    #[test]
    fn alias_source_identity_dotted_used_when_principal_missing() {
        let identity = HboneIdentity::from_baggage_header(
            "source.identity=spiffe://cluster.local/ns/default/sa/client",
        );
        assert_eq!(
            identity.source_principal.as_ref().map(ToString::to_string),
            Some("spiffe://cluster.local/ns/default/sa/client".to_string())
        );
    }

    #[test]
    fn alias_source_identity_underscore_used_when_others_missing() {
        let identity = HboneIdentity::from_baggage_header(
            "source_identity=spiffe://cluster.local/ns/default/sa/client",
        );
        assert_eq!(
            identity.source_principal.as_ref().map(ToString::to_string),
            Some("spiffe://cluster.local/ns/default/sa/client".to_string())
        );
    }

    #[test]
    fn alias_src_identity_dotted_used_when_others_missing() {
        let identity = HboneIdentity::from_baggage_header(
            "src.identity=spiffe://cluster.local/ns/default/sa/client",
        );
        assert_eq!(
            identity.source_principal.as_ref().map(ToString::to_string),
            Some("spiffe://cluster.local/ns/default/sa/client".to_string())
        );
    }

    #[test]
    fn alias_src_identity_underscore_used_when_others_missing() {
        let identity = HboneIdentity::from_baggage_header(
            "src_identity=spiffe://cluster.local/ns/default/sa/client",
        );
        assert_eq!(
            identity.source_principal.as_ref().map(ToString::to_string),
            Some("spiffe://cluster.local/ns/default/sa/client".to_string())
        );
    }

    #[test]
    fn alias_destination_principal_underscore_used_when_dotted_missing() {
        let identity = HboneIdentity::from_baggage_header(
            "destination_principal=spiffe://cluster.local/ns/default/sa/server",
        );
        assert_eq!(
            identity
                .destination_principal
                .as_ref()
                .map(ToString::to_string),
            Some("spiffe://cluster.local/ns/default/sa/server".to_string())
        );
    }

    #[test]
    fn alias_dst_identity_used_when_destination_principal_missing() {
        let identity = HboneIdentity::from_baggage_header(
            "dst.identity=spiffe://cluster.local/ns/default/sa/server",
        );
        assert_eq!(
            identity
                .destination_principal
                .as_ref()
                .map(ToString::to_string),
            Some("spiffe://cluster.local/ns/default/sa/server".to_string())
        );
    }

    #[test]
    fn alias_precedence_source_principal_dotted_wins_over_underscore() {
        // source.principal appears first in the alias list, so it takes
        // precedence even though BTreeMap ordering would present
        // source.principal before source_principal anyway.
        let identity = HboneIdentity::from_baggage_header(
            "source.principal=spiffe://cluster.local/ns/default/sa/primary,\
             source_principal=spiffe://cluster.local/ns/default/sa/secondary",
        );
        assert_eq!(
            identity.source_principal.as_ref().map(ToString::to_string),
            Some("spiffe://cluster.local/ns/default/sa/primary".to_string())
        );
    }

    #[test]
    fn alias_precedence_source_principal_wins_over_src_identity() {
        let identity = HboneIdentity::from_baggage_header(
            "src_identity=spiffe://cluster.local/ns/default/sa/fallback,\
             source.principal=spiffe://cluster.local/ns/default/sa/primary",
        );
        assert_eq!(
            identity.source_principal.as_ref().map(ToString::to_string),
            Some("spiffe://cluster.local/ns/default/sa/primary".to_string())
        );
    }

    // ---------------------------------------------------------------
    // from_headers / baggage edge cases
    // ---------------------------------------------------------------

    #[test]
    fn conflicting_source_principal_across_headers_last_header_wins() {
        // BTreeMap::insert overwrites, so the last-seen header's value wins
        // for the same key.
        let mut headers = HeaderMap::new();
        headers.append(
            BAGGAGE_HEADER,
            "source.principal=spiffe://cluster.local/ns/default/sa/first"
                .parse()
                .expect("valid"),
        );
        headers.append(
            BAGGAGE_HEADER,
            "source.principal=spiffe://cluster.local/ns/default/sa/second"
                .parse()
                .expect("valid"),
        );

        let identity = HboneIdentity::from_headers(&headers);
        assert_eq!(
            identity.source_principal.as_ref().map(ToString::to_string),
            Some("spiffe://cluster.local/ns/default/sa/second".to_string())
        );
    }

    #[test]
    fn empty_baggage_header_produces_no_identity() {
        let identity = HboneIdentity::from_baggage_header("");
        assert!(identity.source_principal.is_none());
        assert!(identity.destination_principal.is_none());
        assert!(identity.baggage.is_empty());
    }

    #[test]
    fn destination_principal_without_source_principal() {
        let identity = HboneIdentity::from_baggage_header(
            "destination.principal=spiffe://cluster.local/ns/default/sa/server",
        );
        assert!(identity.source_principal.is_none());
        assert_eq!(
            identity
                .destination_principal
                .as_ref()
                .map(ToString::to_string),
            Some("spiffe://cluster.local/ns/default/sa/server".to_string())
        );
    }

    #[test]
    fn baggage_with_non_spiffe_value_produces_no_identity() {
        let identity = HboneIdentity::from_baggage_header(
            "source.principal=https://not-a-spiffe-id.example.com/path",
        );
        assert!(identity.source_principal.is_none());
        // The raw value is still in the baggage map even though it didn't
        // parse as a SPIFFE ID.
        assert_eq!(
            identity.baggage.get("source.principal").map(String::as_str),
            Some("https://not-a-spiffe-id.example.com/path")
        );
    }

    #[test]
    fn baggage_with_invalid_percent_encoding_preserves_raw_value() {
        // %ZZ is not valid percent encoding. decode_baggage_value falls
        // back to the raw string when percent-decode produces non-UTF-8.
        let identity =
            HboneIdentity::from_baggage_header("source.principal=spiffe%3A%2F%2Fcluster%ZZlocal");
        // The raw value is preserved in baggage (fallback path).
        assert!(identity.baggage.contains_key("source.principal"));
        // The malformed decoded value won't parse as a valid SPIFFE ID.
        assert!(identity.source_principal.is_none());
    }

    #[test]
    fn baggage_with_double_percent_encoding_decodes_once() {
        // Double-encoded: %253A → %3A (one decode pass), not ":"
        let identity = HboneIdentity::from_baggage_header(
            "source.principal=spiffe%253A%252F%252Fcluster.local%252Fns%252Fdefault%252Fsa%252Fclient",
        );
        // After one decode pass, the value is still percent-encoded, not
        // a valid spiffe:// URI.
        assert!(identity.source_principal.is_none());
        assert_eq!(
            identity.baggage.get("source.principal").map(String::as_str),
            Some("spiffe%3A%2F%2Fcluster.local%2Fns%2Fdefault%2Fsa%2Fclient")
        );
    }

    #[test]
    fn baggage_member_with_empty_value_is_skipped() {
        let identity = HboneIdentity::from_baggage_header("source.principal=");
        assert!(identity.source_principal.is_none());
        assert!(identity.baggage.is_empty());
    }

    #[test]
    fn baggage_member_without_equals_is_skipped() {
        let identity = HboneIdentity::from_baggage_header("noequals");
        assert!(identity.source_principal.is_none());
        assert!(identity.baggage.is_empty());
    }

    #[test]
    fn baggage_empty_key_is_skipped() {
        let identity = HboneIdentity::from_baggage_header("=somevalue");
        assert!(identity.baggage.is_empty());
    }

    #[test]
    fn baggage_semicolon_properties_stripped_from_value() {
        // W3C baggage: key=value;property1;property2 — properties after
        // semicolons are metadata, not part of the value.
        let identity = HboneIdentity::from_baggage_header(
            "source.principal=spiffe://cluster.local/ns/default/sa/client;ttl=300;priority=high",
        );
        assert_eq!(
            identity.source_principal.as_ref().map(ToString::to_string),
            Some("spiffe://cluster.local/ns/default/sa/client".to_string())
        );
    }

    #[test]
    fn baggage_multiple_comma_separated_members_in_single_header() {
        let identity = HboneIdentity::from_baggage_header(
            "source.principal=spiffe://cluster.local/ns/default/sa/client,\
             destination.principal=spiffe://cluster.local/ns/default/sa/server,\
             trace-id=abc123",
        );
        assert_eq!(
            identity.source_principal.as_ref().map(ToString::to_string),
            Some("spiffe://cluster.local/ns/default/sa/client".to_string())
        );
        assert_eq!(
            identity
                .destination_principal
                .as_ref()
                .map(ToString::to_string),
            Some("spiffe://cluster.local/ns/default/sa/server".to_string())
        );
        assert_eq!(
            identity.baggage.get("trace-id").map(String::as_str),
            Some("abc123")
        );
    }

    #[test]
    fn from_baggage_values_merges_multiple_header_values() {
        let values = vec![
            "source.principal=spiffe://cluster.local/ns/default/sa/client",
            "destination.principal=spiffe://cluster.local/ns/default/sa/server",
            "trace-id=abc123",
        ];
        let identity = HboneIdentity::from_baggage_values(values);
        assert!(identity.source_principal.is_some());
        assert!(identity.destination_principal.is_some());
        assert_eq!(
            identity.baggage.get("trace-id").map(String::as_str),
            Some("abc123")
        );
    }

    #[test]
    fn baggage_quoted_value_has_quotes_stripped() {
        // The parser trims surrounding quotes from values.
        let identity = HboneIdentity::from_baggage_header(
            "source.principal=\"spiffe://cluster.local/ns/default/sa/client\"",
        );
        assert_eq!(
            identity.source_principal.as_ref().map(ToString::to_string),
            Some("spiffe://cluster.local/ns/default/sa/client".to_string())
        );
    }

    // ---------------------------------------------------------------
    // parse_spiffe tests
    // ---------------------------------------------------------------

    #[test]
    fn parse_spiffe_valid_workload_identity() {
        let id = parse_spiffe("spiffe://trust.domain/ns/default/sa/myapp");
        assert!(id.is_some());
        let id = id.unwrap();
        assert_eq!(id.trust_domain().as_str(), "trust.domain");
        assert_eq!(id.path(), "ns/default/sa/myapp");
    }

    #[test]
    fn parse_spiffe_root_identity_no_path() {
        let id = parse_spiffe("spiffe://cluster.local");
        assert!(id.is_some());
        let id = id.unwrap();
        assert_eq!(id.trust_domain().as_str(), "cluster.local");
        assert_eq!(id.path(), "");
    }

    #[test]
    fn parse_spiffe_non_spiffe_uri_returns_none() {
        assert!(parse_spiffe("https://example.com/path").is_none());
    }

    #[test]
    fn parse_spiffe_empty_string_returns_none() {
        assert!(parse_spiffe("").is_none());
    }

    #[test]
    fn parse_spiffe_no_scheme_returns_none() {
        assert!(parse_spiffe("cluster.local/ns/default/sa/app").is_none());
    }

    #[test]
    fn parse_spiffe_wrong_case_scheme_returns_none() {
        // SPIFFE spec requires lowercase "spiffe" scheme.
        assert!(parse_spiffe("SPIFFE://cluster.local/ns/default/sa/app").is_none());
    }

    #[test]
    fn parse_spiffe_missing_trust_domain_returns_none() {
        assert!(parse_spiffe("spiffe:///ns/default/sa/app").is_none());
    }

    #[test]
    fn parse_spiffe_trailing_slash_returns_none() {
        assert!(parse_spiffe("spiffe://cluster.local/ns/default/sa/app/").is_none());
    }

    #[test]
    fn parse_spiffe_with_query_returns_none() {
        assert!(parse_spiffe("spiffe://cluster.local/ns/default/sa/app?q=1").is_none());
    }

    #[test]
    fn parse_spiffe_with_fragment_returns_none() {
        assert!(parse_spiffe("spiffe://cluster.local/ns/default/sa/app#frag").is_none());
    }

    #[test]
    fn parse_spiffe_special_chars_in_service_account() {
        // Hyphens, underscores, and dots are allowed in path segments.
        let id = parse_spiffe("spiffe://cluster.local/ns/default/sa/my-app_v2.0-beta");
        assert!(id.is_some());
        assert_eq!(id.unwrap().path(), "ns/default/sa/my-app_v2.0-beta");
    }

    #[test]
    fn parse_spiffe_invalid_path_char_returns_none() {
        // Spaces are not allowed in SPIFFE path segments.
        assert!(parse_spiffe("spiffe://cluster.local/ns/default/sa/my app").is_none());
    }

    #[test]
    fn parse_spiffe_empty_path_segment_returns_none() {
        // Double slash creates empty segment.
        assert!(parse_spiffe("spiffe://cluster.local/ns//default/sa/app").is_none());
    }

    // ---------------------------------------------------------------
    // is_hbone_connect tests
    // ---------------------------------------------------------------

    #[test]
    fn is_hbone_connect_with_ferrum_protocol_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-ferrum-mesh-protocol", "hbone".parse().unwrap());
        assert!(is_hbone_connect(
            &Method::CONNECT,
            Version::HTTP_2,
            &headers
        ));
    }

    #[test]
    fn is_hbone_connect_with_istio_protocol_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-istio-protocol", "HBONE".parse().unwrap());
        assert!(is_hbone_connect(
            &Method::CONNECT,
            Version::HTTP_2,
            &headers
        ));
    }

    #[test]
    fn is_hbone_connect_with_non_hbone_protocol_value_returns_false() {
        let mut headers = HeaderMap::new();
        headers.insert("x-ferrum-mesh-protocol", "tcp".parse().unwrap());
        assert!(!is_hbone_connect(
            &Method::CONNECT,
            Version::HTTP_2,
            &headers
        ));
    }

    #[test]
    fn is_hbone_connect_post_request_returns_false() {
        let headers = HeaderMap::new();
        assert!(!is_hbone_connect(&Method::POST, Version::HTTP_2, &headers));
    }

    #[test]
    fn is_hbone_connect_http3_connect_returns_false() {
        // HBONE is strictly HTTP/2 CONNECT.
        let headers = HeaderMap::new();
        assert!(!is_hbone_connect(
            &Method::CONNECT,
            Version::HTTP_3,
            &headers
        ));
    }

    #[test]
    fn is_hbone_connect_http10_connect_returns_false() {
        let headers = HeaderMap::new();
        assert!(!is_hbone_connect(
            &Method::CONNECT,
            Version::HTTP_10,
            &headers
        ));
    }

    #[test]
    fn is_hbone_connect_protocol_header_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert("x-ferrum-mesh-protocol", "HbOnE".parse().unwrap());
        assert!(is_hbone_connect(
            &Method::CONNECT,
            Version::HTTP_2,
            &headers
        ));
    }

    #[test]
    fn is_hbone_connect_ferrum_header_takes_priority_over_istio() {
        // When both headers are present, x-ferrum-mesh-protocol is checked
        // first (via or_else). If it has a non-hbone value, the result is
        // false even though the istio header says hbone.
        let mut headers = HeaderMap::new();
        headers.insert("x-ferrum-mesh-protocol", "tcp".parse().unwrap());
        headers.insert("x-istio-protocol", "hbone".parse().unwrap());
        assert!(!is_hbone_connect(
            &Method::CONNECT,
            Version::HTTP_2,
            &headers
        ));
    }

    // ---------------------------------------------------------------
    // is_authenticated_hbone_connect tests (relay trust boundary)
    // ---------------------------------------------------------------

    fn peer() -> SpiffeId {
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/client").expect("valid spiffe id")
    }

    #[test]
    fn authenticated_hbone_bare_connect_with_peer_is_authorized() {
        let headers = HeaderMap::new();
        let peer = peer();
        assert!(is_authenticated_hbone_connect(
            &Method::CONNECT,
            Version::HTTP_2,
            &headers,
            Some(&peer),
        ));
    }

    #[test]
    fn authenticated_hbone_bare_connect_without_peer_is_rejected() {
        // The core finding: a marker-less HTTP/2 CONNECT with no authenticated
        // peer must NOT be authorized as an HBONE tunnel even though it is
        // HBONE-shaped.
        let headers = HeaderMap::new();
        assert!(is_hbone_connect(
            &Method::CONNECT,
            Version::HTTP_2,
            &headers
        ));
        assert!(!is_authenticated_hbone_connect(
            &Method::CONNECT,
            Version::HTTP_2,
            &headers,
            None,
        ));
    }

    #[test]
    fn authenticated_hbone_marker_connect_with_peer_is_authorized() {
        let mut headers = HeaderMap::new();
        headers.insert("x-istio-protocol", "hbone".parse().unwrap());
        let peer = peer();
        assert!(is_authenticated_hbone_connect(
            &Method::CONNECT,
            Version::HTTP_2,
            &headers,
            Some(&peer),
        ));
    }

    #[test]
    fn authenticated_hbone_marker_connect_without_peer_is_rejected() {
        // The explicit-marker path does not bypass the authenticated-peer
        // requirement: a marker-bearing CONNECT from an unauthenticated peer
        // is still rejected.
        let mut headers = HeaderMap::new();
        headers.insert("x-ferrum-mesh-protocol", "hbone".parse().unwrap());
        assert!(!is_authenticated_hbone_connect(
            &Method::CONNECT,
            Version::HTTP_2,
            &headers,
            None,
        ));
    }

    #[test]
    fn authenticated_hbone_non_hbone_shape_with_peer_is_rejected() {
        // A verified peer does not turn a non-HBONE-shaped request into a
        // tunnel: GET, H1 CONNECT, and a non-hbone marker all stay rejected.
        let headers = HeaderMap::new();
        let peer = peer();
        assert!(!is_authenticated_hbone_connect(
            &Method::GET,
            Version::HTTP_2,
            &headers,
            Some(&peer),
        ));
        assert!(!is_authenticated_hbone_connect(
            &Method::CONNECT,
            Version::HTTP_11,
            &headers,
            Some(&peer),
        ));
        let mut tcp_headers = HeaderMap::new();
        tcp_headers.insert("x-ferrum-mesh-protocol", "tcp".parse().unwrap());
        assert!(!is_authenticated_hbone_connect(
            &Method::CONNECT,
            Version::HTTP_2,
            &tcp_headers,
            Some(&peer),
        ));
    }

    // ---------------------------------------------------------------
    // is_udp_hbone_connect (F3 §3.3 Stage 4 datagram marker)
    // ---------------------------------------------------------------

    #[test]
    fn is_udp_hbone_connect_requires_explicit_udp_marker() {
        let mut headers = HeaderMap::new();
        headers.insert("x-ferrum-mesh-protocol", "udp".parse().unwrap());
        assert!(is_udp_hbone_connect(
            &Method::CONNECT,
            Version::HTTP_2,
            &headers
        ));
        // Case-insensitive like the hbone marker.
        let mut upper = HeaderMap::new();
        upper.insert("x-ferrum-mesh-protocol", "UDP".parse().unwrap());
        assert!(is_udp_hbone_connect(
            &Method::CONNECT,
            Version::HTTP_2,
            &upper
        ));
        // x-istio-protocol fallback also honored.
        let mut istio = HeaderMap::new();
        istio.insert("x-istio-protocol", "udp".parse().unwrap());
        assert!(is_udp_hbone_connect(
            &Method::CONNECT,
            Version::HTTP_2,
            &istio
        ));
    }

    #[test]
    fn is_udp_hbone_connect_rejects_markerless_and_hbone() {
        // A marker-LESS CONNECT is byte-stream HBONE, NOT udp.
        let empty = HeaderMap::new();
        assert!(!is_udp_hbone_connect(
            &Method::CONNECT,
            Version::HTTP_2,
            &empty
        ));
        // An explicit `hbone` marker is byte-stream, NOT udp.
        let mut hbone = HeaderMap::new();
        hbone.insert("x-ferrum-mesh-protocol", "hbone".parse().unwrap());
        assert!(!is_udp_hbone_connect(
            &Method::CONNECT,
            Version::HTTP_2,
            &hbone
        ));
    }

    #[test]
    fn udp_and_hbone_predicates_are_disjoint() {
        // The two transports must never both fire for one request — the skew
        // posture relies on it (an old dest with no udp branch sees
        // is_hbone_connect==false for a udp CONNECT and 404s).
        let mut udp = HeaderMap::new();
        udp.insert("x-ferrum-mesh-protocol", "udp".parse().unwrap());
        assert!(is_udp_hbone_connect(
            &Method::CONNECT,
            Version::HTTP_2,
            &udp
        ));
        assert!(!is_hbone_connect(&Method::CONNECT, Version::HTTP_2, &udp));

        let markerless = HeaderMap::new();
        assert!(is_hbone_connect(
            &Method::CONNECT,
            Version::HTTP_2,
            &markerless
        ));
        assert!(!is_udp_hbone_connect(
            &Method::CONNECT,
            Version::HTTP_2,
            &markerless
        ));
    }

    #[test]
    fn connect_marker_classification_is_exhaustive_and_fail_closed() {
        // Stage 6 fail-closed contract: every CONNECT marker maps to EXACTLY ONE
        // of {byte-stream HBONE, datagram UDP, neither}, and the two relay
        // predicates are never simultaneously true. An UNKNOWN / future / typo /
        // malformed marker (a not-yet-implemented transport like "quic", a stray
        // "tcp", an empty value, or a non-UTF-8 value) must take NEITHER branch;
        // the dispatcher then rejects the unrecognized CONNECT — the
        // non-WebSocket-CONNECT gate in `handle_proxy_request_inner`
        // (`!is_hbone_connect_any`) returns 405 before routing — so a marker we
        // don't recognize is never relayed onto either transport. This pins the
        // whole marker space in one place; `udp_and_hbone_predicates_are_disjoint`
        // covers only the udp / markerless rows.
        //
        // (marker value, expect is_hbone_connect, expect is_udp_hbone_connect)
        let cases: &[(Option<&str>, bool, bool)] = &[
            (None, true, false),             // markerless → byte-stream HBONE
            (Some("hbone"), true, false),    // explicit hbone → byte-stream
            (Some("HBONE"), true, false),    // case-insensitive
            (Some("udp"), false, true),      // udp → datagram relay
            (Some("UDP"), false, true),      // case-insensitive
            (Some("tcp"), false, false),     // unknown → neither (CONNECT → 405)
            (Some("quic"), false, false),    // future transport → neither (→405)
            (Some("dtls"), false, false),    // DTLS has no own marker (rides "udp")
            (Some("garbage"), false, false), // typo → neither (→405)
            (Some(""), false, false),        // present-but-blank → neither (→405)
        ];

        for &(marker, expect_hbone, expect_udp) in cases {
            let mut headers = HeaderMap::new();
            if let Some(value) = marker {
                headers.insert("x-ferrum-mesh-protocol", value.parse().unwrap());
            }
            let is_hbone = is_hbone_connect(&Method::CONNECT, Version::HTTP_2, &headers);
            let is_udp = is_udp_hbone_connect(&Method::CONNECT, Version::HTTP_2, &headers);
            assert_eq!(
                is_hbone, expect_hbone,
                "is_hbone_connect({marker:?}) mismatch"
            );
            assert_eq!(
                is_udp, expect_udp,
                "is_udp_hbone_connect({marker:?}) mismatch"
            );
            // Dispatch-safety invariant: a request can NEVER match both relay
            // predicates, so it can never take both branches, for any marker.
            assert!(
                !(is_hbone && is_udp),
                "marker {marker:?} matched BOTH relay predicates"
            );
        }

        // A PRESENT but non-UTF-8 / non-visible-ASCII marker is NOT markerless:
        // `to_str()` fails on it, so it must fail closed to the neither branch
        // rather than collapsing to the markerless byte-stream default (codex P2).
        // `Option<&str>` can't carry these bytes, so assert them directly.
        let mut non_utf8 = HeaderMap::new();
        non_utf8.insert(
            "x-ferrum-mesh-protocol",
            http::HeaderValue::from_bytes(&[0xFF, 0xFE]).unwrap(),
        );
        assert!(
            !is_hbone_connect(&Method::CONNECT, Version::HTTP_2, &non_utf8),
            "a non-UTF-8 marker must NOT be treated as markerless byte-stream HBONE"
        );
        assert!(
            !is_udp_hbone_connect(&Method::CONNECT, Version::HTTP_2, &non_utf8),
            "a non-UTF-8 marker must NOT be treated as udp"
        );
    }

    #[test]
    fn is_udp_hbone_connect_rejects_non_connect_and_non_h2() {
        let mut headers = HeaderMap::new();
        headers.insert("x-ferrum-mesh-protocol", "udp".parse().unwrap());
        assert!(!is_udp_hbone_connect(
            &Method::POST,
            Version::HTTP_2,
            &headers
        ));
        assert!(!is_udp_hbone_connect(
            &Method::CONNECT,
            Version::HTTP_11,
            &headers
        ));
    }

    // ---------------------------------------------------------------
    // baggage parsing edge cases
    // ---------------------------------------------------------------

    #[test]
    fn baggage_whitespace_around_key_and_value_is_trimmed() {
        let identity = HboneIdentity::from_baggage_header(
            "  source.principal  =  spiffe://cluster.local/ns/default/sa/client  ",
        );
        assert_eq!(
            identity.source_principal.as_ref().map(ToString::to_string),
            Some("spiffe://cluster.local/ns/default/sa/client".to_string())
        );
    }

    #[test]
    fn baggage_only_whitespace_and_commas_produces_no_identity() {
        let identity = HboneIdentity::from_baggage_header(" , , , ");
        assert!(identity.source_principal.is_none());
        assert!(identity.destination_principal.is_none());
        assert!(identity.baggage.is_empty());
    }

    #[test]
    fn baggage_preserves_non_identity_members_in_map() {
        let identity = HboneIdentity::from_baggage_header(
            "trace-id=abc123,request-id=xyz789,source.principal=spiffe://cluster.local/ns/default/sa/client",
        );
        assert_eq!(
            identity.baggage.get("trace-id").map(String::as_str),
            Some("abc123")
        );
        assert_eq!(
            identity.baggage.get("request-id").map(String::as_str),
            Some("xyz789")
        );
        assert!(identity.source_principal.is_some());
    }

    #[test]
    fn baggage_value_with_equals_sign_preserves_full_value() {
        // Values can contain '=' (only the first '=' splits key from value).
        let baggage = parse_baggage_header("key=val=ue=extra");
        assert_eq!(baggage.get("key").map(String::as_str), Some("val=ue=extra"));
    }
}

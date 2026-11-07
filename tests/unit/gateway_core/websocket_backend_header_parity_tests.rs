//! The H1/H2 and H3 (RFC 9220) WebSocket frontends forward the SAME header
//! set to the backend HTTP/1.1 Upgrade handshake.
//!
//! The H3 filter used to be a hand-maintained copy of the H1/H2 policy that
//! every WebSocket strip fix had to repeat, and it had drifted: H3 alone
//! forwarded `content-length`, `expect`, the internal
//! `x-ferrum-original-content-encoding` / `x-grpc-web-mode` markers, and any
//! field a `Connection` value nominated. These tests drive both collectors with
//! one fixture so a future divergence fails here.

use std::collections::{BTreeSet, HashMap};

use ferrum_edge::_test_support::{
    collect_forwardable_h3_websocket_headers_for_test,
    collect_forwardable_websocket_headers_for_test,
};
use hyper::HeaderMap;
use hyper::header::{HeaderName, HeaderValue};

/// Every class the backend handshake filter decides on: RFC 9110 §7.6.1
/// hop-by-hop names, transport framing, `expect`, gateway-internal markers,
/// RFC 6455 handshake fields, gateway identity assertions, `host`, a
/// `Connection`-nominated field, and ordinary end-to-end fields that must
/// survive. `early-data` and H3 pseudo-headers are H3-only by design and are
/// pinned separately below.
const FIXTURE: &[(&str, &str)] = &[
    ("connection", "x-nominated-by-connection"),
    ("x-nominated-by-connection", "dropped"),
    ("keep-alive", "timeout=5"),
    ("proxy-authorization", "Basic Zm9vOmJhcg=="),
    ("proxy-authenticate", "Basic"),
    ("proxy-connection", "keep-alive"),
    ("te", "trailers"),
    ("trailer", "expires"),
    ("transfer-encoding", "chunked"),
    ("upgrade", "websocket"),
    ("content-length", "5"),
    ("expect", "100-continue"),
    ("x-ferrum-original-content-encoding", "gzip"),
    ("x-grpc-web-mode", "binary"),
    ("host", "backend.example"),
    ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
    ("sec-websocket-version", "13"),
    ("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
    ("sec-websocket-extensions", "permessage-deflate"),
    ("x-consumer-username", "spoofed"),
    ("x-consumer-role", "admin"),
    ("x-authenticated-identity", "spoofed"),
    ("x-geo-country", "ATTACKER"),
    ("sec-websocket-protocol", "chat"),
    ("origin", "https://app.example"),
    ("authorization", "Bearer backend-token"),
    ("cookie", "session=abc"),
    ("x-trace-id", "abc123"),
];

fn raw_header_map(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut raw = HeaderMap::new();
    for (name, value) in pairs {
        raw.append(
            HeaderName::from_bytes(name.as_bytes()).expect("fixture name"),
            HeaderValue::from_str(value).expect("fixture value"),
        );
    }
    raw
}

fn proxy_header_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
        .collect()
}

fn forwarded_names(forwarded: &[(String, String)]) -> BTreeSet<String> {
    forwarded
        .iter()
        .map(|(name, _)| name.to_ascii_lowercase())
        .collect()
}

#[test]
fn h3_and_h1_h2_websocket_frontends_forward_the_same_backend_handshake_headers() {
    let h1_h2 = forwarded_names(&collect_forwardable_websocket_headers_for_test(
        &raw_header_map(FIXTURE),
        &proxy_header_map(FIXTURE),
    ));
    let h3 = forwarded_names(&collect_forwardable_h3_websocket_headers_for_test(
        &proxy_header_map(FIXTURE),
        false,
    ));
    assert_eq!(
        h3, h1_h2,
        "the H3 WebSocket backend handshake must forward exactly what H1/H2 forwards"
    );

    let expected: BTreeSet<String> = [
        "authorization",
        "cookie",
        "origin",
        "sec-websocket-protocol",
        "x-trace-id",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    assert_eq!(
        h1_h2, expected,
        "fixture must exercise both stripped and forwarded names"
    );
}

#[test]
fn h3_websocket_handshake_strips_framing_expect_and_internal_markers() {
    // Regression for the H3-only drift. `content-length` on the backend
    // Upgrade GET would let an origin read relayed WebSocket bytes as a body.
    // Mixed-case keys come from plugin-written maps and must not bypass it.
    let headers = proxy_header_map(&[
        ("Content-Length", "5"),
        ("expect", "100-continue"),
        ("X-Ferrum-Original-Content-Encoding", "gzip"),
        ("x-grpc-web-mode", "binary"),
        ("x-trace-id", "kept"),
    ]);
    let forwarded = forwarded_names(&collect_forwardable_h3_websocket_headers_for_test(
        &headers, false,
    ));
    let expected: BTreeSet<String> = BTreeSet::from(["x-trace-id".to_string()]);
    assert_eq!(forwarded, expected);
}

#[test]
fn h3_websocket_handshake_strips_connection_nominated_fields() {
    let headers = proxy_header_map(&[
        ("Connection", "X-Hop-Field, close"),
        ("x-hop-field", "nominated"),
        ("x-trace-id", "kept"),
    ]);
    let forwarded = forwarded_names(&collect_forwardable_h3_websocket_headers_for_test(
        &headers, false,
    ));
    let expected: BTreeSet<String> = BTreeSet::from(["x-trace-id".to_string()]);
    assert_eq!(forwarded, expected);
}

#[test]
fn h3_only_early_data_and_pseudo_header_handling_is_kept() {
    let headers = proxy_header_map(&[
        ("early-data", "0"),
        (":method", "CONNECT"),
        (":scheme", "https"),
        (":authority", "example.com"),
        (":path", "/ws"),
        (":protocol", "websocket"),
        (":status", "200"),
        ("x-trace-id", "kept"),
    ]);

    let one_rtt = collect_forwardable_h3_websocket_headers_for_test(&headers, false);
    let expected: BTreeSet<String> = BTreeSet::from(["x-trace-id".to_string()]);
    assert_eq!(forwarded_names(&one_rtt), expected);

    let zero_rtt = collect_forwardable_h3_websocket_headers_for_test(&headers, true);
    let early_data: Vec<&str> = zero_rtt
        .iter()
        .filter(|(name, _)| name == "early-data")
        .map(|(_, value)| value.as_str())
        .collect();
    assert_eq!(
        early_data,
        vec!["1"],
        "0-RTT must carry exactly the gateway's Early-Data: 1"
    );
}

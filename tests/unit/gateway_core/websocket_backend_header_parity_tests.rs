//! Backend WebSocket handshake request-header strip, H1/H2 vs H3.
//!
//! Both frontends bridge to the same backend WebSocket transport, so both
//! collectors strip the shared WebSocket handshake set
//! (`headers::WEBSOCKET_HANDSHAKE_STRIP_HEADER_NAMES`) and the
//! consumer-assertion namespace through the shared predicates.
//!
//! Each collector keeps its own frontend-specific arms, pinned below: H3 strips
//! a client `early-data` and re-injects the gateway's own on 0-RTT, and drops
//! H3 pseudo-headers; H1/H2 drops `Connection`-nominated names and forwards
//! `early-data` as received.

use std::collections::HashMap;

use ferrum_edge::_test_support::{
    collect_forwardable_h3_websocket_headers_for_test,
    collect_forwardable_websocket_headers_for_test,
};
use ferrum_edge::proxy::headers::{
    BACKEND_REQUEST_STRIP_HEADER_NAMES, WEBSOCKET_HANDSHAKE_STRIP_HEADER_NAMES,
    is_websocket_backend_request_strip_header,
};
use hyper::HeaderMap;
use hyper::header::{HeaderName, HeaderValue};

/// Consumer-assertion namespace samples (prefix, `_` spelling, identity).
const CONSUMER_ASSERTION_SAMPLES: &[&str] = &[
    "x-consumer-username",
    "x-consumer-role",
    "x_consumer_groups",
    "x-authenticated-identity",
];

/// Every name the shared WebSocket backend strip covers.
fn shared_strip_names() -> Vec<&'static str> {
    BACKEND_REQUEST_STRIP_HEADER_NAMES
        .iter()
        .chain(WEBSOCKET_HANDSHAKE_STRIP_HEADER_NAMES)
        .chain(CONSUMER_ASSERTION_SAMPLES)
        .copied()
        .collect()
}

/// Mixed-case spelling, so the H3 collector's own lowercasing is exercised.
fn mixed_case(name: &str) -> String {
    name.split('-')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}

fn h1_h2(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut raw = HeaderMap::new();
    let mut proxy = HashMap::new();
    for (name, value) in pairs {
        raw.append(
            HeaderName::from_bytes(name.as_bytes()).expect("valid header name"),
            HeaderValue::from_str(value).expect("valid header value"),
        );
        proxy.insert((*name).to_string(), (*value).to_string());
    }
    collect_forwardable_websocket_headers_for_test(&raw, &proxy)
}

fn h3(pairs: &[(&str, &str)], is_early_data: bool) -> Vec<(String, String)> {
    let headers: HashMap<String, String> = pairs
        .iter()
        .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
        .collect();
    collect_forwardable_h3_websocket_headers_for_test(&headers, is_early_data)
}

fn forwarded(out: &[(String, String)], name: &str) -> Vec<String> {
    out.iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
        .collect()
}

#[test]
fn the_shared_predicate_covers_the_whole_inventory() {
    for name in shared_strip_names() {
        assert!(
            is_websocket_backend_request_strip_header(name),
            "`{name}` must be stripped from a backend WebSocket handshake"
        );
    }
    for name in [
        "sec-websocket-protocol",
        "authorization",
        "cookie",
        "x-trace-id",
    ] {
        assert!(
            !is_websocket_backend_request_strip_header(name),
            "`{name}` must still reach the backend handshake"
        );
    }
}

/// Assert neither frontend forwards any of `names` (H3 also with mixed-case
/// keys), while an ordinary header still passes.
fn assert_both_frontends_strip(names: &[&str]) {
    for &name in names {
        let h1_h2_out = h1_h2(&[(name, "client-value"), ("x-keep", "1")]);
        assert!(
            forwarded(&h1_h2_out, name).is_empty(),
            "H1/H2 forwarded `{name}`: {h1_h2_out:?}"
        );
        assert_eq!(forwarded(&h1_h2_out, "x-keep"), ["1"]);

        for key in [name.to_string(), mixed_case(name)] {
            let h3_out = h3(&[(key.as_str(), "client-value"), ("x-keep", "1")], false);
            assert!(
                forwarded(&h3_out, name).is_empty(),
                "H3 forwarded `{key}`: {h3_out:?}"
            );
            assert_eq!(forwarded(&h3_out, "x-keep"), ["1"]);
        }
    }
}

/// Shared invariant: both frontends strip the WebSocket handshake set and the
/// consumer-assertion namespace through the shared predicates.
#[test]
fn both_frontends_strip_the_websocket_handshake_set_and_consumer_namespace() {
    let names: Vec<&str> = WEBSOCKET_HANDSHAKE_STRIP_HEADER_NAMES
        .iter()
        .chain(CONSUMER_ASSERTION_SAMPLES)
        .copied()
        .collect();
    assert_both_frontends_strip(&names);
}

/// INTENTIONAL (H3 only): H3 is the only frontend that terminates 0-RTT
/// itself, so it strips any client `early-data` and injects exactly one
/// `early-data: 1` when the stream arrived in early data (RFC 8470 §5.2).
#[test]
fn h3_replaces_client_early_data_with_the_gateway_value() {
    let out = h3(&[("Early-Data", "0"), ("x-keep", "1")], false);
    assert!(forwarded(&out, "early-data").is_empty(), "{out:?}");

    let out = h3(&[("early-data", "0"), ("x-keep", "1")], true);
    assert_eq!(forwarded(&out, "early-data"), ["1"], "{out:?}");
}

/// INTENTIONAL (H1/H2): the H1/H2 frontends never accept early data, so an
/// `Early-Data` header can only come from a trusted intermediary (RFC 8470 §5.1)
/// and is forwarded as received.
#[test]
fn h1_h2_forwards_early_data_as_received() {
    let out = h1_h2(&[("early-data", "1")]);
    assert_eq!(forwarded(&out, "early-data"), ["1"], "{out:?}");
}

/// INTENTIONAL (H3 only): H3 pseudo-headers never become HTTP/1.1 fields.
#[test]
fn h3_drops_pseudo_headers() {
    let out = h3(
        &[
            (":method", "CONNECT"),
            (":scheme", "https"),
            (":authority", "example.com"),
            (":path", "/ws"),
            (":protocol", "websocket"),
            (":status", "200"),
            ("x-keep", "1"),
        ],
        false,
    );
    assert_eq!(out, vec![("x-keep".to_string(), "1".to_string())]);
}

/// INTENTIONAL (H1/H2 only): a name the client nominated in `Connection` is
/// hop-by-hop and is dropped. H3 has no `Connection` semantics (a `Connection`
/// field is malformed on H3, RFC 9114 §4.2) and ingress confinement resolves
/// nominations before the collector runs, so the H3 collector does not parse it.
#[test]
fn only_h1_h2_parses_connection_nominations() {
    let pairs = [("connection", "x-hop"), ("x-hop", "1"), ("x-keep", "1")];
    let out = h1_h2(&pairs);
    assert!(forwarded(&out, "x-hop").is_empty(), "{out:?}");
    assert_eq!(forwarded(&out, "x-keep"), ["1"]);

    let out = h3(&pairs, false);
    assert_eq!(forwarded(&out, "x-hop"), ["1"], "{out:?}");
    assert!(forwarded(&out, "connection").is_empty(), "{out:?}");
}

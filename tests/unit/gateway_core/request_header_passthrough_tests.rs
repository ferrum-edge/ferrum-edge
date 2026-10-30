//! Request-header passthrough (issue #6671).
//!
//! A routed request no plugin can observe dispatches from its wire header block
//! instead of the materialized `RequestContext::headers` map. These tests pin
//! the equivalence that makes that safe: for every eligible block the
//! passthrough view reads, rebuilds, rematerializes and forwards exactly what
//! the eager path would, and every block the eager path would reshape
//! (repeated names, non-UTF-8 values, reserved gateway assertions) stays on the
//! materialized path.

use ferrum_edge::_test_support::{
    RequestHeaderPassthroughProbe, request_header_passthrough_probe_for_test,
};
use http::{HeaderMap, HeaderName, HeaderValue};

const PROBE_NAMES: &[&str] = &[
    "host",
    "Host",
    "User-Agent",
    "x-ferrum-hops",
    "X-Ferrum-Hops",
    "absent-header",
    "not a header name",
    "",
];

fn block(fields: &[(&str, &[u8])]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in fields {
        map.append(
            HeaderName::from_bytes(name.as_bytes()).expect("test header name"),
            HeaderValue::from_bytes(value).expect("test header value"),
        );
    }
    map
}

fn probe(
    raw: HeaderMap,
    authority: Option<&str>,
    proxy_hops: Option<u8>,
) -> Option<RequestHeaderPassthroughProbe> {
    request_header_passthrough_probe_for_test(raw, authority, proxy_hops, PROBE_NAMES)
}

fn assert_equivalent(probe: &RequestHeaderPassthroughProbe) {
    assert_eq!(probe.view_map, probe.eager, "view rebuilds the eager map");
    assert_eq!(
        probe.rematerialized, probe.eager,
        "leaving the lane yields the eager map"
    );
    assert!(
        probe.lookups_match,
        "every lookup agrees with the eager map"
    );
    assert!(probe.len_matches, "length and entry count agree");
    assert!(
        probe.connection_listed_matches,
        "Connection-listed names agree"
    );
    assert_eq!(
        probe.view_outbound, probe.eager_outbound,
        "outbound headers are byte-identical"
    );
}

#[test]
fn http1_block_is_equivalent_and_keeps_the_client_host() {
    let probe = probe(
        block(&[
            ("host", b"api.example.com"),
            ("user-agent", b"curl/8.9"),
            ("accept", b"application/json, text/plain;q=0.5"),
            ("cookie", b"a=1; b=2"),
            ("content-length", b"42"),
            ("x-request-id", b"req-1"),
            ("x-ferrum-hops", b"1"),
        ]),
        Some("ignored.example.com"),
        Some(1),
    )
    .expect("plain H1 block is eligible");
    assert_equivalent(&probe);
    assert_eq!(
        probe.eager.get("host").map(String::as_str),
        Some("api.example.com")
    );
}

#[test]
fn http2_block_backfills_host_from_authority() {
    let probe = probe(
        block(&[
            ("content-type", b"application/json"),
            ("x-ferrum-hops", b"1"),
        ]),
        Some("api.example.com:8443"),
        Some(1),
    )
    .expect("H2 block without Host is eligible");
    assert_equivalent(&probe);
    assert_eq!(
        probe.view_map.get("host").map(String::as_str),
        Some("api.example.com:8443")
    );
}

#[test]
fn reasserted_hop_count_replaces_or_appends_the_wire_value() {
    let replaced = probe(block(&[("x-ferrum-hops", b"7")]), None, Some(2))
        .expect("single hop field is eligible");
    assert_equivalent(&replaced);
    assert_eq!(
        replaced.view_map.get("x-ferrum-hops").map(String::as_str),
        Some("2")
    );

    let appended = probe(block(&[("accept", b"*/*")]), None, Some(3))
        .expect("block without a hop field is eligible");
    assert_equivalent(&appended);
    assert_eq!(
        appended.view_map.get("x-ferrum-hops").map(String::as_str),
        Some("3")
    );
}

#[test]
fn disabled_hop_limit_forwards_the_client_value_unchanged() {
    let probe = probe(block(&[("x-ferrum-hops", b"9")]), None, None)
        .expect("hop field with the limit disabled is eligible");
    assert_equivalent(&probe);
    assert_eq!(
        probe.view_map.get("x-ferrum-hops").map(String::as_str),
        Some("9")
    );
}

#[test]
fn utf8_obs_text_and_tab_values_forward_byte_exact() {
    let probe = probe(
        block(&[
            ("x-name", "caf\u{e9}".as_bytes()),
            ("x-tabbed", b"a\tb"),
            ("x-empty", b""),
        ]),
        None,
        None,
    )
    .expect("UTF-8 obs-text is eligible");
    assert_equivalent(&probe);
}

#[test]
fn empty_block_is_equivalent() {
    let probe = probe(HeaderMap::new(), None, None).expect("empty block is eligible");
    assert_equivalent(&probe);
    assert!(probe.eager.is_empty());
}

#[test]
fn blocks_the_eager_path_reshapes_stay_materialized() {
    let ineligible = [
        (
            "repeated name folds into one value",
            block(&[("accept", b"text/html"), ("accept", b"*/*")]),
        ),
        (
            "repeated cookie folds with a semicolon",
            block(&[("cookie", b"a=1"), ("cookie", b"b=2")]),
        ),
        (
            "non-UTF-8 value is dropped",
            block(&[("x-binary", &[0x66, 0xff, 0x6f])]),
        ),
        (
            "consumer assertion is scrubbed",
            block(&[("x-consumer-username", b"mallory")]),
        ),
        (
            "underscore consumer assertion is scrubbed",
            block(&[("x_consumer_id", b"1")]),
        ),
        (
            "path-parameter assertion is scrubbed",
            block(&[("x-path-param-id", b"7")]),
        ),
        (
            "backend-equivalent hop-count spelling is scrubbed",
            block(&[("x_ferrum_hops", b"0")]),
        ),
        (
            "case-folded hop-count spelling next to the canonical one",
            block(&[("x-ferrum-hops", b"1"), ("x_Ferrum_Hops", b"0")]),
        ),
    ];
    for (case, raw) in ineligible {
        assert!(
            probe(raw, Some("api.example.com"), Some(1)).is_none(),
            "{case}"
        );
    }
}

#[test]
fn connection_listed_names_match_the_eager_parse() {
    let probe = probe(
        block(&[
            ("connection", b"keep-alive, X-Debug, , bad header"),
            ("x-debug", b"1"),
            ("keep-alive", b"timeout=5"),
        ]),
        None,
        Some(1),
    )
    .expect("single Connection field is eligible");
    assert_equivalent(&probe);
}

/// Strip `//` comment lines and all whitespace so the check survives rustfmt.
fn compact(text: &str) -> String {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace())
        .collect()
}

/// The handler admits a request to the lane only behind every exclusion the
/// view does not model, and only once the plugin view is known.
#[test]
fn handler_gate_keeps_every_lane_exclusion() {
    let source = compact(include_str!("../../../src/proxy/mod.rs"));
    let arm = source
        .find("ifrm.path_params.is_empty(){request_headers_deferred=true;}else{")
        .expect("route match defers only routes without path-parameter captures");
    let view = source
        .find("letplugin_cache_view=ifgrpc_web_request{")
        .expect("plugin view resolution");
    let gate_start = source[view..]
        .find("ifrequest_headers_deferred{")
        .map(|at| view + at)
        .expect("passthrough decision follows the plugin view");
    assert!(arm < view, "deferral is recorded at route match");
    let gate_end = source[gate_start..]
        .find("materialize_routed_request_headers(&mutctx,req.uri().authority());")
        .map(|at| gate_start + at)
        .expect("a declined request materializes at the decision point");
    let gate = &source[gate_start..gate_end];
    for needle in [
        "matches!(request_protocol,ProxyProtocol::Http)",
        "matches!(flavor,HttpFlavor::Plain)",
        "!grpc_web_request",
        "hyper::Version::HTTP_10|hyper::Version::HTTP_11|hyper::Version::HTTP_2",
        "ctx.mesh_direction.is_none()",
        "!is_hbone_connect_any",
        "method!=\"OPTIONS\"",
        "state.mesh_egress_strip_baggage_keys.is_empty()",
        "plugin_cache_view.plugins().is_empty()",
        "ctx.try_begin_request_header_passthrough(",
    ] {
        assert!(gate.contains(needle), "passthrough gate lost `{needle}`");
    }
    let first_reject = source[gate_start..]
        .find("ROUTE_PROTOCOL_NOT_PERMITTED_BODY")
        .map(|at| gate_start + at)
        .expect("route-level protocol reject");
    assert!(
        gate_end < first_reject,
        "the decision precedes every route-level reject that can log headers"
    );
}

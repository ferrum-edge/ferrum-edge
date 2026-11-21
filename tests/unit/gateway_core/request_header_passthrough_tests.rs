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
    RequestHeaderPassthroughProbe, request_header_passthrough_overlay_probe_for_test,
    request_header_passthrough_probe_for_test, response_header_passthrough_parity_for_test,
};
use ferrum_edge::config::types::{GatewayConfig, PluginScope, ProxyProtocol};
use ferrum_edge::plugins::create_plugin;
use ferrum_edge::{PluginCache, PluginCapabilities};
use http::{HeaderMap, HeaderName, HeaderValue};
use serde_json::json;

use crate::unit::plugins::plugin_utils::{make_plugin_config_with_json, make_proxy};

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
            "GeoIP assertion is scrubbed",
            block(&[("x-geo-country", b"US")]),
        ),
        (
            "underscore GeoIP assertion is scrubbed",
            block(&[("x_geo_country", b"US")]),
        ),
        (
            "authenticated-identity assertion is scrubbed",
            block(&[("x-authenticated-identity", b"spiffe://evil")]),
        ),
        (
            "underscore authenticated-identity assertion is scrubbed",
            block(&[("x_authenticated_identity", b"spiffe://evil")]),
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

#[test]
fn authority_that_cannot_be_a_header_value_stays_materialized() {
    assert!(
        probe(block(&[("accept", b"*/*")]), Some("bad\u{7f}host"), Some(1)).is_none(),
        "a Host backfill the outbound builders would drop must not enter the lane"
    );
}

#[test]
fn overlay_strips_credentials_and_injects_gateway_assertions_identically() {
    let probe = request_header_passthrough_overlay_probe_for_test(
        block(&[
            ("host", b"api.example.com"),
            ("x-api-key", b"super-secret-key"),
            ("content-type", b"application/json"),
            ("x-ferrum-hops", b"1"),
        ]),
        None,
        Some(2),
        &["x-api-key"],
        Some("alice"),
        Some("cust-42"),
        Some("alice@example.com"),
        Some("US"),
        PROBE_NAMES,
    )
    .expect("header-only key_auth overlay with valid assertions is eligible");
    assert_equivalent(&probe);
    assert!(!probe.view_map.contains_key("x-api-key"));
    assert_eq!(
        probe
            .view_map
            .get("x-consumer-username")
            .map(String::as_str),
        Some("alice")
    );
    assert_eq!(
        probe
            .view_map
            .get("x-consumer-custom-id")
            .map(String::as_str),
        Some("cust-42")
    );
    assert_eq!(
        probe
            .view_map
            .get("x-authenticated-identity")
            .map(String::as_str),
        Some("alice@example.com")
    );
    assert_eq!(
        probe.view_map.get("x-geo-country").map(String::as_str),
        Some("US")
    );
}

#[test]
fn overlay_falls_back_on_unrepresentable_assertion_values() {
    assert!(
        request_header_passthrough_overlay_probe_for_test(
            block(&[("host", b"api.example.com"), ("x-api-key", b"k")]),
            None,
            Some(1),
            &["x-api-key"],
            Some("bad\u{7f}user"),
            None,
            None,
            None,
            PROBE_NAMES,
        )
        .is_none(),
        "control characters in gateway assertions must decline the overlay and materialize"
    );
}

#[test]
fn overlay_stripping_host_hides_authority_backfill() {
    let probe = request_header_passthrough_overlay_probe_for_test(
        block(&[("accept", b"*/*")]),
        Some("api.example.com"),
        Some(1),
        &["host"],
        Some("alice"),
        None,
        None,
        None,
        PROBE_NAMES,
    )
    .expect("stripping host keeps view and materialized maps consistent");
    assert_equivalent(&probe);
    assert!(!probe.view_map.contains_key("host"));
}

#[test]
fn key_auth_passthrough_eligibility_rules() {
    let header_key_auth = create_plugin("key_auth", &json!({ "key_location": "header:X-API-Key" }))
        .expect("header key_auth builds")
        .expect("key_auth is registered");
    assert!(header_key_auth.supports_request_header_passthrough());

    let query_key_auth = create_plugin("key_auth", &json!({ "key_location": "query:api_key" }))
        .expect("query key_auth builds")
        .expect("key_auth is registered");
    assert!(!query_key_auth.supports_request_header_passthrough());

    let host_key_auth = create_plugin("key_auth", &json!({ "key_location": "header:Host" }))
        .expect("host key_auth builds")
        .expect("key_auth is registered");
    assert!(
        !host_key_auth.supports_request_header_passthrough(),
        "header:Host needs materialized H2 Host backfill before lookup"
    );

    let anon_key_auth = create_plugin(
        "key_auth",
        &json!({
            "key_location": "header:X-API-Key",
            "anonymous_consumer": "anon"
        }),
    )
    .expect("anonymous key_auth builds")
    .expect("key_auth is registered");
    assert!(anon_key_auth.supports_request_header_passthrough());

    let proxy = make_proxy("bench-key-auth", "/api", vec!["key-auth-1"]);
    let plugin_cfg = make_plugin_config_with_json(
        "key-auth-1",
        "key_auth",
        json!({ "key_location": "header:X-API-Key", "hide_credentials": true }),
        PluginScope::Proxy,
        Some("bench-key-auth"),
    );
    let mut cfg = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![proxy],
        plugin_configs: vec![plugin_cfg],
        ..Default::default()
    };
    let cache = PluginCache::new(&cfg).expect("plugin cache builds");
    let view = cache.request_view("ferrum", "bench-key-auth", ProxyProtocol::Http);
    assert!(
        view.capabilities()
            .has(PluginCapabilities::SUPPORTS_REQUEST_HEADER_PASSTHROUGH),
        "header-only key_auth chain must advertise SUPPORTS_REQUEST_HEADER_PASSTHROUGH"
    );

    // Adding a trigger disables passthrough so trigger evaluation sees materialized headers.
    cfg.plugin_configs[0].trigger = Some(
        serde_json::from_value(json!({
            "when": { "match": { "method": ["POST"] } }
        }))
        .expect("valid trigger"),
    );
    let triggered_cache = PluginCache::new(&cfg).expect("triggered plugin cache builds");
    let triggered_view =
        triggered_cache.request_view("ferrum", "bench-key-auth", ProxyProtocol::Http);
    assert!(
        !triggered_view
            .capabilities()
            .has(PluginCapabilities::SUPPORTS_REQUEST_HEADER_PASSTHROUGH),
        "a trigger on key_auth must disable request-header passthrough"
    );
}

#[test]
fn deferred_response_header_lane_matches_materialized_wire_headers() {
    let raw = block(&[
        ("content-type", b"application/json"),
        ("content-length", b"1024"),
        ("connection", b"keep-alive"),
        ("keep-alive", b"timeout=5"),
        ("via", b"1.1 envoy"),
        ("alt-svc", b"h3=\":8443\""),
        ("set-cookie", b"a=1; Path=/"),
        ("set-cookie", b"b=2; Path=/"),
        ("x-gateway-error", b"spoofed"),
        ("x-gateway-upstream-status", b"spoofed"),
        ("x-ferrum-diagnostic-ref", b"spoofed"),
        ("x-upstream-id", b"backend-1"),
    ]);
    let (materialized, deferred) = response_header_passthrough_parity_for_test(
        raw,
        200,
        Some("1.1 ferrum"),
        Some("h3=\":443\""),
    )
    .expect("standard H1 response with multi Set-Cookie and Connection: keep-alive is eligible");
    assert_eq!(
        deferred, materialized,
        "deferred HeaderMap lane must produce byte-identical wire headers (including Via/Alt-Svc append)"
    );
    let via_count = deferred.iter().filter(|(name, _)| name == "via").count();
    assert_eq!(
        via_count, 2,
        "upstream Via and gateway Via must both be present"
    );
    let alt_svc_count = deferred
        .iter()
        .filter(|(name, _)| name == "alt-svc")
        .count();
    assert_eq!(
        alt_svc_count, 2,
        "upstream Alt-Svc and gateway Alt-Svc must both be present"
    );

    // Connection nominating a non-standard header (such as content-length or x-custom)
    // must decline passthrough so collection strips it identically.
    assert!(
        response_header_passthrough_parity_for_test(
            block(&[
                ("connection", b"keep-alive, content-length"),
                ("content-length", b"42"),
            ]),
            200,
            None,
            None,
        )
        .is_none()
    );
    assert!(
        response_header_passthrough_parity_for_test(
            block(&[("x-dup", b"one"), ("x-dup", b"two")]),
            200,
            None,
            None,
        )
        .is_none()
    );
}

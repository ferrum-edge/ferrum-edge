//! A client's RFC 9110 §7.6.1 `Connection` nominations are resolved against
//! the client's own fields at ingress
//! (`proxy::headers::confine_connection_nominated_request_headers`).
//!
//! The backend builders strip every name the request's `Connection` field
//! lists from the FINAL outbound map. Without the ingress pass a client could
//! nominate a header the gateway asserts after admission — consumer identity,
//! a verified claim destination — and have the gateway delete its own
//! assertion before dispatch. These tests drive the helper directly and then
//! the same ingress → plugin-assertion → backend-strip sequence the dispatch
//! paths compose.

use std::collections::HashMap;

use ferrum_edge::plugins::RequestContext;
use ferrum_edge::proxy::headers::{
    confine_connection_nominated_request_headers, field_names_equivalent_for_backends,
    is_gateway_assertion_header, is_path_param_assertion_header,
    parse_connection_listed_from_str_map, strip_backend_request_headers,
};
use ferrum_edge::proxy::refresh_backend_gateway_assertion_headers;
use http::{HeaderMap, HeaderName, HeaderValue, header::CONNECTION};

fn header_map(fields: &[(&str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in fields {
        headers.append(
            HeaderName::from_bytes(name.as_bytes()).expect("valid test header name"),
            HeaderValue::from_str(value).expect("valid test header value"),
        );
    }
    headers
}

fn connection_values(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(CONNECTION)
        .iter()
        .map(|value| value.to_str().expect("ASCII Connection").to_string())
        .collect()
}

#[test]
fn nominated_client_fields_are_removed_and_connection_keeps_only_options() {
    let mut headers = header_map(&[
        ("host", "api.example.test"),
        (
            "connection",
            "keep-alive, x-consumer-username, X-Tenant-Id, x-client-secret",
        ),
        ("keep-alive", "timeout=5"),
        ("x-tenant-id", "client-chosen"),
        ("x-client-secret", "s3cret"),
        ("x-request-id", "req-1"),
    ]);

    confine_connection_nominated_request_headers(&mut headers, None);

    assert!(!headers.contains_key("x-tenant-id"));
    assert!(!headers.contains_key("x-client-secret"));
    assert_eq!(connection_values(&headers), vec!["keep-alive".to_string()]);
    assert_eq!(headers.get("keep-alive").unwrap(), "timeout=5");
    assert_eq!(headers.get("host").unwrap(), "api.example.test");
    assert_eq!(headers.get("x-request-id").unwrap(), "req-1");
}

#[test]
fn connection_options_and_hop_by_hop_names_are_left_untouched() {
    for value in [
        "keep-alive",
        "close",
        "Upgrade",
        "keep-alive, Upgrade",
        "TE, close",
        "Proxy-Connection",
    ] {
        let mut headers = header_map(&[
            ("connection", value),
            ("upgrade", "websocket"),
            ("te", "trailers"),
        ]);
        let before = headers.clone();

        confine_connection_nominated_request_headers(&mut headers, None);

        assert_eq!(
            headers, before,
            "`Connection: {value}` must not be rewritten"
        );
    }
}

#[test]
fn absent_connection_is_a_no_op() {
    let mut headers = header_map(&[("x-tenant-id", "t"), ("host", "h")]);
    let before = headers.clone();

    confine_connection_nominated_request_headers(&mut headers, None);

    assert_eq!(headers, before);
}

#[test]
fn routing_and_framing_fields_survive_their_own_nomination() {
    let mut headers = header_map(&[
        ("host", "api.example.test"),
        ("content-length", "4"),
        ("expect", "100-continue"),
        ("connection", "Host, content-length, expect"),
    ]);

    confine_connection_nominated_request_headers(&mut headers, None);

    assert_eq!(headers.get("host").unwrap(), "api.example.test");
    assert_eq!(headers.get("content-length").unwrap(), "4");
    assert_eq!(headers.get("expect").unwrap(), "100-continue");
    assert!(
        !headers.contains_key(CONNECTION),
        "no retained option remains, so `Connection` is dropped"
    );
}

/// Trusted-proxy client-IP and scheme resolution reads the forwarding fields
/// after ingress. A nominated one that ingress removed would make the request
/// resolve to the upstream proxy's socket address instead of the client.
#[test]
fn forwarding_fields_survive_their_own_nomination() {
    let mut headers = header_map(&[
        (
            "connection",
            "X-Forwarded-For, x-real-ip, Forwarded, x-forwarded-proto, \
             x-forwarded-host, x-forwarded-port, cf-connecting-ip, x-other",
        ),
        ("x-forwarded-for", "203.0.113.7"),
        ("x-real-ip", "203.0.113.7"),
        ("forwarded", "for=203.0.113.7"),
        ("x-forwarded-proto", "https"),
        ("x-forwarded-host", "api.example.test"),
        ("x-forwarded-port", "443"),
        ("cf-connecting-ip", "203.0.113.7"),
        ("x-other", "removed"),
    ]);

    confine_connection_nominated_request_headers(&mut headers, Some("cf-connecting-ip"));

    for name in [
        "x-forwarded-for",
        "x-real-ip",
        "forwarded",
        "x-forwarded-proto",
        "x-forwarded-host",
        "x-forwarded-port",
        "cf-connecting-ip",
    ] {
        assert!(
            headers.contains_key(name),
            "`{name}` must survive its nomination"
        );
    }
    assert!(!headers.contains_key("x-other"));
    assert!(
        !headers.contains_key(CONNECTION),
        "the rewritten `Connection` no longer nominates the forwarding fields"
    );
}

#[test]
fn configured_real_ip_header_is_protected_only_when_configured() {
    let mut headers = header_map(&[
        ("connection", "cf-connecting-ip"),
        ("cf-connecting-ip", "203.0.113.7"),
    ]);

    confine_connection_nominated_request_headers(&mut headers, None);

    assert!(
        !headers.contains_key("cf-connecting-ip"),
        "an unconfigured custom header is an ordinary client field"
    );
}

/// `Connection: authorization` removes the client's credential before
/// authentication runs, so the route fails closed with `401` rather than
/// authenticating a request whose credential the backend would never see.
#[test]
fn nominated_authorization_is_removed_before_authentication() {
    let mut headers = header_map(&[
        ("connection", "keep-alive, Authorization"),
        ("authorization", "Bearer token"),
    ]);

    confine_connection_nominated_request_headers(&mut headers, None);

    assert!(!headers.contains_key("authorization"));
    assert_eq!(connection_values(&headers), vec!["keep-alive".to_string()]);
}

#[test]
fn repeated_connection_fields_and_unparseable_tokens_are_resolved_together() {
    let mut headers = header_map(&[
        ("connection", "x-first"),
        ("connection", "close, bad token, x-second"),
        ("x-first", "1"),
        ("x-second", "2"),
    ]);

    confine_connection_nominated_request_headers(&mut headers, None);

    assert!(!headers.contains_key("x-first"));
    assert!(!headers.contains_key("x-second"));
    assert_eq!(connection_values(&headers), vec!["close".to_string()]);
}

#[test]
fn non_ascii_connection_value_is_dropped() {
    let mut headers = HeaderMap::new();
    headers.insert(
        CONNECTION,
        HeaderValue::from_bytes(b"x-consumer-username, \xff").expect("obs-text value"),
    );
    headers.insert("x-request-id", HeaderValue::from_static("req-1"));

    confine_connection_nominated_request_headers(&mut headers, None);

    assert!(!headers.contains_key(CONNECTION));
    assert_eq!(headers.get("x-request-id").unwrap(), "req-1");
}

/// The dispatch sequence: ingress confinement, materialization, the gateway's
/// identity assertion and a plugin-installed claim destination, then the
/// backend boundary's Connection-listed + hop-by-hop strip.
#[test]
fn gateway_assertions_survive_the_backend_hop_by_hop_strip() {
    let mut raw = header_map(&[
        ("host", "api.example.test"),
        ("connection", "close, x-authenticated-identity, x-tenant-id"),
        ("x-tenant-id", "tenant-b"),
        ("authorization", "Bearer tenant-a-token"),
    ]);
    confine_connection_nominated_request_headers(&mut raw, None);

    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    ctx.authenticated_identity = Some("alice".to_string());
    ctx.set_raw_headers(raw);
    ctx.materialize_headers();
    assert!(
        !ctx.headers.contains_key("x-tenant-id"),
        "the client's nominated field never reaches the plugin view"
    );

    let mut outbound: HashMap<String, String> = ctx.headers.clone();
    // A claim-header plugin installs the verified destination...
    outbound.insert("x-tenant-id".to_string(), "tenant-a".to_string());
    // ...and the gateway asserts the authenticated principal.
    refresh_backend_gateway_assertion_headers(&ctx, &mut outbound);

    let listed = parse_connection_listed_from_str_map(&outbound);
    for assertion in ["x-authenticated-identity", "x-tenant-id"] {
        assert!(
            !listed.iter().any(|name| name == assertion),
            "the residual Connection list must not name `{assertion}`: {listed:?}"
        );
    }

    let mut wire = HeaderMap::new();
    for (name, value) in &outbound {
        wire.insert(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    strip_backend_request_headers(&mut wire);

    assert_eq!(wire.get("x-authenticated-identity").unwrap(), "alice");
    assert_eq!(wire.get("x-tenant-id").unwrap(), "tenant-a");
    assert!(!wire.contains_key(CONNECTION));
}

#[test]
fn backend_field_name_equivalence_folds_case_and_underscore() {
    let equivalent = field_names_equivalent_for_backends;
    assert!(equivalent("x-tenant-id", "X_Tenant_Id"));
    assert!(equivalent("X-TENANT_ID", "x-tenant-id"));
    assert!(!equivalent("x-tenant-id", "x-tenant-idx"));
    assert!(!equivalent("x-tenant-id", "x-tenant.id"));
}

#[test]
fn geo_assertion_matches_underscore_spellings() {
    assert!(is_gateway_assertion_header("x-geo-country"));
    assert!(is_gateway_assertion_header("X_Geo_Country"));
    assert!(is_gateway_assertion_header("x_geo-country"));
    assert!(!is_gateway_assertion_header("x-geo-countryx"));
}

#[test]
fn path_param_assertion_matches_underscore_spellings() {
    assert!(is_path_param_assertion_header("x-path-param-id"));
    assert!(is_path_param_assertion_header("X_Path_Param_Id"));
    assert!(is_path_param_assertion_header("x_path-param-account"));
    assert!(!is_path_param_assertion_header("x-path-paramid"));
    assert!(!is_path_param_assertion_header("x-path"));
}

/// CGI-style backends fold `X_Path_Param_Id` onto the gateway's
/// `x-path-param-id`, so ingress drops every client spelling of the namespace.
#[test]
fn client_path_param_spellings_never_reach_the_plugin_view() {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    ctx.set_raw_headers(header_map(&[
        ("x_path_param_id", "client-chosen"),
        ("X-Path_Param-Account", "client-chosen"),
        ("x-request-id", "req-1"),
    ]));
    ctx.materialize_headers();

    assert!(!ctx.headers.contains_key("x_path_param_id"));
    assert!(!ctx.headers.contains_key("x-path_param-account"));
    assert_eq!(ctx.headers.get("x-request-id").unwrap(), "req-1");
}

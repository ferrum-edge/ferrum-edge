//! The `x-consumer-*` request-header namespace is gateway-owned consumer
//! assertion metadata (ferrum-alloy#25 item 4).
//!
//! A client-supplied `X-Consumer-Role` or `X-Consumer-Groups` is as much a
//! forged identity assertion to a backend as a client-supplied
//! `X-Consumer-Username`. These tests drive the three shared boundaries every
//! protocol path composes over, with the client header shapes the functional
//! suites send on the wire:
//!
//! - ingress materialization (`RequestContext::materialize_headers`), which
//!   builds the plugin-facing map every H1/H2/H3, cross-protocol, and HBONE
//!   dispatch reads;
//! - the raw merge base (`merge_proxy_headers_and_strip_for_grpc`), which native
//!   gRPC, the direct-H2 pool, and secured mesh replay layer the plugin view
//!   over;
//! - the post-plugin refresh (`refresh_backend_gateway_assertion_headers`),
//!   which scrubs plugin-authored values and restores only the authenticated
//!   principal.

use std::collections::HashMap;

use ferrum_edge::plugins::RequestContext;
use ferrum_edge::proxy::headers::{
    is_consumer_assertion_header, is_gateway_assertion_header,
    merge_proxy_headers_and_strip_for_grpc,
};
use ferrum_edge::proxy::refresh_backend_gateway_assertion_headers;
use http::HeaderMap;

fn ctx() -> RequestContext {
    RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into())
}

fn authenticated_ctx(identity: &str) -> RequestContext {
    let mut ctx = ctx();
    ctx.authenticated_identity = Some(identity.to_string());
    ctx
}

fn consumer_namespace_keys(headers: &HashMap<String, String>) -> Vec<String> {
    headers
        .keys()
        .filter(|name| name.to_ascii_lowercase().starts_with("x-consumer-"))
        .cloned()
        .collect()
}

#[test]
fn gateway_assertion_predicate_covers_whole_consumer_namespace_case_insensitively() {
    for name in [
        "x-consumer-username",
        "x-consumer-custom-id",
        "x-consumer-role",
        "x-consumer-groups",
        "X-Consumer-Role",
        "X-CONSUMER-GROUPS",
        "x-consumer-",
    ] {
        assert!(is_consumer_assertion_header(name), "{name}");
        assert!(is_gateway_assertion_header(name), "{name}");
    }
    for name in [
        "",
        "x-consumer",
        "x-consumerrole",
        "x-consumers-role",
        "x-geo-country",
        "consumer-role",
        "x-forwarded-consumer-role",
    ] {
        assert!(!is_consumer_assertion_header(name), "{name}");
    }
    assert!(is_gateway_assertion_header("x-geo-country"));
    assert!(is_gateway_assertion_header("X-Geo-Country"));
    assert!(!is_gateway_assertion_header("x-request-id"));
}

#[test]
fn ingress_materialization_drops_every_client_consumer_assertion() {
    let mut ctx = ctx();
    let mut raw = HeaderMap::new();
    raw.insert("x-consumer-role", "admin".parse().unwrap());
    raw.append("x-consumer-groups", "admins".parse().unwrap());
    raw.append("x-consumer-groups", "ops".parse().unwrap());
    raw.insert("X-Consumer-Username", "forged".parse().unwrap());
    raw.insert("x-consumer-custom-id", "forged-id".parse().unwrap());
    raw.insert("x-consumers-note", "ordinary".parse().unwrap());
    raw.insert("x-request-id", "req-1".parse().unwrap());
    ctx.set_raw_headers(raw);

    ctx.materialize_headers();

    assert!(
        consumer_namespace_keys(&ctx.headers).is_empty(),
        "no client x-consumer-* header may enter the plugin-facing map: {:?}",
        ctx.headers
    );
    assert_eq!(
        ctx.headers.get("x-consumers-note").map(String::as_str),
        Some("ordinary")
    );
    assert_eq!(
        ctx.headers.get("x-request-id").map(String::as_str),
        Some("req-1")
    );
}

#[test]
fn raw_grpc_merge_base_drops_client_consumer_namespace_but_keeps_gateway_username() {
    // Native gRPC / direct-H2 / mesh replay use the raw inbound map as their
    // merge base; the materialized view carries only the gateway assertion.
    let mut headers = HeaderMap::new();
    headers.insert("content-type", "application/grpc".parse().unwrap());
    headers.insert("x-consumer-role", "admin".parse().unwrap());
    headers.append("x-consumer-groups", "admins".parse().unwrap());
    headers.append("x-consumer-groups", "ops".parse().unwrap());
    headers.insert("x-consumer-username", "forged".parse().unwrap());
    let mut proxy_headers = HashMap::new();
    proxy_headers.insert("content-type".to_string(), "application/grpc".to_string());
    proxy_headers.insert("x-consumer-username".to_string(), "alice".to_string());

    merge_proxy_headers_and_strip_for_grpc(&mut headers, &proxy_headers);

    assert!(headers.get("x-consumer-role").is_none());
    assert!(headers.get("x-consumer-groups").is_none());
    assert_eq!(
        headers
            .get_all("x-consumer-username")
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>(),
        ["alice"],
        "only the gateway-asserted username may reach the backend"
    );
    assert_eq!(
        headers.get("content-type").and_then(|v| v.to_str().ok()),
        Some("application/grpc")
    );
}

#[test]
fn raw_grpc_merge_base_drops_client_consumer_namespace_without_a_principal() {
    let mut headers = HeaderMap::new();
    headers.insert("x-consumer-role", "admin".parse().unwrap());
    headers.insert("x-consumer-username", "forged".parse().unwrap());
    headers.insert("x-app", "kept".parse().unwrap());
    let mut proxy_headers = HashMap::new();
    proxy_headers.insert("x-app".to_string(), "kept".to_string());

    merge_proxy_headers_and_strip_for_grpc(&mut headers, &proxy_headers);

    assert!(
        headers
            .keys()
            .all(|name| !name.as_str().starts_with("x-consumer-")),
        "{headers:?}"
    );
    assert_eq!(
        headers.get("x-app").and_then(|v| v.to_str().ok()),
        Some("kept")
    );
}

#[test]
fn post_plugin_refresh_scrubs_plugin_authored_consumer_namespace() {
    // A plugin (or config) that wrote beneath the namespace cannot reach the
    // backend; only the authenticated principal is asserted.
    let ctx = authenticated_ctx("alice");
    let mut headers = HashMap::new();
    headers.insert("X-Consumer-Role".to_string(), "admin".to_string());
    headers.insert("x-consumer-groups".to_string(), "admins".to_string());
    headers.insert("X-Consumer-Username".to_string(), "forged".to_string());
    headers.insert("x-request-id".to_string(), "req-1".to_string());

    refresh_backend_gateway_assertion_headers(&ctx, &mut headers);

    assert_eq!(
        consumer_namespace_keys(&headers),
        vec!["x-consumer-username".to_string()],
        "only the gateway-owned username survives: {headers:?}"
    );
    assert_eq!(
        headers.get("x-consumer-username").map(String::as_str),
        Some("alice")
    );
    assert_eq!(
        headers.get("x-request-id").map(String::as_str),
        Some("req-1")
    );
}

#[test]
fn post_plugin_refresh_scrubs_consumer_namespace_without_a_principal() {
    let ctx = ctx();
    let mut headers = HashMap::new();
    headers.insert("x-consumer-role".to_string(), "admin".to_string());
    headers.insert("x-request-id".to_string(), "req-1".to_string());

    refresh_backend_gateway_assertion_headers(&ctx, &mut headers);

    assert!(
        consumer_namespace_keys(&headers).is_empty(),
        "no x-consumer-* header may survive the refresh: {headers:?}"
    );
    assert_eq!(
        headers.get("x-request-id").map(String::as_str),
        Some("req-1")
    );
}

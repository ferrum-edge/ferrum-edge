//! Integrity of the gateway-owned client diagnostic surface.
//!
//! * `X-Gateway-Error` and `X-Gateway-Upstream-Status` are gateway-owned
//!   (#5759): one shared list names them, every backend response boundary
//!   (reqwest / direct hyper / native gRPC, native HTTP/3, the HTTP/3 bridge,
//!   and every trailer section) drops a backend-supplied copy, and the final
//!   client wire sanitizer still keeps the gateway's own values.
//! * A route-deadline `504` that no backend held reads `request_timeout`, never
//!   `backend_timeout` (#5762).
//! * A reqwest connection-pool client that cannot be built answers the fixed
//!   pool-failure body on every attempt: no local path or raw library text,
//!   always valid JSON.

use std::collections::HashMap;

use ferrum_edge::_test_support::{
    collect_backend_response_headers_for_test, collect_h3_backend_response_headers_for_test,
    collect_h3_bridge_backend_response_headers_for_test,
    connection_pool_client_error_response_for_test, finalize_h3_response_gateway_headers_for_test,
    finalize_h3_response_routing_headers_for_test,
    gateway_owned_diagnostic_response_headers_for_test,
    govern_streaming_grpc_web_terminal_frame_for_test,
    govern_streaming_h2_backend_trailers_for_test,
    govern_streaming_h2_native_grpc_trailers_for_test,
    h3_bridge_pool_client_failure_headers_for_test,
    h3_route_deadline_mark_after_plugin_metadata_for_test, proxy_to_backend_retry_for_test,
    x_gateway_error_after_route_timeout_for_test,
};
use ferrum_edge::config::types::{GatewayConfig, Proxy};
use ferrum_edge::proxy::ProxyState;
use ferrum_edge::proxy::headers::{
    ClientResponseFraming, is_backend_response_strip_header,
    sanitize_client_response_headers_for_wire,
};
use ferrum_edge::retry::{
    ErrorClass, HTTP_OBSERVABILITY_ERROR_CLASSES, OBS_REQUEST_TIMEOUT, ResponseBody,
    intern_http_observability_error_class,
};

const GATEWAY_OWNED: [&str; 2] = ["x-gateway-error", "x-gateway-upstream-status"];

/// A backend response head that forges both gateway-owned fields beside an
/// ordinary application header.
fn forged_backend_headers() -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    headers.insert("content-type", "text/plain".parse().unwrap());
    headers.insert("x-app", "kept".parse().unwrap());
    headers.insert("x-gateway-error", "backend_error".parse().unwrap());
    headers.insert("x-gateway-upstream-status", "degraded".parse().unwrap());
    headers
}

fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

fn assert_no_gateway_owned(headers: &HashMap<String, String>, path: &str) {
    for name in headers.keys() {
        assert!(
            !GATEWAY_OWNED
                .iter()
                .any(|owned| name.eq_ignore_ascii_case(owned)),
            "{path}: backend-forged `{name}` crossed the backend boundary: {headers:?}"
        );
    }
    assert_eq!(
        headers.get("x-app").map(String::as_str),
        Some("kept"),
        "{path}: ordinary backend headers must still pass: {headers:?}"
    );
}

// ── #5759: one shared list, stripped at every backend boundary ─────────────

#[test]
fn gateway_owned_diagnostics_live_in_one_shared_list() {
    assert_eq!(
        gateway_owned_diagnostic_response_headers_for_test(),
        GATEWAY_OWNED.as_slice()
    );
}

#[test]
fn backend_boundary_predicate_strips_every_gateway_owned_field_in_any_case() {
    for name in gateway_owned_diagnostic_response_headers_for_test() {
        assert!(is_backend_response_strip_header(name), "{name}");
        assert!(
            is_backend_response_strip_header(&name.to_ascii_uppercase()),
            "{name} (uppercase)"
        );
    }
    assert!(!is_backend_response_strip_header("x-gateway-other"));
    assert!(!is_backend_response_strip_header("x-app"));
}

#[test]
fn h1_h2_and_native_grpc_collection_drops_forged_diagnostics() {
    let collected = collect_backend_response_headers_for_test(&forged_backend_headers());
    assert_no_gateway_owned(&collected, "reqwest / direct hyper / native gRPC");
}

#[test]
fn native_h3_collection_drops_forged_diagnostics() {
    let collected = collect_h3_backend_response_headers_for_test(&forged_backend_headers());
    assert_no_gateway_owned(&collected, "native HTTP/3");
}

#[test]
fn h3_bridge_collection_drops_forged_diagnostics() {
    let mut builder = http::Response::builder().status(200);
    for (name, value) in &forged_backend_headers() {
        builder = builder.header(name, value);
    }
    let response = reqwest::Response::from(builder.body("ok").unwrap());
    let collected = collect_h3_bridge_backend_response_headers_for_test(&response);
    assert_no_gateway_owned(&collected, "HTTP/3 bridge");
}

fn forged_trailers() -> Vec<(&'static str, &'static str)> {
    vec![
        ("grpc-status", "0"),
        ("x-gateway-error", "backend_timeout"),
        ("x-gateway-upstream-status", "degraded"),
        ("x-keep", "yes"),
    ]
}

fn assert_trailers_clean(surviving: &[(String, String)], path: &str) {
    assert!(
        !surviving
            .iter()
            .any(|(name, _)| GATEWAY_OWNED.contains(&name.as_str())),
        "{path}: backend-forged gateway-owned trailer survived: {surviving:?}"
    );
    assert!(
        surviving
            .iter()
            .any(|(name, value)| name == "x-keep" && value == "yes"),
        "{path}: ordinary trailers must still pass: {surviving:?}"
    );
}

#[test]
fn plain_and_native_grpc_trailer_sections_drop_forged_diagnostics() {
    // No response-header phase and no gateway write on this response, so
    // nothing but the backend boundary itself can remove the forged fields.
    let empty = HashMap::new();
    let plain = govern_streaming_h2_backend_trailers_for_test(
        &forged_trailers(),
        &empty,
        &empty,
        &[],
        false,
        false,
    );
    assert_trailers_clean(&plain, "plain trailers");
    let grpc = govern_streaming_h2_native_grpc_trailers_for_test(
        &forged_trailers(),
        &empty,
        &empty,
        &[],
        false,
        false,
    );
    assert_trailers_clean(&grpc, "native gRPC trailers");
}

#[test]
fn grpc_web_trailer_frame_never_carries_forged_diagnostics() {
    let empty = HashMap::new();
    for text_mode in [false, true] {
        let (_, frame, status) = govern_streaming_grpc_web_terminal_frame_for_test(
            &forged_trailers(),
            &empty,
            &empty,
            &[],
            false,
            false,
            200,
            text_mode,
        );
        let frame = String::from_utf8_lossy(&frame).to_ascii_lowercase();
        assert_eq!(status, 0);
        assert!(frame.contains("x-keep: yes"), "{frame}");
        assert!(!frame.contains("x-gateway-"), "{frame}");
    }
}

#[test]
fn client_wire_sanitizer_keeps_gateway_authored_diagnostics() {
    // Reject builders (overload, open breaker, adaptive concurrency, stale
    // config) carry their token in the same map the final sanitizer runs on.
    let mut headers = map(&[
        ("x-gateway-error", "overload"),
        ("x-gateway-upstream-status", "degraded"),
        ("connection", "keep-alive"),
    ]);
    sanitize_client_response_headers_for_wire(&mut headers, ClientResponseFraming::Streaming);
    assert_eq!(
        headers.get("x-gateway-error").map(String::as_str),
        Some("overload")
    );
    assert_eq!(
        headers.get("x-gateway-upstream-status").map(String::as_str),
        Some("degraded")
    );
    assert!(!headers.contains_key("connection"));
}

#[test]
fn h3_routing_seal_is_the_only_author_of_upstream_status() {
    // Not fallback: a copy a backend or hook left behind is removed.
    let mut headers = map(&[
        ("X-Gateway-Upstream-Status", "degraded"),
        ("content-type", "text/plain"),
    ]);
    finalize_h3_response_routing_headers_for_test(false, &mut headers);
    assert!(
        !headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("x-gateway-upstream-status")),
        "{headers:?}"
    );
    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("text/plain")
    );

    // Fallback: exactly one gateway value, whatever case variants arrived.
    let mut headers = map(&[
        ("X-Gateway-Upstream-Status", "ok"),
        ("x-gateway-upstream-status", "healthy"),
    ]);
    finalize_h3_response_routing_headers_for_test(true, &mut headers);
    let values: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("x-gateway-upstream-status"))
        .map(|(_, value)| value.as_str())
        .collect();
    assert_eq!(values, ["degraded"]);
}

/// Every `X-Gateway-Error` value on `headers`, whatever its name case.
fn gateway_error_values(headers: &HashMap<String, String>) -> Vec<&str> {
    headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("x-gateway-error"))
        .map(|(_, value)| value.as_str())
        .collect()
}

// ── #5783: every HTTP/3 response path writes the gateway's own token ────────

#[test]
fn h3_response_seal_writes_backend_error_for_a_relayed_backend_5xx() {
    // A plugin- or hook-set copy in any case is replaced by exactly one
    // gateway value, and the seal claims it for trailer reconciliation.
    let mut headers = map(&[
        ("X-Gateway-Error", "connection_failure"),
        ("x-gateway-error", "overload"),
        ("content-type", "text/plain"),
    ]);
    assert!(finalize_h3_response_gateway_headers_for_test(false, 503, &mut headers));
    assert_eq!(gateway_error_values(&headers), ["backend_error"]);
    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("text/plain")
    );

    let mut headers = HashMap::new();
    assert!(finalize_h3_response_gateway_headers_for_test(true, 502, &mut headers));
    assert_eq!(gateway_error_values(&headers), ["connection_failure"]);
}

#[test]
fn h3_response_seal_removes_a_forged_token_from_a_success() {
    let mut headers = map(&[("X-Gateway-Error", "backend_error"), ("x-app", "kept")]);
    assert!(!finalize_h3_response_gateway_headers_for_test(false, 200, &mut headers));
    assert!(gateway_error_values(&headers).is_empty(), "{headers:?}");
    assert_eq!(headers.get("x-app").map(String::as_str), Some("kept"));
}

#[test]
fn every_h3_response_finalize_site_writes_the_gateway_token() {
    // The bare routing seal writes no `X-Gateway-Error`; a relay that called
    // it directly would forward a backend 5xx without the gateway's token and
    // keep a plugin-written copy.
    let cross = include_str!("../../../src/http3/cross_protocol.rs");
    assert!(
        !cross.contains("finalize_h3_response_routing_headers("),
        "every HTTP/3 bridge response must use the gateway-token seal"
    );
    let server = include_str!("../../../src/http3/server.rs");
    let production = server
        .split("#[cfg(test)]")
        .next()
        .expect("server.rs production code");
    assert_eq!(
        production
            .matches("finalize_h3_response_routing_headers(")
            .count(),
        2,
        "only the routing seal's definition and the gateway-token seal may call it"
    );
    assert_eq!(
        production
            .matches("finalize_h3_response_gateway_headers(")
            .count(),
        6,
        "the definition plus the native buffered writer and the four streaming relays"
    );
    assert_eq!(
        cross
            .matches("finalize_h3_response_gateway_headers(")
            .count(),
        4,
        "the plain bridge's buffered and streaming paths and both gRPC bridge paths"
    );
}

#[test]
fn h1_h2_builder_strips_both_diagnostics_through_the_shared_helper() {
    let proxy = include_str!("../../../src/proxy/mod.rs");
    let builder = proxy
        .split("// Build final response\n")
        .nth(1)
        .expect("H1/H2 final response builder");
    let strip = builder
        .find("strip_gateway_owned_diagnostic_response_headers(&mut response_headers)")
        .expect("the H1/H2 builder must strip both gateway-owned fields before writing its own");
    let write = builder
        .find("resp_builder.header(\"X-Gateway-Upstream-Status\", \"degraded\")")
        .expect("the H1/H2 builder writes the degraded-routing header");
    assert!(strip < write, "strip must precede the builder's own write");
    let error_write = builder
        .find("resp_builder.header(\"X-Gateway-Error\"")
        .expect("the H1/H2 builder writes the gateway error token");
    assert!(
        strip < error_write,
        "strip must precede the builder's own X-Gateway-Error write"
    );
}

// ── #5762: a route timeout no backend held is not a backend timeout ─────────

/// The token the context-aware classifier picks, asserting the header writer
/// (which starts from a stale `backend_timeout`) wrote exactly that value.
fn token(phase: Option<&str>, connection_error: bool, status: u16) -> Option<&'static str> {
    let (token, written) =
        x_gateway_error_after_route_timeout_for_test(phase, connection_error, status);
    assert_eq!(written.as_deref(), token, "writer and classifier disagree");
    token
}

#[test]
fn route_timeout_before_any_backend_reads_request_timeout() {
    for phase in ["before_dispatch", "retry_backoff"] {
        assert_eq!(
            token(Some(phase), false, 504),
            Some("request_timeout"),
            "{phase}"
        );
    }
}

#[test]
fn route_timeout_a_backend_held_stays_backend_timeout() {
    assert_eq!(token(Some("dispatch"), false, 504), Some("backend_timeout"));
    // No route deadline at all: an ordinary backend read timeout.
    assert_eq!(token(None, false, 504), Some("backend_timeout"));
}

#[test]
fn request_timeout_token_is_scoped_to_the_route_deadline_504() {
    // A hook that later replaced the status, or a pre-wire failure, keeps the
    // ordinary classification.
    let before = Some("before_dispatch");
    assert_eq!(token(before, false, 502), Some("backend_error"));
    assert_eq!(token(before, true, 504), Some("connection_failure"));
    assert_eq!(token(before, false, 200), None);
}

#[test]
fn a_plugin_written_route_timeout_marker_cannot_suppress_the_phase() {
    // A plugin pre-writes the transaction-log key with a `dispatch` value.
    // The typed context marker, not the metadata, decides whether a phase is
    // already recorded, so the real before-dispatch phase is still recorded
    // and the 504 reads `request_timeout`.
    let (recorded_before, logged, token) =
        h3_route_deadline_mark_after_plugin_metadata_for_test("dispatch", "before_dispatch");
    assert!(
        !recorded_before,
        "plugin metadata must not read as a recorded total-deadline expiry"
    );
    assert_eq!(logged.as_deref(), Some("before_dispatch"));
    assert_eq!(token, Some("request_timeout"));

    // A plugin value naming a no-backend phase cannot select the token when
    // the backend held the attempt.
    let (recorded_before, logged, token) =
        h3_route_deadline_mark_after_plugin_metadata_for_test("retry_backoff", "dispatch");
    assert!(!recorded_before);
    assert_eq!(logged.as_deref(), Some("dispatch"));
    assert_eq!(token, Some("backend_timeout"));
}

#[test]
fn request_timeout_is_a_closed_vocabulary_token() {
    assert_eq!(OBS_REQUEST_TIMEOUT, "request_timeout");
    assert!(HTTP_OBSERVABILITY_ERROR_CLASSES.contains(&OBS_REQUEST_TIMEOUT));
    assert_eq!(
        intern_http_observability_error_class("request_timeout"),
        Some("request_timeout")
    );
}

// ── Fixed pool-failure body on every attempt ────────────────────────────────

fn assert_fixed_pool_failure(response: &ferrum_edge::retry::BackendResponse) {
    assert_eq!(response.status_code, 502);
    assert!(
        response.connection_error,
        "a client that was never built is pre-wire"
    );
    assert_eq!(response.error_class, Some(ErrorClass::ConnectionPoolError));
    let ResponseBody::Buffered(body) = &response.body else {
        panic!("the pool-failure body must be buffered");
    };
    let parsed: serde_json::Value =
        serde_json::from_slice(body).expect("the pool-failure body must be valid JSON");
    assert_eq!(parsed, serde_json::json!({"error": "Bad Gateway"}));
}

#[test]
fn connection_pool_client_error_response_is_fixed_and_valid_json() {
    let response = connection_pool_client_error_response_for_test(Some("10.0.0.7".into()));
    assert_fixed_pool_failure(&response);
    assert_eq!(response.backend_resolved_ip.as_deref(), Some("10.0.0.7"));
}

/// A retry attempt whose reqwest client cannot be built (its backend TLS
/// client material source is unreadable) answers the fixed body. The
/// construction error names the source path in quotes, so interpolating it
/// would both disclose the path and break the JSON body.
#[tokio::test]
async fn retry_client_construction_failure_never_reaches_the_client_body() {
    let absent_dir = std::env::temp_dir()
        .join(format!("ferrum-pool-failure-{}", std::process::id()))
        .join("tenant \"a\"");
    let cert_path = absent_dir.join("client.crt").to_string_lossy().into_owned();
    let key_path = absent_dir.join("client.key").to_string_lossy().into_owned();
    assert!(
        !absent_dir.exists(),
        "the TLS material source must be absent"
    );

    let proxy_json = serde_json::json!({
        "id": "retry-pool-failure",
        "listen_path": "/retry",
        "backend_scheme": "https",
        "backend_host": "127.0.0.1",
        "backend_port": 1,
        "backend_tls_client_cert_path": cert_path,
        "backend_tls_client_key_path": key_path,
    });
    let proxy: Proxy = serde_json::from_value(proxy_json).expect("proxy fixture");
    let mut config = GatewayConfig {
        proxies: vec![proxy],
        ..GatewayConfig::default()
    };
    config.normalize_fields();
    let mut proxy = config.proxies[0].clone();
    proxy.resolved_tls.client_cert_path = Some(cert_path.clone());
    proxy.resolved_tls.client_key_path = Some(key_path.clone());

    let dns_cache = ferrum_edge::dns::DnsCache::new(ferrum_edge::dns::DnsConfig::default());
    let env_config = ferrum_edge::config::env_config::EnvConfig::default();
    let (state, _) = ProxyState::new(GatewayConfig::default(), dns_cache, env_config, None, None)
        .expect("test proxy state should build");

    let response = proxy_to_backend_retry_for_test(&state, &proxy, "https://127.0.0.1:1/").await;

    assert_fixed_pool_failure(&response);
    let ResponseBody::Buffered(body) = &response.body else {
        unreachable!("asserted buffered above");
    };
    let body = String::from_utf8_lossy(body);
    for leaked in [
        "ferrum-pool-failure",
        "client.crt",
        "client.key",
        "tenant",
        "os error",
        "Failed to",
    ] {
        assert!(
            !body.contains(leaked),
            "the retry body must not carry `{leaked}`: {body}"
        );
    }
}

/// The HTTP/3 bridge's pool-failure `502` carries the same
/// `connection_failure` token proxy core's builder writes for the shared
/// pool-failure response (#5783).
#[test]
fn h3_bridge_pool_client_failure_carries_the_connection_failure_token() {
    let headers = h3_bridge_pool_client_failure_headers_for_test();
    assert_eq!(gateway_error_values(&headers), ["connection_failure"]);
    let (h1_h2_token, _) = x_gateway_error_after_route_timeout_for_test(
        None,
        connection_pool_client_error_response_for_test(None).connection_error,
        502,
    );
    assert_eq!(h1_h2_token, Some("connection_failure"));
}

#[test]
fn no_dispatch_path_interpolates_the_pool_construction_error() {
    let proxy = include_str!("../../../src/proxy/mod.rs");
    assert!(
        !proxy.contains(r#"Backend unavailable: {}"#),
        "a pool-failure body must never interpolate the construction error"
    );
    // Definition plus the first-attempt and retry call sites.
    assert_eq!(
        proxy
            .matches("connection_pool_client_error_response(")
            .count(),
        3,
        "both reqwest attempts must answer the shared pool-failure response"
    );
    let cross = include_str!("../../../src/http3/cross_protocol.rs");
    assert!(
        cross.contains("crate::proxy::CONNECTION_POOL_CLIENT_ERROR_BODY"),
        "the HTTP/3 bridge must answer the same fixed pool-failure body"
    );
}

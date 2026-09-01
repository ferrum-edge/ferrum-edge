//! Client-visible error-response headers: RFC 9110 `Allow` on 405 and
//! `X-Gateway-Error` on gateway-synthesized 5xx.

use std::collections::HashMap;

use ferrum_edge::_test_support::{
    PROTOCOL_LEVEL_405_ALLOW_FOR_TEST, allow_header_from_allowed_methods_for_test,
    apply_authoritative_backend_gateway_error_header_for_test, request_method_is_allowed_for_test,
    x_gateway_error_for_backend_failure_for_test,
};

fn gateway_error_values(headers: &HashMap<String, String>) -> Vec<&str> {
    let mut values: Vec<&str> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("x-gateway-error"))
        .map(|(_, value)| value.as_str())
        .collect();
    values.sort_unstable();
    values
}

#[test]
fn x_gateway_error_maps_connect_timeout_and_backend_5xx() {
    assert_eq!(
        x_gateway_error_for_backend_failure_for_test(true, 502),
        Some("connection_failure")
    );
    assert_eq!(
        x_gateway_error_for_backend_failure_for_test(false, 504),
        Some("backend_timeout")
    );
    assert_eq!(
        x_gateway_error_for_backend_failure_for_test(false, 500),
        Some("backend_error")
    );
    assert_eq!(
        x_gateway_error_for_backend_failure_for_test(false, 503),
        Some("backend_error")
    );
    assert_eq!(
        x_gateway_error_for_backend_failure_for_test(false, 404),
        None
    );
}

#[test]
fn allow_header_uppercases_in_config_order() {
    let methods = vec!["get".to_string(), "HEAD".to_string(), "post".to_string()];
    assert_eq!(
        allow_header_from_allowed_methods_for_test(&methods),
        "GET, HEAD, POST"
    );
}

#[test]
fn padded_allowed_methods_admit_and_advertise_the_trimmed_token() {
    let methods = vec![" GET ".to_string(), "post".to_string()];
    assert!(request_method_is_allowed_for_test(&methods, "GET"));
    assert!(request_method_is_allowed_for_test(&methods, "POST"));
    assert!(!request_method_is_allowed_for_test(&methods, "DELETE"));
    assert_eq!(
        allow_header_from_allowed_methods_for_test(&methods),
        "GET, POST"
    );
}

#[test]
fn late_hook_cannot_erase_or_spoof_authoritative_gateway_error() {
    let mut headers = HashMap::new();
    headers.insert("X-Gateway-Error".to_string(), "spoofed".to_string());
    headers.insert("x-gateway-error".to_string(), "also-spoofed".to_string());
    assert!(apply_authoritative_backend_gateway_error_header_for_test(
        &mut headers,
        true,
        403
    ));
    assert_eq!(gateway_error_values(&headers), ["connection_failure"]);

    headers.clear();
    assert!(apply_authoritative_backend_gateway_error_header_for_test(
        &mut headers,
        true,
        502
    ));
    assert_eq!(gateway_error_values(&headers), ["connection_failure"]);

    headers.insert("x-gateway-error".to_string(), "backend_error".to_string());
    assert!(apply_authoritative_backend_gateway_error_header_for_test(
        &mut headers,
        false,
        504
    ));
    assert_eq!(gateway_error_values(&headers), ["backend_timeout"]);

    headers.insert("X-Gateway-Error".to_string(), "spoofed".to_string());
    assert!(!apply_authoritative_backend_gateway_error_header_for_test(
        &mut headers,
        false,
        200
    ));
    assert!(gateway_error_values(&headers).is_empty());
}

#[test]
fn protocol_level_405_allow_omits_trace_and_connect() {
    assert_eq!(
        PROTOCOL_LEVEL_405_ALLOW_FOR_TEST,
        "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"
    );
    assert!(
        !PROTOCOL_LEVEL_405_ALLOW_FOR_TEST.contains("TRACE")
            && !PROTOCOL_LEVEL_405_ALLOW_FOR_TEST.contains("CONNECT")
    );
}

#[test]
fn protocol_level_405_sites_emit_static_allow() {
    let proxy = include_str!("../../../src/proxy/mod.rs");
    assert!(
        proxy.contains("fn build_method_not_allowed_response("),
        "H1/H2 TRACE/CONNECT 405s must share one Allow-bearing builder"
    );
    assert!(
        proxy.contains(".header(\"Allow\", PROTOCOL_LEVEL_405_ALLOW)"),
        "H1/H2 protocol-level 405 must attach the static Allow value"
    );
    let h3 = include_str!("../../../src/http3/server.rs");
    assert_eq!(
        h3.matches("send_h3_protocol_method_not_allowed(").count(),
        3,
        "H3 TRACE and CONNECT must both call send_h3_protocol_method_not_allowed (plus definition)"
    );
    let cross = include_str!("../../../src/http3/cross_protocol.rs");
    assert!(
        cross.contains("crate::proxy::PROTOCOL_LEVEL_405_ALLOW"),
        "unparseable-method 405 on the H3→HTTP bridge must advertise Allow"
    );
}

#[test]
fn circuit_breaker_open_sites_use_distinct_token() {
    for (name, src) in [
        ("H1/H2", include_str!("../../../src/proxy/mod.rs")),
        ("H3", include_str!("../../../src/http3/server.rs")),
        ("HBONE", include_str!("../../../src/proxy/hbone_proxy.rs")),
    ] {
        assert!(
            src.contains("circuit_breaker_open_reject_headers()"),
            "{name} open-breaker 503 must start from the precomputed header snapshot"
        );
        assert!(
            src.contains("X_GATEWAY_ERROR_CIRCUIT_BREAKER_OPEN"),
            "{name} must restore circuit_breaker_open after after_proxy"
        );
    }
}

#[test]
fn overload_and_stale_config_sites_set_distinct_gateway_error() {
    let proxy = include_str!("../../../src/proxy/mod.rs");
    assert!(
        proxy.contains("build_response_with_gateway_error("),
        "H1/H2 gateway-authored 503 fences must share the X-Gateway-Error builder"
    );
    assert!(
        proxy.contains("X_GATEWAY_ERROR_OVERLOAD"),
        "H1/H2 overload 503 must attach overload"
    );
    assert!(
        proxy.contains("X_GATEWAY_ERROR_CONFIG_STALE"),
        "H1/H2 stale-config 503 must attach config_stale"
    );

    let h3 = include_str!("../../../src/http3/server.rs");
    assert!(
        h3.contains("overload_reject_headers()"),
        "H3 overload 503 must start from the precomputed overload header snapshot"
    );
    assert!(
        h3.contains("config_stale_reject_headers()"),
        "H3 stale-config 503 must start from the precomputed stale-config header snapshot"
    );
}

#[test]
fn adaptive_concurrency_plugin_uses_concurrency_limit_token() {
    let src = include_str!("../../../src/plugins/adaptive_concurrency.rs");
    assert!(
        src.contains("OBS_CONCURRENCY_LIMIT"),
        "adaptive_concurrency 503 must intern the closed concurrency_limit token"
    );
    assert!(
        src.contains("\"x-gateway-error\""),
        "adaptive_concurrency 503 must set x-gateway-error"
    );
}

#[test]
fn h3_cross_protocol_classified_failures_keep_typed_gateway_error() {
    let cross = include_str!("../../../src/http3/cross_protocol.rs");
    let helper_definition = "fn reqwest_error_response_for_cross_protocol(";
    let helper_end = cross
        .find(helper_definition)
        .expect("cross-protocol reqwest classifier definition")
        + helper_definition.len();
    let mut classified_writes = 0usize;
    // Search only after the helper definition. Slicing at the function-name
    // match itself loses the preceding `fn `, so trying to reject the
    // definition from the suffix misclassifies it as a call site.
    let mut search = &cross[helper_end..];
    while let Some(idx) = search.find("reqwest_error_response_for_cross_protocol(") {
        let suffix = &search[idx..];
        let end = suffix
            .find("return Ok(outcome);")
            .expect("classified dispatch branch must return its written outcome")
            + "return Ok(outcome);".len();
        let window = &suffix[..end];
        assert!(
            window.contains("write_classified_backend_dispatch_error("),
            "classified H3→HTTP dispatch failure must write via write_classified_backend_dispatch_error"
        );
        assert!(
            !window.contains(r#"{"error":"Bad Gateway"}"#),
            "classified H3→HTTP dispatch failure must not collapse to generic Bad Gateway"
        );
        classified_writes += 1;
        search = &search[idx + 1..];
    }
    assert_eq!(
        classified_writes, 2,
        "buffered-exhausted and streaming send failures must both keep classified status/body/header"
    );
}

#[test]
fn native_h3_dispatch_failures_send_typed_gateway_error() {
    let h3 = include_str!("../../../src/http3/server.rs");
    assert!(
        h3.contains("fn send_h3_backend_failure_response("),
        "native H3 dispatch failures must share one X-Gateway-Error writer"
    );
    let buffered = h3
        .split("// ===== BUFFERED RESPONSE PATH =====")
        .nth(1)
        .expect("native H3 buffered response path");
    let after_proxy = buffered
        .find("run_after_proxy_hooks(")
        .expect("buffered native H3 after_proxy");
    let committed = buffered[after_proxy..]
        .find("run_deadline_bounded_response_committed_hooks(")
        .map(|idx| after_proxy + idx)
        .expect("buffered native H3 committed hooks");
    let sanitize = buffered[committed..]
        .find("sanitize_client_response_headers_for_wire(")
        .map(|idx| committed + idx)
        .expect("buffered native H3 pre-wire sanitize");
    let restore = buffered[sanitize..]
        .find("apply_authoritative_backend_gateway_error_header(")
        .map(|idx| sanitize + idx)
        .expect("buffered native H3 must restore X-Gateway-Error after committed hooks");
    assert!(
        !buffered[..sanitize].contains("apply_authoritative_backend_gateway_error_header("),
        "buffered native H3 must not restore X-Gateway-Error before the final pre-wire boundary"
    );
    assert!(
        restore > sanitize,
        "buffered native H3 must restore X-Gateway-Error after sanitizing for the wire"
    );
}

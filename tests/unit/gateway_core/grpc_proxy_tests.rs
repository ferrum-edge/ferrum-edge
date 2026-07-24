use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::Utc;
use ferrum_edge::config::types::{AuthMode, BackendScheme, DispatchKind, Proxy};
use ferrum_edge::plugins::security_headers::SecurityHeaders;
use ferrum_edge::plugins::{
    BufferedInitialResponseHeaderPolicyState, Plugin, RequestContext,
    response_transformer::ResponseTransformer,
};
use ferrum_edge::proxy::build_backend_url;
use ferrum_edge::proxy::grpc_proxy;
use ferrum_edge::proxy::headers::merge_proxy_headers_and_strip_for_grpc;
use serde_json::json;

fn test_proxy() -> Proxy {
    Proxy {
        id: "grpc-test".into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("gRPC Test Proxy".into()),
        hosts: vec![],
        listen_path: Some("/grpc".to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "grpc-backend.example.com".into(),
        backend_port: 50051,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5000,
        backend_read_timeout_ms: 30000,
        backend_write_timeout_ms: 30000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: Default::default(),
        dispatch_port_overrides: None,
        dispatch_port_override_fallback: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: AuthMode::Single,
        plugins: vec![],

        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        h2_upgrade_policy: None,
        pool_max_requests_per_connection: None,
        pool_http1_max_pending_requests: None,
        upstream_id: None,
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn headers_with_content_type(ct: &str) -> hyper::HeaderMap {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-type", ct.parse().unwrap());
    headers
}

#[test]
fn native_grpc_strips_raw_geo_assertion_before_authoritative_merge() {
    let mut raw_headers = hyper::HeaderMap::new();
    raw_headers.append("x-geo-country", "attacker-first".parse().unwrap());
    raw_headers.append("x-geo-country", "attacker-second".parse().unwrap());

    merge_proxy_headers_and_strip_for_grpc(&mut raw_headers, &HashMap::new());
    assert!(!raw_headers.contains_key("x-geo-country"));

    let mut raw_headers = hyper::HeaderMap::new();
    raw_headers.insert("x-geo-country", "attacker".parse().unwrap());
    let proxy_headers = HashMap::from([("x-geo-country".to_string(), "SE".to_string())]);

    merge_proxy_headers_and_strip_for_grpc(&mut raw_headers, &proxy_headers);
    assert_eq!(
        raw_headers
            .get("x-geo-country")
            .and_then(|value| value.to_str().ok()),
        Some("SE")
    );
}

#[test]
fn native_grpc_preserves_unchanged_repeated_metadata_field_lines() {
    let mut headers = hyper::HeaderMap::new();
    headers.append(
        "x-grpc-trace",
        hyper::header::HeaderValue::from_static("first"),
    );
    headers.append(
        "x-grpc-trace",
        hyper::header::HeaderValue::from_static("second"),
    );
    headers.append(
        "trace-proto-bin",
        hyper::header::HeaderValue::from_static("AQID"),
    );
    headers.append(
        "trace-proto-bin",
        hyper::header::HeaderValue::from_static("BAUG"),
    );

    let proxy_headers = HashMap::from([
        ("x-grpc-trace".to_string(), "first, second".to_string()),
        ("trace-proto-bin".to_string(), "AQID, BAUG".to_string()),
    ]);

    merge_proxy_headers_and_strip_for_grpc(&mut headers, &proxy_headers);

    let trace_values: Vec<_> = headers
        .get_all("x-grpc-trace")
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect();
    assert_eq!(trace_values, ["first", "second"]);
    let binary_values: Vec<_> = headers
        .get_all("trace-proto-bin")
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect();
    assert_eq!(binary_values, ["AQID", "BAUG"]);
}

#[test]
fn native_grpc_replaces_repeated_metadata_after_plugin_mutation() {
    let mut headers = hyper::HeaderMap::new();
    headers.append(
        "x-grpc-trace",
        hyper::header::HeaderValue::from_static("first"),
    );
    headers.append(
        "x-grpc-trace",
        hyper::header::HeaderValue::from_static("second"),
    );
    let proxy_headers = HashMap::from([("x-grpc-trace".to_string(), "replacement".to_string())]);

    merge_proxy_headers_and_strip_for_grpc(&mut headers, &proxy_headers);

    let values: Vec<_> = headers
        .get_all("x-grpc-trace")
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect();
    assert_eq!(values, ["replacement"]);
}

#[test]
fn h3_grpc_bridge_preserves_trusted_geo_assertion_on_both_dispatch_paths() {
    let source = include_str!("../../../src/http3/cross_protocol.rs");
    let helper = source
        .split("fn trusted_plugin_assertion_proxy_headers")
        .nth(1)
        .and_then(|tail| tail.split("/// Stream a live gRPC backend response").next())
        .expect("trusted H3 gRPC assertion helper source section");

    assert!(
        helper.contains("key.eq_ignore_ascii_case(\"x-geo-country\")"),
        "the H3 gRPC assertion bridge must retain the authoritative geo result"
    );
    assert_eq!(
        source
            .matches("trusted_plugin_assertion_proxy_headers(proxy_headers)")
            .count(),
        2,
        "both buffered and streaming H3-to-gRPC dispatches must use the trusted assertion map"
    );
}

// --- is_grpc_content_type detection tests ---

#[test]
fn test_is_grpc_request_application_grpc() {
    let headers = headers_with_content_type("application/grpc");
    assert!(grpc_proxy::is_grpc_content_type(&headers));
}

#[test]
fn test_is_grpc_request_application_grpc_proto() {
    let headers = headers_with_content_type("application/grpc+proto");
    assert!(grpc_proxy::is_grpc_content_type(&headers));
}

#[test]
fn test_is_grpc_request_application_grpc_json() {
    let headers = headers_with_content_type("application/grpc+json");
    assert!(grpc_proxy::is_grpc_content_type(&headers));
}

#[test]
fn test_is_grpc_request_content_type_is_case_insensitive() {
    let headers = headers_with_content_type("Application/Grpc+Proto");
    assert!(grpc_proxy::is_grpc_content_type(&headers));
}

#[test]
fn test_is_grpc_request_grpc_web_content_type_is_not_native_grpc() {
    let headers = headers_with_content_type("Application/Grpc-Web+Proto");
    assert!(!grpc_proxy::is_grpc_content_type(&headers));
}

#[test]
fn test_is_grpc_request_grpc_prefix_token_is_not_native_grpc() {
    for content_type in [
        "application/grpcish",
        "application/grpcx",
        "application/grpc-webish",
        "application/grpc -web",
    ] {
        let headers = headers_with_content_type(content_type);
        assert!(
            !grpc_proxy::is_grpc_content_type(&headers),
            "{content_type} must not be treated as native gRPC"
        );
    }
}

#[test]
fn test_is_grpc_request_allows_ows_before_parameters() {
    let headers = headers_with_content_type("application/grpc ;charset=utf-8");
    assert!(grpc_proxy::is_grpc_content_type(&headers));
}

#[test]
fn test_is_grpc_request_allows_immediate_and_tab_ows_parameters() {
    for content_type in [
        "application/grpc;charset=utf-8",   // immediate ';' (Some(b';') arm)
        "application/grpc\t;charset=utf-8", // tab OWS before ';'
    ] {
        let headers = headers_with_content_type(content_type);
        assert!(
            grpc_proxy::is_grpc_content_type(&headers),
            "{content_type} should be treated as native gRPC"
        );
    }
}

#[test]
fn test_is_grpc_request_trailing_ows_without_parameter_is_grpc() {
    // Per the gRPC-over-HTTP/2 spec the content-type "begins with
    // application/grpc"; trailing OWS is insignificant (trims to
    // `application/grpc`) and must still classify as native gRPC.
    for content_type in [
        "application/grpc ",     // trailing space
        "application/grpc\t",    // trailing tab
        "application/grpc ;x=y", // OWS then ';' (existing behaviour, confirmed)
    ] {
        let headers = headers_with_content_type(content_type);
        assert!(
            grpc_proxy::is_grpc_content_type(&headers),
            "{content_type:?} should be treated as native gRPC"
        );
    }
}

#[test]
fn test_is_grpc_request_grpc_web_is_not_grpc() {
    let headers = headers_with_content_type("application/grpc-web");
    assert!(!grpc_proxy::is_grpc_content_type(&headers));
}

#[test]
fn test_is_grpc_request_application_json_is_not_grpc() {
    let headers = headers_with_content_type("application/json");
    assert!(!grpc_proxy::is_grpc_content_type(&headers));
}

#[test]
fn test_is_grpc_request_no_content_type() {
    let headers = hyper::HeaderMap::new();
    assert!(!grpc_proxy::is_grpc_content_type(&headers));
}

#[test]
fn test_is_grpc_request_text_plain_is_not_grpc() {
    let headers = headers_with_content_type("text/plain");
    assert!(!grpc_proxy::is_grpc_content_type(&headers));
}

// --- build_backend_url for gRPC protocols ---

#[test]
fn test_build_backend_url_grpc_uses_http_scheme() {
    let proxy = test_proxy();
    let url = build_backend_url(
        &proxy,
        "/grpc/my.Service/MyMethod",
        "",
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
    );
    assert_eq!(
        url,
        "http://grpc-backend.example.com:50051/my.Service/MyMethod"
    );
}

#[test]
fn test_build_backend_url_grpcs_uses_https_scheme() {
    let mut proxy = test_proxy();
    proxy.backend_scheme = Some(BackendScheme::Https);
    proxy.dispatch_kind = DispatchKind::from(BackendScheme::Https);
    let url = build_backend_url(
        &proxy,
        "/grpc/my.Service/MyMethod",
        "",
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
    );
    assert_eq!(
        url,
        "https://grpc-backend.example.com:50051/my.Service/MyMethod"
    );
}

#[test]
fn test_build_backend_url_grpc_with_backend_path() {
    let mut proxy = test_proxy();
    proxy.backend_path = Some("/prefix".into());
    let url = build_backend_url(
        &proxy,
        "/grpc/my.Service/MyMethod",
        "",
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
    );
    assert_eq!(
        url,
        "http://grpc-backend.example.com:50051/prefix/my.Service/MyMethod"
    );
}

#[test]
fn test_build_backend_url_grpc_no_strip() {
    let mut proxy = test_proxy();
    proxy.strip_listen_path = false;
    let url = build_backend_url(
        &proxy,
        "/grpc/my.Service/MyMethod",
        "",
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
    );
    assert_eq!(
        url,
        "http://grpc-backend.example.com:50051/grpc/my.Service/MyMethod"
    );
}

// --- gRPC error response tests ---

#[test]
fn test_grpc_error_response_unavailable() {
    let resp =
        grpc_proxy::build_grpc_error_response(grpc_proxy::grpc_status::UNAVAILABLE, "Backend down");
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/grpc"
    );
    assert_eq!(resp.headers().get("grpc-status").unwrap(), "14");
    assert_eq!(resp.headers().get("grpc-message").unwrap(), "Backend down");
}

#[test]
fn trailers_only_error_can_retain_unread_frontend_upload() {
    // #2057: a pre-wire backend failure must keep the unread frontend upload
    // coupled to the synthesized Trailers-Only response lifecycle. This is an
    // H2 defense-in-depth ownership guarantee; raw clients still handle the
    // permitted post-response NO_ERROR reset.
    use http_body_util::Full;

    let held = grpc_proxy::GrpcBody::Buffered(Full::new(bytes::Bytes::from_static(b"pending")));
    let resp = grpc_proxy::attach_held_frontend_grpc_upload(
        grpc_proxy::build_grpc_error_response(
            grpc_proxy::grpc_status::UNAVAILABLE,
            "Backend unavailable",
        ),
        Some(held),
    );
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("grpc-status").unwrap(), "14");
    assert!(
        http_body::Body::is_end_stream(resp.body()),
        "Trailers-Only error body must still report end-of-stream at header time"
    );
}

#[test]
fn streaming_dispatch_acquires_sender_before_wrapping_frontend_upload() {
    // Source-order guard for #2057: connect/handshake failure must be able to
    // return the unread frontend upload. That requires get_sender before
    // Request::new(grpc_body).
    let src = include_str!("../../../src/proxy/grpc_proxy.rs");
    let start = src
        .find("async fn proxy_grpc_streaming_dispatch(")
        .expect("proxy_grpc_streaming_dispatch not found");
    let body = &src[start..];
    let end = body
        .find("\npub(crate) async fn collect_grpc_request_body(")
        .expect("collect_grpc_request_body anchor not found");
    let body = &body[..end];
    let sender_pos = body
        .find("grpc_pool.get_sender(proxy)")
        .expect("streaming dispatch must call get_sender");
    let request_pos = body
        .find("Request::new(grpc_body)")
        .expect("streaming dispatch must build backend request from grpc_body");
    assert!(
        sender_pos < request_pos,
        "get_sender must run before Request::new(grpc_body) so pre-wire failures \
         can retain the frontend upload (#2057); sender@{sender_pos} request@{request_pos}"
    );
    assert!(
        body.contains("*held_frontend_upload = Some(grpc_body)"),
        "pre-wire failures must stash the unread frontend upload for the caller"
    );

    let proxy_src = include_str!("../../../src/proxy/mod.rs");
    assert_eq!(
        proxy_src
            .matches("grpc_proxy::attach_held_frontend_grpc_upload(")
            .count(),
        3,
        "all three terminal native/gRPC-Web error shapes must attach the held upload"
    );
    assert_eq!(
        proxy_src
            .matches("held_frontend_grpc_upload.take()")
            .count(),
        3,
        "each terminal error attachment must consume the held upload exactly once"
    );
}

#[test]
fn test_grpc_error_response_deadline_exceeded() {
    let resp = grpc_proxy::build_grpc_error_response(
        grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
        "Timeout",
    );
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("grpc-status").unwrap(), "4");
    assert_eq!(resp.headers().get("grpc-message").unwrap(), "Timeout");
}

#[test]
fn test_grpc_error_response_unauthenticated() {
    let resp = grpc_proxy::build_grpc_error_response(
        16, // UNAUTHENTICATED
        "Missing token",
    );
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("grpc-status").unwrap(), "16");
}

#[test]
fn test_grpc_error_response_resource_exhausted() {
    let resp = grpc_proxy::build_grpc_error_response(
        8, // RESOURCE_EXHAUSTED
        "Rate limited",
    );
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("grpc-status").unwrap(), "8");
}

#[test]
fn grpc_error_policy_preserves_gateway_terminal_and_transport_authority() {
    let policy: Arc<dyn Plugin> = Arc::new(
        SecurityHeaders::new(&json!({
            "set": {
                "X-Synthetic-Policy": "enforced",
                "Content-Type": "text/plain",
                "Content-Length": "999",
                "Transfer-Encoding": "chunked",
                "Grpc-Status": "0",
                "Grpc-Message": "policy override",
                "Grpc-Status-Details-Bin": "hostile"
            },
            "remove": []
        }))
        .unwrap(),
    );

    let response = grpc_proxy::build_grpc_error_response_with_policy(
        grpc_proxy::grpc_status::UNAVAILABLE,
        "Backend down",
        &[policy],
    );

    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/grpc"
    );
    assert_eq!(response.headers().get("grpc-status").unwrap(), "14");
    assert_eq!(
        response.headers().get("grpc-message").unwrap(),
        "Backend down"
    );
    assert_eq!(
        response.headers().get("x-synthetic-policy").unwrap(),
        "enforced"
    );
    for managed in [
        "content-length",
        "transfer-encoding",
        "grpc-status-details-bin",
    ] {
        assert!(
            response.headers().get(managed).is_none(),
            "{managed} leaked"
        );
    }
}

#[test]
fn grpc_web_reject_finalizer_preserves_synthesized_status_without_terminal_overrides() {
    for (response_content_type, is_text) in [
        ("application/grpc-web+proto", false),
        ("application/grpc-web-text+proto", true),
    ] {
        let mut response = ferrum_edge::plugins::grpc_web::error_response_for_content_type(
            response_content_type,
            14,
            "backend unavailable",
        );
        let finalized_headers = HashMap::from([(
            "access-control-allow-origin".to_string(),
            "https://app.example".to_string(),
        )]);

        ferrum_edge::_test_support::finalize_grpc_web_error_response_headers(
            &mut response,
            &[],
            Some(&finalized_headers),
        );

        let wire_body = if is_text {
            BASE64.decode(&response.body).expect("decode text response")
        } else {
            response.body
        };
        let trailer = String::from_utf8_lossy(&wire_body[5..]);
        assert!(trailer.contains("grpc-status: 14\r\n"));
        assert!(trailer.contains("grpc-message: backend unavailable\r\n"));
    }
}

#[test]
fn grpc_web_reject_finalizer_moves_rich_status_details_into_body_trailer() {
    for (response_content_type, is_text) in [
        ("application/grpc-web+proto", false),
        ("application/grpc-web-text+proto", true),
    ] {
        let mut response = ferrum_edge::plugins::grpc_web::error_response_for_content_type(
            response_content_type,
            7,
            "denied",
        );
        let finalized_headers = HashMap::from([
            ("content-type".to_string(), "application/grpc".to_string()),
            ("grpc-status".to_string(), "7".to_string()),
            ("grpc-message".to_string(), "denied".to_string()),
            ("grpc-status-details-bin".to_string(), "AQID".to_string()),
            (
                "Access-Control-Expose-Headers".to_string(),
                "X-Request-ID, grpc-status".to_string(),
            ),
        ]);

        ferrum_edge::_test_support::finalize_grpc_web_error_response_headers(
            &mut response,
            &[],
            Some(&finalized_headers),
        );

        for terminal in ["grpc-status", "grpc-message", "grpc-status-details-bin"] {
            assert!(!response.headers.contains_key(terminal));
        }
        assert_eq!(
            response.headers.get("content-type").map(String::as_str),
            Some(response_content_type)
        );
        let expected_content_length = response.body.len().to_string();
        assert_eq!(
            response.headers.get("content-length").map(String::as_str),
            Some(expected_content_length.as_str())
        );
        let exposed_headers = response
            .headers
            .get("access-control-expose-headers")
            .expect("gRPC-Web rejects must expose configured and terminal metadata");
        for expected in [
            "grpc-status",
            "grpc-message",
            "grpc-status-details-bin",
            "X-Request-ID",
        ] {
            assert!(
                exposed_headers
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case(expected)),
                "missing {expected} in {exposed_headers}"
            );
        }
        assert_eq!(
            exposed_headers
                .split(',')
                .filter(|token| token.trim().eq_ignore_ascii_case("grpc-status"))
                .count(),
            1,
            "mandatory exposure must not be duplicated: {exposed_headers}"
        );
        let wire_body = if is_text {
            BASE64.decode(&response.body).expect("decode text response")
        } else {
            response.body
        };
        let trailer = String::from_utf8_lossy(&wire_body[5..]);
        assert!(trailer.contains("grpc-status: 7\r\n"));
        assert!(trailer.contains("grpc-message: denied\r\n"));
        assert!(trailer.contains("grpc-status-details-bin: AQID\r\n"));
    }
}

// --- BackendScheme display and deserialization ---
//
// Post-refactor, gRPC is no longer a backend_scheme — it is detected
// per-request via the content-type header. A gRPC proxy is configured with
// scheme `http` (plaintext) or `https` (TLS) and content-type routing picks
// the gRPC dispatch path.

#[test]
fn test_backend_scheme_display() {
    assert_eq!(BackendScheme::Https.to_string(), "https");
    assert_eq!(BackendScheme::Http.to_string(), "http");
}

// --- Response header capacity hint ---

#[test]
fn test_response_header_capacity_hint_matches_keys_len() {
    // Verify that HashMap::with_capacity(keys_len()) pre-allocates correctly.
    // This mirrors the optimization in proxy_grpc_request_core.
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-type", "application/grpc".parse().unwrap());
    headers.insert("grpc-status", "0".parse().unwrap());
    headers.insert("grpc-message", "OK".parse().unwrap());

    // keys_len() counts unique header names (same as len() when no duplicate names)
    let capacity_hint = headers.keys_len();
    assert_eq!(capacity_hint, 3);

    let mut resp_headers = std::collections::HashMap::with_capacity(capacity_hint);
    for (k, v) in &headers {
        if let Ok(vs) = v.to_str() {
            resp_headers.insert(k.as_str().to_string(), vs.to_string());
        }
    }
    assert_eq!(resp_headers.len(), 3);
    assert_eq!(resp_headers["content-type"], "application/grpc");
    assert_eq!(resp_headers["grpc-status"], "0");
}

#[test]
fn test_response_header_capacity_hint_with_duplicate_names() {
    // keys_len() de-duplicates repeated header names; verify capacity is still valid.
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-type", "application/grpc".parse().unwrap());
    // Append a second value for the same key
    headers.append("content-type", "application/grpc+proto".parse().unwrap());
    headers.insert("grpc-status", "0".parse().unwrap());

    // keys_len() = 2 (two unique names), len() = 3 (three values)
    assert_eq!(headers.keys_len(), 2);
    assert_eq!(headers.len(), 3);

    // A HashMap built with this capacity will hold the last value per key
    let capacity_hint = headers.keys_len();
    let mut resp_headers = std::collections::HashMap::with_capacity(capacity_hint);
    for (k, v) in &headers {
        if let Ok(vs) = v.to_str() {
            resp_headers.insert(k.as_str().to_string(), vs.to_string());
        }
    }
    // Map has at most keys_len() unique entries
    assert!(resp_headers.len() <= headers.keys_len());
}

#[test]
fn test_grpc_buffered_body_capacity_hint_clamps_large_content_length() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", "999999999".parse().unwrap());
    assert_eq!(
        grpc_proxy::grpc_buffered_body_capacity_hint(&headers),
        1024 * 1024
    );
}

#[test]
fn test_grpc_buffered_body_capacity_hint_defaults_without_content_length() {
    let headers = hyper::HeaderMap::new();
    assert_eq!(
        grpc_proxy::grpc_buffered_body_capacity_hint(&headers),
        16 * 1024
    );
}

// --- Streaming mode returns empty body bytes ---

#[tokio::test]
async fn test_proxy_grpc_request_from_bytes_error_on_unreachable_backend() {
    // Verify the buffered path (proxy_grpc_request_from_bytes) errors gracefully
    // on an unreachable backend; this also confirms no panic in either code path.
    use bytes::Bytes;

    let pool = grpc_proxy::GrpcConnectionPool::default();
    let mut proxy = test_proxy();
    proxy.backend_host = "127.0.0.1".to_string();
    proxy.backend_port = 1; // intentionally unreachable port
    proxy.retry = None;

    let dns = ferrum_edge::dns::DnsCache::new(ferrum_edge::dns::DnsConfig::default());
    let headers = headers_with_content_type("application/grpc");
    let body = Bytes::from_static(b"\x00\x00\x00\x00\x05hello");
    let proxy_headers = std::collections::HashMap::new();

    let result = grpc_proxy::proxy_grpc_request_from_bytes(
        hyper::Method::POST,
        headers,
        body,
        &proxy,
        "http://127.0.0.1:1/test.Service/Method",
        &pool,
        &dns,
        &proxy_headers,
        false,
        0,
        None,
    )
    .await;
    assert!(
        result.is_err(),
        "Connection to unreachable port should fail"
    );
}

// --- parse_grpc_timeout_ms tests ---

fn headers_with_grpc_timeout(val: &str) -> hyper::HeaderMap {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("grpc-timeout", val.parse().unwrap());
    headers
}

#[test]
fn test_parse_grpc_timeout_seconds() {
    let headers = headers_with_grpc_timeout("5S");
    assert_eq!(grpc_proxy::parse_grpc_timeout_ms(&headers), Some(5000));
}

#[test]
fn test_parse_grpc_timeout_milliseconds() {
    let headers = headers_with_grpc_timeout("200m");
    assert_eq!(grpc_proxy::parse_grpc_timeout_ms(&headers), Some(200));
}

#[test]
fn test_parse_grpc_timeout_hours() {
    let headers = headers_with_grpc_timeout("1H");
    assert_eq!(grpc_proxy::parse_grpc_timeout_ms(&headers), Some(3_600_000));
}

#[test]
fn test_parse_grpc_timeout_minutes() {
    let headers = headers_with_grpc_timeout("2M");
    assert_eq!(grpc_proxy::parse_grpc_timeout_ms(&headers), Some(120_000));
}

#[test]
fn test_parse_grpc_timeout_microseconds() {
    let headers = headers_with_grpc_timeout("5000u");
    assert_eq!(grpc_proxy::parse_grpc_timeout_ms(&headers), Some(5));
}

#[test]
fn test_parse_grpc_timeout_nanoseconds() {
    let headers = headers_with_grpc_timeout("5000000n");
    assert_eq!(grpc_proxy::parse_grpc_timeout_ms(&headers), Some(5));
}

#[test]
fn test_parse_grpc_timeout_sub_millisecond_clamps_to_1() {
    // 100 microseconds = 0.1ms → clamped to 1ms
    let headers = headers_with_grpc_timeout("100u");
    assert_eq!(grpc_proxy::parse_grpc_timeout_ms(&headers), Some(1));
}

#[test]
fn test_parse_grpc_timeout_zero_returns_none() {
    let headers = headers_with_grpc_timeout("0S");
    assert_eq!(grpc_proxy::parse_grpc_timeout_ms(&headers), None);
}

#[test]
fn test_parse_grpc_timeout_missing_header() {
    let headers = hyper::HeaderMap::new();
    assert_eq!(grpc_proxy::parse_grpc_timeout_ms(&headers), None);
}

#[test]
fn test_parse_grpc_timeout_invalid_unit() {
    let headers = headers_with_grpc_timeout("5X");
    assert_eq!(grpc_proxy::parse_grpc_timeout_ms(&headers), None);
}

#[test]
fn test_parse_grpc_timeout_invalid_number() {
    let headers = headers_with_grpc_timeout("abcS");
    assert_eq!(grpc_proxy::parse_grpc_timeout_ms(&headers), None);
}

#[test]
fn test_parse_grpc_timeout_empty_value() {
    let headers = headers_with_grpc_timeout("");
    // Empty header value — cannot split unit character
    assert_eq!(grpc_proxy::parse_grpc_timeout_ms(&headers), None);
}

#[test]
fn test_parse_grpc_timeout_overflow_returns_none() {
    // The gRPC wire format allows at most 8 digits; an 18-digit value violates the
    // grammar and is rejected (`None`), exactly like the `grpc_deadline` plugin.
    // Returning `None` — rather than saturating to `u64::MAX` — keeps the operator's
    // `backend_read_timeout_ms` fallback in force so a malformed client header cannot
    // opt out of the operator timeout by presenting an effectively unbounded deadline.
    let headers = headers_with_grpc_timeout("999999999999999999H");
    assert_eq!(grpc_proxy::parse_grpc_timeout_ms(&headers), None);

    // A maximal IN-grammar value (8 digits) is still accepted and never overflows.
    let headers = headers_with_grpc_timeout("99999999H");
    assert_eq!(
        grpc_proxy::parse_grpc_timeout_ms(&headers),
        Some(99_999_999u64 * 3_600_000)
    );
}

// --- GrpcConnectionPool creation ---

#[tokio::test]
async fn test_grpc_connection_pool_creation() {
    let pool = grpc_proxy::GrpcConnectionPool::default();
    // Pool should be functional after creation — attempting to get a sender for
    // a non-existent backend should fail with a connection error, not a panic.
    let mut proxy = test_proxy();
    proxy.backend_host = "127.0.0.1".to_string();
    proxy.backend_port = 1; // intentionally unreachable port
    let result = pool.get_sender(&proxy).await;
    // Connection should fail (unreachable port), but not panic
    assert!(
        result.is_err(),
        "Connection to unreachable port should fail"
    );
}

// --- Buffered gRPC plugin header/trailer view + reconciliation ---
//
// These cover the shared helpers the main gRPC buffered path
// (`proxy::handle_proxy_request`) and the HTTP/3 cross-protocol bridge
// (`http3::cross_protocol`) both use so a response-hook sanitizer reaches the
// wire trailers identically across H1/H2 and H3 (#1614 / #1612).

fn grpc_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn build_view_merges_trailer_only_keys_and_tracks_no_shadow() {
    let headers = grpc_map(&[("content-type", "application/grpc")]);
    let trailers = grpc_map(&[("grpc-status", "0"), ("x-trailer-only", "tv")]);

    let (view, shadowed) = grpc_proxy::build_grpc_plugin_header_view(&headers, &trailers);

    // Trailer-only keys are merged into the view so hooks can see/sanitize them.
    assert_eq!(
        view.get("content-type").map(String::as_str),
        Some("application/grpc")
    );
    assert_eq!(view.get("grpc-status").map(String::as_str), Some("0"));
    assert_eq!(view.get("x-trailer-only").map(String::as_str), Some("tv"));
    assert!(
        shadowed.is_empty(),
        "no key was duplicated across headers and trailers"
    );
}

#[test]
fn build_view_tracks_header_shadowed_key_without_overriding_header_value() {
    let headers = grpc_map(&[("x-dup", "header-val")]);
    let trailers = grpc_map(&[("x-dup", "trailer-val")]);

    let (view, shadowed) = grpc_proxy::build_grpc_plugin_header_view(&headers, &trailers);

    // A trailer never overrides a real header in the merged view.
    assert_eq!(view.get("x-dup").map(String::as_str), Some("header-val"));
    assert!(
        shadowed.contains("x-dup"),
        "the duplicated key must be tracked as shadowed"
    );
}

#[test]
fn build_view_reserved_terminal_keys_are_never_shadowed() {
    // A malformed backend duplicated grpc-status into the initial headers with a
    // bogus value; the real terminal status rides the trailer. Reserved terminal
    // keys are trailer-authoritative, so the trailer value wins in the view and
    // the key is NOT treated as shadowed (the bogus header copy must be stripped
    // off the wire by the caller, never fed to plugins or the client).
    let headers = grpc_map(&[("grpc-status", "99"), ("grpc-message", "bogus")]);
    let trailers = grpc_map(&[("grpc-status", "0"), ("grpc-message", "OK")]);

    let (view, shadowed) = grpc_proxy::build_grpc_plugin_header_view(&headers, &trailers);

    assert_eq!(view.get("grpc-status").map(String::as_str), Some("0"));
    assert_eq!(view.get("grpc-message").map(String::as_str), Some("OK"));
    assert!(!shadowed.contains("grpc-status"));
    assert!(!shadowed.contains("grpc-message"));
}

#[test]
fn reconcile_propagates_hook_edit_of_shadowed_key_into_trailer() {
    let original_headers = grpc_map(&[("x-dup", "orig")]);
    let mut trailers = grpc_map(&[("x-dup", "trailer-orig")]);
    let shadowed: HashSet<String> = ["x-dup".to_string()].into_iter().collect();
    // Hook rewrote the visible header copy in the view.
    let view = grpc_map(&[("x-dup", "redacted-by-hook")]);

    grpc_proxy::reconcile_grpc_trailers_from_view(
        &mut trailers,
        &view,
        &original_headers,
        &shadowed,
        None,
    );

    // The sanitized value must scrub the hidden trailer copy too.
    assert_eq!(
        trailers.get("x-dup").map(String::as_str),
        Some("redacted-by-hook")
    );
}

#[test]
fn reconcile_keeps_backend_trailer_value_for_untouched_shadowed_key() {
    let original_headers = grpc_map(&[("x-dup", "header-untouched")]);
    let mut trailers = grpc_map(&[("x-dup", "trailer-untouched")]);
    let shadowed: HashSet<String> = ["x-dup".to_string()].into_iter().collect();
    // Hook left the shadowed key at its original header value.
    let view = grpc_map(&[("x-dup", "header-untouched")]);

    grpc_proxy::reconcile_grpc_trailers_from_view(
        &mut trailers,
        &view,
        &original_headers,
        &shadowed,
        None,
    );

    // An untouched shadowed trailer must keep the backend's true trailing value,
    // NOT be clobbered by the (equal-or-not) header value.
    assert_eq!(
        trailers.get("x-dup").map(String::as_str),
        Some("trailer-untouched")
    );
}

#[test]
fn reconcile_drops_hook_removed_keys() {
    let original_headers = grpc_map(&[("x-shadow", "hv")]);
    let mut trailers = grpc_map(&[
        ("grpc-status", "0"),
        ("x-removed-trailer", "tv"),
        ("x-shadow", "tv"),
    ]);
    let shadowed: HashSet<String> = ["x-shadow".to_string()].into_iter().collect();
    // Hook removed both the trailer-only key and the shadowed key from the view.
    let view = grpc_map(&[("grpc-status", "0")]);

    grpc_proxy::reconcile_grpc_trailers_from_view(
        &mut trailers,
        &view,
        &original_headers,
        &shadowed,
        None,
    );

    assert_eq!(trailers.get("grpc-status").map(String::as_str), Some("0"));
    assert!(
        !trailers.contains_key("x-removed-trailer"),
        "hook removal drops trailer-only key"
    );
    assert!(
        !trailers.contains_key("x-shadow"),
        "hook removal drops the hidden shadowed trailer too"
    );
}

#[test]
fn reconcile_propagates_trailer_only_edit_and_keeps_untouched() {
    let original_headers = grpc_map(&[]);
    let mut trailers = grpc_map(&[("x-edited", "orig"), ("x-kept", "v")]);
    let shadowed: HashSet<String> = HashSet::new();
    let view = grpc_map(&[("x-edited", "edited"), ("x-kept", "v")]);

    grpc_proxy::reconcile_grpc_trailers_from_view(
        &mut trailers,
        &view,
        &original_headers,
        &shadowed,
        None,
    );

    assert_eq!(trailers.get("x-edited").map(String::as_str), Some("edited"));
    assert_eq!(trailers.get("x-kept").map(String::as_str), Some("v"));
}

#[test]
fn build_then_reconcile_matches_buffered_writeback_scenario() {
    // Mirrors the wire-trailer assertions of the main-path integration test
    // `grpc_buffered_trailer_writeback_honors_hook_removal_and_duplicate_keys`,
    // exercising the exact merge + reconcile the H3 cross-protocol bridge now
    // shares with the main gRPC path.
    let backend_headers = grpc_map(&[
        ("content-type", "application/grpc"),
        ("x-dup-key", "header-untouched"),
        ("x-dup-untouched", "header-untouched"),
        ("x-shadowed-removed", "hv"),
    ]);
    let backend_trailers = grpc_map(&[
        ("grpc-status", "0"),
        ("grpc-message", "OK"),
        ("x-dup-key", "trailer-untouched"),
        ("x-dup-untouched", "trailer-untouched"),
        ("x-removed-trailer", "tv"),
        ("x-shadowed-removed", "tv"),
    ]);

    let (mut view, shadowed) =
        grpc_proxy::build_grpc_plugin_header_view(&backend_headers, &backend_trailers);

    // Simulate a response_transformer that updates x-dup-key and removes
    // x-removed-trailer + x-shadowed-removed (operating on the merged view).
    view.insert("x-dup-key".to_string(), "redacted-by-hook".to_string());
    view.remove("x-removed-trailer");
    view.remove("x-shadowed-removed");

    let mut wire_trailers = backend_trailers.clone();
    grpc_proxy::reconcile_grpc_trailers_from_view(
        &mut wire_trailers,
        &view,
        &backend_headers,
        &shadowed,
        None,
    );

    // Terminal status keeps the backend's true trailing values.
    assert_eq!(
        wire_trailers.get("grpc-status").map(String::as_str),
        Some("0")
    );
    assert_eq!(
        wire_trailers.get("grpc-message").map(String::as_str),
        Some("OK")
    );
    // Hook-edited shadowed key: sanitized value reaches the wire trailer.
    assert_eq!(
        wire_trailers.get("x-dup-key").map(String::as_str),
        Some("redacted-by-hook")
    );
    // Untouched shadowed key: backend's true trailer value preserved.
    assert_eq!(
        wire_trailers.get("x-dup-untouched").map(String::as_str),
        Some("trailer-untouched")
    );
    // Hook removals suppress both a trailer-only key and a shadowed trailer.
    assert!(!wire_trailers.contains_key("x-removed-trailer"));
    assert!(!wire_trailers.contains_key("x-shadowed-removed"));
}

#[tokio::test]
async fn buffered_policy_is_applied_to_initial_headers_without_promoting_trailers() {
    let backend_headers = grpc_map(&[("content-type", "application/grpc")]);
    let backend_trailers = grpc_map(&[
        ("grpc-status", "0"),
        ("grpc-message", "OK"),
        ("x-policy", "backend-trailer-value"),
        ("x-application-trailer", "application-value"),
    ]);
    let (mut plugin_view, shadowed) =
        grpc_proxy::build_grpc_plugin_header_view(&backend_headers, &backend_trailers);
    let policy: Arc<dyn Plugin> = Arc::new(
        SecurityHeaders::new(&json!({
            "override_existing": false,
            "set": {
                "X-Policy": "gateway-enforced",
                "Grpc-Status": "13"
            },
            "remove": []
        }))
        .unwrap(),
    );
    let mut policy_state = BufferedInitialResponseHeaderPolicyState::new(
        Arc::new(policy.initial_response_header_policy_names().to_vec()),
        &backend_headers,
        &plugin_view,
    )
    .unwrap();
    let mut ctx = RequestContext::new("203.0.113.10".into(), "POST".into(), "/svc".into());
    let _ = policy.after_proxy(&mut ctx, 200, &mut plugin_view).await;
    policy_state.record_after_proxy_plugin(policy.as_ref(), &mut plugin_view);

    let mut wire_trailers = backend_trailers.clone();
    grpc_proxy::reconcile_grpc_trailers_from_view(
        &mut wire_trailers,
        &plugin_view,
        &backend_headers,
        &shadowed,
        Some(&policy_state),
    );
    let mut initial_headers = plugin_view;
    grpc_proxy::strip_non_initial_grpc_trailer_fields(
        &mut initial_headers,
        &wire_trailers,
        &shadowed,
    );
    grpc_proxy::apply_buffered_grpc_initial_response_policy(
        Some(&policy_state),
        &mut initial_headers,
        None,
    );

    assert_eq!(
        initial_headers.get("x-policy").map(String::as_str),
        Some("gateway-enforced"),
        "override_existing=false must evaluate against genuine initial headers"
    );
    assert!(!initial_headers.contains_key("x-application-trailer"));
    assert!(!initial_headers.contains_key("grpc-status"));
    assert!(!initial_headers.contains_key("grpc-message"));
    assert_eq!(
        wire_trailers.get("x-policy").map(String::as_str),
        Some("backend-trailer-value"),
        "policy enforcement must not promote or relocate the backend trailer value"
    );
    assert_eq!(
        wire_trailers
            .get("x-application-trailer")
            .map(String::as_str),
        Some("application-value")
    );
    assert_eq!(
        wire_trailers.get("grpc-status").map(String::as_str),
        Some("0")
    );
    assert_eq!(
        wire_trailers.get("grpc-message").map(String::as_str),
        Some("OK")
    );
}

#[tokio::test]
async fn buffered_override_policy_preserves_application_trailer_value() {
    let backend_headers = grpc_map(&[("content-type", "application/grpc")]);
    let backend_trailers = grpc_map(&[("grpc-status", "0"), ("x-policy", "application-value")]);
    let (mut plugin_view, shadowed) =
        grpc_proxy::build_grpc_plugin_header_view(&backend_headers, &backend_trailers);
    let policy: Arc<dyn Plugin> = Arc::new(
        SecurityHeaders::new(&json!({
            "override_existing": true,
            "set": { "X-Policy": "gateway-enforced" }
        }))
        .unwrap(),
    );
    let mut policy_state = BufferedInitialResponseHeaderPolicyState::new(
        Arc::new(policy.initial_response_header_policy_names().to_vec()),
        &backend_headers,
        &plugin_view,
    )
    .unwrap();
    let mut ctx = RequestContext::new("203.0.113.10".into(), "POST".into(), "/svc".into());

    let _ = policy.after_proxy(&mut ctx, 200, &mut plugin_view).await;
    policy_state.record_after_proxy_plugin(policy.as_ref(), &mut plugin_view);

    let mut wire_trailers = backend_trailers;
    grpc_proxy::reconcile_grpc_trailers_from_view(
        &mut wire_trailers,
        &plugin_view,
        &backend_headers,
        &shadowed,
        Some(&policy_state),
    );
    let mut initial_headers = plugin_view;
    grpc_proxy::strip_non_initial_grpc_trailer_fields(
        &mut initial_headers,
        &wire_trailers,
        &shadowed,
    );
    policy_state.apply_to_initial_headers(&mut initial_headers);

    assert_eq!(
        initial_headers.get("x-policy").map(String::as_str),
        Some("gateway-enforced")
    );
    assert_eq!(
        wire_trailers.get("x-policy").map(String::as_str),
        Some("application-value"),
        "initial-header policy must not overwrite application metadata"
    );
}

#[tokio::test]
async fn buffered_policy_removal_suppresses_mutated_cookie_and_application_trailers() {
    let backend_headers = grpc_map(&[
        ("content-type", "application/grpc"),
        ("x-powered-by", "backend-header"),
    ]);
    let backend_trailers = grpc_map(&[
        ("grpc-status", "0"),
        ("set-cookie", "session=backend"),
        ("x-powered-by", "backend-trailer"),
        ("x-trailer-only", "backend-trailer"),
    ]);
    let original_trailer_set_cookie = backend_trailers.get("set-cookie").cloned();
    let (mut plugin_view, shadowed) =
        grpc_proxy::build_grpc_plugin_header_view(&backend_headers, &backend_trailers);
    let transformer: Arc<dyn Plugin> = Arc::new(
        ResponseTransformer::new(&json!({
            "rules": [{
                "operation": "update",
                "target": "header",
                "key": "Set-Cookie",
                "value": "session=mutated"
            }]
        }))
        .unwrap(),
    );
    let policy: Arc<dyn Plugin> = Arc::new(
        SecurityHeaders::new(&json!({
            "set": {},
            "remove": ["Set-Cookie", "X-Powered-By", "X-Trailer-Only", "Grpc-Status"]
        }))
        .unwrap(),
    );
    let mut policy_state = BufferedInitialResponseHeaderPolicyState::new(
        Arc::new(policy.initial_response_header_policy_names().to_vec()),
        &backend_headers,
        &plugin_view,
    )
    .unwrap();
    let mut ctx = RequestContext::new("203.0.113.10".into(), "POST".into(), "/svc".into());

    let _ = transformer
        .after_proxy(&mut ctx, 200, &mut plugin_view)
        .await;
    policy_state.record_after_proxy_plugin(transformer.as_ref(), &mut plugin_view);
    assert_eq!(
        plugin_view.get("set-cookie").map(String::as_str),
        Some("session=mutated")
    );
    let _ = policy.after_proxy(&mut ctx, 200, &mut plugin_view).await;
    policy_state.record_after_proxy_plugin(policy.as_ref(), &mut plugin_view);

    let mut wire_trailers = backend_trailers;
    grpc_proxy::reconcile_grpc_trailers_from_view(
        &mut wire_trailers,
        &plugin_view,
        &backend_headers,
        &shadowed,
        Some(&policy_state),
    );
    let mut initial_headers = plugin_view;
    grpc_proxy::finalize_buffered_grpc_split_response(
        &mut initial_headers,
        &mut wire_trailers,
        &shadowed,
        Some(&policy_state),
        None,
        original_trailer_set_cookie.as_deref(),
    );

    for removed_name in ["set-cookie", "x-powered-by", "x-trailer-only"] {
        assert!(
            !initial_headers.contains_key(removed_name),
            "final security policy removal must suppress {removed_name} in initial headers"
        );
        assert!(
            !wire_trailers.contains_key(removed_name),
            "final security policy removal must suppress {removed_name} in trailers"
        );
    }
    assert!(
        !initial_headers.contains_key("grpc-status"),
        "terminal gRPC status must not be promoted to non-empty initial headers"
    );
    assert_eq!(
        wire_trailers.get("grpc-status").map(String::as_str),
        Some("0"),
        "policy removal must not disturb terminal gRPC metadata"
    );
}

#[tokio::test]
async fn buffered_policy_state_preserves_later_header_mutator_order() {
    let backend_headers = grpc_map(&[("content-type", "application/grpc")]);
    let backend_trailers = grpc_map(&[("grpc-status", "0"), ("x-policy", "backend-trailer")]);
    let (mut plugin_view, shadowed) =
        grpc_proxy::build_grpc_plugin_header_view(&backend_headers, &backend_trailers);
    let policy: Arc<dyn Plugin> = Arc::new(
        SecurityHeaders::new(&json!({
            "override_existing": false,
            "set": { "X-Policy": "gateway-policy" }
        }))
        .unwrap(),
    );
    let later_mutator: Arc<dyn Plugin> = Arc::new(
        ResponseTransformer::new(&json!({
            "rules": [{
                "operation": "update",
                "target": "header",
                "key": "X-Policy",
                "value": "later-transformer"
            }]
        }))
        .unwrap(),
    );
    let mut policy_state = BufferedInitialResponseHeaderPolicyState::new(
        Arc::new(policy.initial_response_header_policy_names().to_vec()),
        &backend_headers,
        &plugin_view,
    )
    .unwrap();
    let mut ctx = RequestContext::new("203.0.113.10".into(), "POST".into(), "/svc".into());

    let _ = policy.after_proxy(&mut ctx, 200, &mut plugin_view).await;
    policy_state.record_after_proxy_plugin(policy.as_ref(), &mut plugin_view);
    let _ = later_mutator
        .after_proxy(&mut ctx, 200, &mut plugin_view)
        .await;
    policy_state.record_after_proxy_plugin(later_mutator.as_ref(), &mut plugin_view);

    let mut wire_trailers = backend_trailers;
    grpc_proxy::reconcile_grpc_trailers_from_view(
        &mut wire_trailers,
        &plugin_view,
        &backend_headers,
        &shadowed,
        Some(&policy_state),
    );
    let mut final_initial_headers = backend_headers;
    policy_state.apply_to_initial_headers(&mut final_initial_headers);
    assert_eq!(
        final_initial_headers.get("x-policy").map(String::as_str),
        Some("later-transformer"),
        "a later response-header mutator must retain priority over policy"
    );
    assert_eq!(
        wire_trailers.get("x-policy").map(String::as_str),
        Some("later-transformer"),
        "a later generic mutator still owns the application-trailer copy"
    );
}

#[test]
fn buffered_policy_state_tracks_mixed_case_later_mutation() {
    let policy: Arc<dyn Plugin> = Arc::new(
        SecurityHeaders::new(&json!({
            "set": { "X-Frame-Options": "DENY" }
        }))
        .unwrap(),
    );
    let initial_headers = HashMap::new();
    let mut plugin_view = HashMap::new();
    let mut policy_state = BufferedInitialResponseHeaderPolicyState::new(
        Arc::new(policy.initial_response_header_policy_names().to_vec()),
        &initial_headers,
        &plugin_view,
    )
    .unwrap();

    policy.apply_initial_response_header_policy(&mut plugin_view);
    policy_state.record_after_proxy_plugin(policy.as_ref(), &mut plugin_view);
    plugin_view.insert("X-Frame-Options".to_string(), "later-plugin".to_string());
    policy_state.record_later_response_header_mutations(&mut plugin_view);

    assert_eq!(
        plugin_view.get("x-frame-options").map(String::as_str),
        Some("later-plugin")
    );
    assert_eq!(
        plugin_view
            .keys()
            .filter(|name| name.eq_ignore_ascii_case("x-frame-options"))
            .count(),
        1,
        "later mixed-case mutations must be canonicalized without duplicates"
    );

    let mut final_initial_headers = HashMap::from([(
        "X-Frame-Options".to_string(),
        "stale-mixed-case".to_string(),
    )]);
    policy_state.apply_to_initial_headers(&mut final_initial_headers);
    assert_eq!(
        final_initial_headers
            .get("x-frame-options")
            .map(String::as_str),
        Some("later-plugin")
    );
    assert_eq!(
        final_initial_headers
            .keys()
            .filter(|name| name.eq_ignore_ascii_case("x-frame-options"))
            .count(),
        1
    );
}

#[test]
fn buffered_policy_state_preserves_body_transform_validator_removal() {
    let policy: Arc<dyn Plugin> = Arc::new(
        SecurityHeaders::new(&json!({
            "set": { "ETag": "\"gateway-policy\"" }
        }))
        .unwrap(),
    );
    let initial_headers = HashMap::new();
    let mut plugin_view = HashMap::new();
    let mut policy_state = BufferedInitialResponseHeaderPolicyState::new(
        Arc::new(policy.initial_response_header_policy_names().to_vec()),
        &initial_headers,
        &plugin_view,
    )
    .unwrap();

    policy.apply_initial_response_header_policy(&mut plugin_view);
    policy_state.record_after_proxy_plugin(policy.as_ref(), &mut plugin_view);
    assert_eq!(
        plugin_view.get("etag").map(String::as_str),
        Some("\"gateway-policy\"")
    );

    plugin_view.remove("etag");
    policy_state.record_later_response_header_mutations(&mut plugin_view);
    let mut initial_headers = HashMap::new();
    policy_state.apply_to_initial_headers(&mut initial_headers);

    assert!(
        !initial_headers.contains_key("etag"),
        "a body transform must be able to remove a stale policy-owned validator"
    );
}

/// Drive the production ordering of the buffered gRPC rewrite phase for a
/// policy-owned header whose name the backend supplied ONLY as an application
/// trailer. Recording later mutations must happen before the stale
/// compatibility-view trailer is retired; the reverse order makes the discard
/// look like an intentional later removal and silently drops the gateway value.
#[test]
fn policy_header_survives_trailer_retirement_after_body_rewrite() {
    let policy: Arc<dyn Plugin> = Arc::new(
        SecurityHeaders::new(&json!({
            "set": { "X-Security-Policy": "gateway-enforced" }
        }))
        .unwrap(),
    );
    let backend_headers = HashMap::new();
    let mut wire_trailers = grpc_map(&[
        ("x-security-policy", "backend-trailer-value"),
        ("grpc-status", "0"),
    ]);
    let (mut plugin_view, shadowed) =
        grpc_proxy::build_grpc_plugin_header_view(&backend_headers, &wire_trailers);
    assert_eq!(
        plugin_view.get("x-security-policy").map(String::as_str),
        Some("backend-trailer-value"),
        "a trailer-only key is merged into the buffered hook view"
    );

    let mut policy_state = BufferedInitialResponseHeaderPolicyState::new(
        Arc::new(policy.initial_response_header_policy_names().to_vec()),
        &backend_headers,
        &plugin_view,
    )
    .unwrap();
    policy.apply_initial_response_header_policy(&mut plugin_view);
    policy_state.record_after_proxy_plugin(policy.as_ref(), &mut plugin_view);

    // Production ordering: record genuine transform edits, then retire the
    // stale compatibility-view trailer copies.
    policy_state.record_later_response_header_mutations(&mut plugin_view);
    grpc_proxy::discard_grpc_application_trailers_after_body_rewrite(
        &mut plugin_view,
        &mut wire_trailers,
        &shadowed,
    );

    let mut final_initial_headers = backend_headers.clone();
    policy_state.apply_to_initial_headers(&mut final_initial_headers);
    assert_eq!(
        final_initial_headers
            .get("x-security-policy")
            .map(String::as_str),
        Some("gateway-enforced"),
        "the configured policy value must remain in initial HEADERS even when \
         the backend supplied the same name only as an application trailer"
    );
    assert!(
        !wire_trailers.contains_key("x-security-policy"),
        "the stale application-trailer copy must still be retired"
    );
    assert_eq!(
        wire_trailers.get("grpc-status").map(String::as_str),
        Some("0"),
        "reserved terminal metadata stays on the terminal channel"
    );
}

/// The ordering fix must not resurrect a header a body transform genuinely
/// removed, even when the backend also sent that name as an application trailer.
#[test]
fn body_transform_removal_beats_policy_when_backend_sent_a_trailer_copy() {
    let policy: Arc<dyn Plugin> = Arc::new(
        SecurityHeaders::new(&json!({
            "set": { "X-Security-Policy": "gateway-enforced" }
        }))
        .unwrap(),
    );
    let backend_headers = HashMap::new();
    let mut wire_trailers = grpc_map(&[("x-security-policy", "backend-trailer-value")]);
    let (mut plugin_view, shadowed) =
        grpc_proxy::build_grpc_plugin_header_view(&backend_headers, &wire_trailers);

    let mut policy_state = BufferedInitialResponseHeaderPolicyState::new(
        Arc::new(policy.initial_response_header_policy_names().to_vec()),
        &backend_headers,
        &plugin_view,
    )
    .unwrap();
    policy.apply_initial_response_header_policy(&mut plugin_view);
    policy_state.record_after_proxy_plugin(policy.as_ref(), &mut plugin_view);

    // A body transform intentionally drops the policy-owned header.
    plugin_view.remove("x-security-policy");
    policy_state.record_later_response_header_mutations(&mut plugin_view);
    grpc_proxy::discard_grpc_application_trailers_after_body_rewrite(
        &mut plugin_view,
        &mut wire_trailers,
        &shadowed,
    );

    let mut final_initial_headers = backend_headers.clone();
    policy_state.apply_to_initial_headers(&mut final_initial_headers);
    assert!(
        !final_initial_headers.contains_key("x-security-policy"),
        "an intentional later removal stays authoritative and is not restored"
    );
    assert!(
        !wire_trailers.contains_key("x-security-policy"),
        "the application-trailer copy is retired alongside the removal"
    );
}

#[test]
fn buffered_policy_overlay_preserves_transform_owned_content_length() {
    let policy: Arc<dyn Plugin> = Arc::new(
        SecurityHeaders::new(&json!({
            "set": {
                "Content-Length": "1",
                "X-Policy": "gateway-policy"
            }
        }))
        .unwrap(),
    );
    let initial_headers = HashMap::new();
    let mut merged_headers = HashMap::new();
    let mut policy_state = BufferedInitialResponseHeaderPolicyState::new(
        Arc::new(policy.initial_response_header_policy_names().to_vec()),
        &initial_headers,
        &merged_headers,
    )
    .unwrap();
    policy.apply_initial_response_header_policy(&mut merged_headers);
    policy_state.record_after_proxy_plugin(policy.as_ref(), &mut merged_headers);

    let mut transformed_headers = grpc_map(&[("content-length", "73")]);
    grpc_proxy::apply_buffered_grpc_initial_response_policy(
        Some(&policy_state),
        &mut transformed_headers,
        None,
    );
    assert_eq!(
        transformed_headers
            .get("content-length")
            .map(String::as_str),
        Some("73")
    );
    assert_eq!(
        transformed_headers.get("x-policy").map(String::as_str),
        Some("gateway-policy")
    );

    let mut absent_content_length = HashMap::new();
    grpc_proxy::apply_buffered_grpc_initial_response_policy(
        Some(&policy_state),
        &mut absent_content_length,
        None,
    );
    assert!(!absent_content_length.contains_key("content-length"));
}

#[test]
fn buffered_policy_restores_pristine_terminal_metadata_for_true_trailers_only_shape() {
    let terminal_headers = grpc_map(&[
        ("content-type", "application/grpc"),
        ("grpc-status", "7"),
        ("grpc-message", "permission denied"),
    ]);
    let terminal_snapshot =
        grpc_proxy::GrpcTerminalMetadataSnapshot::from_headers(&terminal_headers);

    let mut split_initial_headers = terminal_headers.clone();
    grpc_proxy::apply_buffered_grpc_initial_response_policy(None, &mut split_initial_headers, None);
    assert!(!split_initial_headers.contains_key("grpc-status"));
    assert!(!split_initial_headers.contains_key("grpc-message"));

    let hostile_set: Arc<dyn Plugin> = Arc::new(
        SecurityHeaders::new(&json!({
            "set": {
                "Grpc-Status": "0",
                "Grpc-Message": "policy override"
            },
            "remove": []
        }))
        .unwrap(),
    );
    let mut trailers_only_initial_headers = terminal_headers.clone();
    hostile_set.apply_initial_response_header_policy(&mut trailers_only_initial_headers);
    grpc_proxy::apply_buffered_grpc_initial_response_policy(
        None,
        &mut trailers_only_initial_headers,
        Some(&terminal_snapshot),
    );
    assert_eq!(
        trailers_only_initial_headers
            .get("grpc-status")
            .map(String::as_str),
        Some("7")
    );
    assert_eq!(
        trailers_only_initial_headers
            .get("grpc-message")
            .map(String::as_str),
        Some("permission denied")
    );

    let hostile_remove: Arc<dyn Plugin> = Arc::new(
        SecurityHeaders::new(&json!({
            "set": {},
            "remove": ["Grpc-Status", "Grpc-Message"]
        }))
        .unwrap(),
    );
    let mut removed_trailers_only_initial_headers = terminal_headers;
    hostile_remove.apply_initial_response_header_policy(&mut removed_trailers_only_initial_headers);
    grpc_proxy::apply_buffered_grpc_initial_response_policy(
        None,
        &mut removed_trailers_only_initial_headers,
        Some(&terminal_snapshot),
    );
    assert_eq!(
        removed_trailers_only_initial_headers
            .get("grpc-status")
            .map(String::as_str),
        Some("7")
    );
    assert_eq!(
        removed_trailers_only_initial_headers
            .get("grpc-message")
            .map(String::as_str),
        Some("permission denied")
    );
}

#[tokio::test]
async fn trailers_only_collapse_enforces_policy_and_preserves_terminal_metadata() {
    let backend_headers = grpc_map(&[("content-type", "application/grpc")]);
    let backend_trailers = grpc_map(&[
        ("grpc-status", "0"),
        ("grpc-message", "OK"),
        ("x-policy", "backend-trailer-value"),
        ("x-application-trailer", "application-value"),
        ("x-removed-trailer", "remove-me"),
        ("content-length", "999"),
    ]);
    let (mut plugin_view, shadowed) =
        grpc_proxy::build_grpc_plugin_header_view(&backend_headers, &backend_trailers);
    let policy: Arc<dyn Plugin> = Arc::new(
        SecurityHeaders::new(&json!({
            "override_existing": false,
            "set": {
                "X-Policy": "gateway-enforced",
                "Grpc-Status": "13"
            },
            "remove": ["X-Removed-Trailer"]
        }))
        .unwrap(),
    );
    let mut policy_state = BufferedInitialResponseHeaderPolicyState::new(
        Arc::new(policy.initial_response_header_policy_names().to_vec()),
        &backend_headers,
        &plugin_view,
    )
    .unwrap();
    let mut ctx = RequestContext::new("203.0.113.10".into(), "POST".into(), "/svc".into());
    let _ = policy.after_proxy(&mut ctx, 200, &mut plugin_view).await;
    policy_state.record_after_proxy_plugin(policy.as_ref(), &mut plugin_view);

    let mut wire_trailers = backend_trailers;
    grpc_proxy::reconcile_grpc_trailers_from_view(
        &mut wire_trailers,
        &plugin_view,
        &backend_headers,
        &shadowed,
        Some(&policy_state),
    );
    grpc_proxy::collapse_grpc_trailers_only_with_initial_response_policies(
        &mut plugin_view,
        &mut wire_trailers,
        &shadowed,
        Some(&policy_state),
        None,
    );

    assert!(wire_trailers.is_empty());
    assert_eq!(
        plugin_view.get("x-policy").map(String::as_str),
        Some("gateway-enforced")
    );
    assert_eq!(
        plugin_view.get("x-application-trailer").map(String::as_str),
        Some("application-value")
    );
    assert!(!plugin_view.contains_key("x-removed-trailer"));
    assert!(!plugin_view.contains_key("content-length"));
    assert_eq!(
        plugin_view.get("grpc-status").map(String::as_str),
        Some("0")
    );
    assert_eq!(
        plugin_view.get("grpc-message").map(String::as_str),
        Some("OK")
    );
}

// ── GrpcBody::Channel (H3 cross-protocol streaming request body) ──────────────
//
// `GrpcBody::Channel` is the body the HTTP/3 → non-H3 gRPC bridge hands to the
// gRPC pool: a pump task feeds request DATA frames (or `Err(())` on a frontend
// upload failure) into the channel, and hyper drives the upload by polling this
// body in the background. These tests exercise the body directly — proving
// frames flow incrementally (not buffered), the size limit is enforced
// incrementally, and a frontend error becomes a body error (backend RST) rather
// than a clean END_STREAM the backend would mistake for a completed request.

fn grpc_channel_body(
    max_bytes: usize,
) -> (
    tokio::sync::mpsc::Sender<Result<bytes::Bytes, ()>>,
    grpc_proxy::GrpcBody,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    let (tx, receiver) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, ()>>(8);
    let exceeded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let body = grpc_proxy::GrpcBody::Channel {
        receiver,
        bytes_seen: 0,
        max_bytes,
        exceeded: std::sync::Arc::clone(&exceeded),
        upload_observer: None,
    };
    (tx, body, exceeded)
}

#[tokio::test]
async fn grpc_channel_body_forwards_frames_in_order_then_clean_eof() {
    use http_body_util::BodyExt;
    use std::sync::atomic::Ordering;

    let (tx, body, exceeded) = grpc_channel_body(0); // 0 = unlimited
    let pump = tokio::spawn(async move {
        tx.send(Ok(bytes::Bytes::from_static(b"msg1")))
            .await
            .unwrap();
        tx.send(Ok(bytes::Bytes::from_static(b"msg2")))
            .await
            .unwrap();
        // Drop `tx` → channel closes → body observes a clean END_STREAM.
    });
    let collected = body
        .collect()
        .await
        .expect("clean-EOF channel body must complete without error")
        .to_bytes();
    pump.await.unwrap();
    // Frames are concatenated in send order — the body forwards them as they
    // arrive rather than reordering or buffering past the channel capacity.
    assert_eq!(&collected[..], b"msg1msg2");
    assert!(
        !exceeded.load(Ordering::Relaxed),
        "size flag must stay clear when no limit is configured"
    );
}

#[tokio::test]
async fn grpc_channel_body_enforces_size_limit_incrementally() {
    use http_body_util::BodyExt;
    use std::sync::atomic::Ordering;

    // 4-byte ceiling: the first 3-byte frame is under the limit; the second
    // pushes the running total to 6 and must trip the limit *mid-stream* (not
    // only after the whole body is collected).
    let (tx, body, exceeded) = grpc_channel_body(4);
    let pump = tokio::spawn(async move {
        let _ = tx.send(Ok(bytes::Bytes::from_static(b"abc"))).await;
        let _ = tx.send(Ok(bytes::Bytes::from_static(b"def"))).await;
        let _ = tx.send(Ok(bytes::Bytes::from_static(b"ghi"))).await;
    });
    let result = body.collect().await;
    let _ = pump.await;
    assert!(
        result.is_err(),
        "body must error once the running byte count exceeds max_bytes"
    );
    assert!(
        exceeded.load(Ordering::Acquire),
        "overflow must set the shared `exceeded` flag so the dispatcher can map it to RESOURCE_EXHAUSTED"
    );
}

#[tokio::test]
async fn grpc_channel_body_propagates_frontend_error_as_body_error() {
    use http_body_util::BodyExt;
    use std::sync::atomic::Ordering;

    let (tx, body, exceeded) = grpc_channel_body(0);
    let pump = tokio::spawn(async move {
        let _ = tx.send(Ok(bytes::Bytes::from_static(b"partial"))).await;
        // Frontend (H3 recv) failure: the pump signals abort with `Err(())`.
        let _ = tx.send(Err(())).await;
    });
    let result = body.collect().await;
    let _ = pump.await;
    assert!(
        result.is_err(),
        "a frontend upload failure must surface as a body error (backend RST), \
         never a clean END_STREAM the backend would treat as a completed request"
    );
    assert!(
        !exceeded.load(Ordering::Relaxed),
        "a transport-level abort is not a size violation"
    );
}

// ── gRPC mesh-transport dispatch classification (issue #2003) ───────────────
//
// The direct-dial gRPC pool must NEVER dispatch a mesh-transport-tagged target
// (silent SVID-mTLS/HBONE bypass — unauthenticated under PERMISSIVE
// PeerAuthentication). `classify_grpc_mesh_dispatch` is the single predicate
// every gRPC dispatch surface (H1/H2 branch, its retry rotation, the H3
// bridge) consults; these tests pin the classification matrix.

fn target_with_tags(tags: &[(&str, &str)]) -> ferrum_edge::config::types::UpstreamTarget {
    ferrum_edge::config::types::UpstreamTarget {
        host: "orders.default.svc.cluster.local".to_string(),
        port: 8080,
        service_port_policy_key: None,
        weight: 100,
        tags: tags
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
        locality: None,
        path: None,
    }
}

#[test]
fn grpc_mesh_dispatch_untagged_target_is_direct() {
    use grpc_proxy::{GrpcMeshDispatch, classify_grpc_mesh_dispatch};
    assert_eq!(
        classify_grpc_mesh_dispatch(&target_with_tags(&[])),
        GrpcMeshDispatch::Direct,
        "a target without mesh transport tags keeps the direct gRPC pool dial"
    );
    // Unrelated tags must not trip the mesh classification.
    assert_eq!(
        classify_grpc_mesh_dispatch(&target_with_tags(&[("subset", "v2")])),
        GrpcMeshDispatch::Direct
    );
    // A boolish-false transport tag is NOT mesh-tagged.
    assert_eq!(
        classify_grpc_mesh_dispatch(&target_with_tags(&[(
            ferrum_edge::proxy::mesh_mtls_pool::MESH_MTLS_TARGET_TAG,
            "false"
        )])),
        GrpcMeshDispatch::Direct
    );
}

#[test]
fn grpc_mesh_dispatch_same_cluster_mtls_routes_over_mesh_mtls() {
    use grpc_proxy::{GrpcMeshDispatch, classify_grpc_mesh_dispatch};
    let target = target_with_tags(&[
        (
            ferrum_edge::proxy::mesh_mtls_pool::MESH_MTLS_TARGET_TAG,
            "true",
        ),
        (
            ferrum_edge::proxy::hbone_pool::MESH_SPIFFE_ID_TAG,
            "spiffe://cluster.local/ns/default/sa/orders",
        ),
    ]);
    assert_eq!(
        classify_grpc_mesh_dispatch(&target),
        GrpcMeshDispatch::MeshMtls,
        "same-cluster Sidecar mesh-mTLS targets dispatch over the SVID-mTLS H2 pool"
    );
}

#[test]
fn grpc_mesh_dispatch_same_cluster_hbone_is_out_of_scope_and_fails_closed() {
    use grpc_proxy::{GrpcMeshDispatch, classify_grpc_mesh_dispatch};
    let target = target_with_tags(&[(ferrum_edge::proxy::hbone_pool::HBONE_TARGET_TAG, "true")]);
    assert_eq!(
        classify_grpc_mesh_dispatch(&target),
        GrpcMeshDispatch::RefuseHbone,
        "Ambient native gRPC over HBONE is out of scope: the inner protocol is HTTP/1.1 and cannot carry gRPC trailers — refuse, never dial"
    );
}

#[test]
fn grpc_mesh_dispatch_cross_cluster_sidecar_mtls_wellformed_routes_over_mesh_mtls() {
    use grpc_proxy::{GrpcMeshDispatch, classify_grpc_mesh_dispatch};
    // A WELL-FORMED cross-cluster Sidecar mesh-mTLS target (transport tag +
    // cross-cluster marker + destination-FQDN SNI override + remote trust
    // domain) now rides the mesh-mTLS pool's cross-cluster east-west branch
    // (issue #2010) — the same transport the HTTP family already uses.
    let target = target_with_tags(&[
        (
            ferrum_edge::proxy::mesh_mtls_pool::MESH_MTLS_TARGET_TAG,
            "true",
        ),
        (
            ferrum_edge::proxy::mesh_mtls_pool::MESH_CROSS_CLUSTER_TAG,
            "true",
        ),
        (
            ferrum_edge::proxy::mesh_mtls_pool::MESH_EASTWEST_SNI_TAG,
            "svc-c.ferrum.svc.cluster.local",
        ),
        (
            ferrum_edge::proxy::mesh_mtls_pool::MESH_TRUST_DOMAIN_TAG,
            "cluster-b.local",
        ),
    ]);
    assert_eq!(
        classify_grpc_mesh_dispatch(&target),
        GrpcMeshDispatch::MeshMtlsCrossCluster,
        "cross-cluster Sidecar mesh-mTLS gRPC routes over the east-west mesh-mTLS branch"
    );
}

#[test]
fn grpc_mesh_dispatch_cross_cluster_ambient_hbone_fails_closed() {
    use grpc_proxy::{GrpcMeshDispatch, classify_grpc_mesh_dispatch};
    // Ambient HBONE cross-cluster gRPC stays fail-closed: the HBONE inner
    // protocol is HTTP/1.1 and cannot carry gRPC trailers, cross-cluster or not.
    let hbone_xc = target_with_tags(&[
        (ferrum_edge::proxy::hbone_pool::HBONE_TARGET_TAG, "true"),
        (
            ferrum_edge::proxy::mesh_mtls_pool::MESH_CROSS_CLUSTER_TAG,
            "true",
        ),
    ]);
    assert_eq!(
        classify_grpc_mesh_dispatch(&hbone_xc),
        GrpcMeshDispatch::RefuseCrossCluster,
        "cross-cluster Ambient HBONE gRPC must fail closed (HBONE has no trailer path)"
    );
}

#[test]
fn grpc_mesh_dispatch_cross_cluster_sidecar_mtls_missing_metadata_fails_closed() {
    use grpc_proxy::{GrpcMeshDispatch, classify_grpc_mesh_dispatch};
    let mtls = ferrum_edge::proxy::mesh_mtls_pool::MESH_MTLS_TARGET_TAG;
    let xc = ferrum_edge::proxy::mesh_mtls_pool::MESH_CROSS_CLUSTER_TAG;
    let sni = ferrum_edge::proxy::mesh_mtls_pool::MESH_EASTWEST_SNI_TAG;
    let td = ferrum_edge::proxy::mesh_mtls_pool::MESH_TRUST_DOMAIN_TAG;
    // Cross-cluster mesh-mTLS transport tag present but the dial metadata is
    // incomplete — refuse cleanly instead of reaching a 502 at dispatch.
    // Neither SNI nor trust domain.
    assert_eq!(
        classify_grpc_mesh_dispatch(&target_with_tags(&[(mtls, "true"), (xc, "true")])),
        GrpcMeshDispatch::RefuseCrossClusterMalformed
    );
    // SNI present, trust domain missing.
    assert_eq!(
        classify_grpc_mesh_dispatch(&target_with_tags(&[
            (mtls, "true"),
            (xc, "true"),
            (sni, "svc-c.ferrum.svc.cluster.local"),
        ])),
        GrpcMeshDispatch::RefuseCrossClusterMalformed
    );
    // Trust domain present, SNI missing.
    assert_eq!(
        classify_grpc_mesh_dispatch(&target_with_tags(&[
            (mtls, "true"),
            (xc, "true"),
            (td, "cluster-b.local"),
        ])),
        GrpcMeshDispatch::RefuseCrossClusterMalformed
    );
    // Empty SNI is treated as absent — never dial the gateway address as SNI.
    assert_eq!(
        classify_grpc_mesh_dispatch(&target_with_tags(&[
            (mtls, "true"),
            (xc, "true"),
            (sni, ""),
            (td, "cluster-b.local"),
        ])),
        GrpcMeshDispatch::RefuseCrossClusterMalformed
    );
}

#[test]
fn grpc_mesh_dispatch_cross_cluster_conflicting_tags_take_the_hbone_refusal() {
    use grpc_proxy::{GrpcMeshDispatch, classify_grpc_mesh_dispatch};
    // A corrupted cross-cluster target carrying BOTH transport tags must never
    // fall through to the mesh-mTLS pool — HBONE wins as the stricter refusal
    // even when SNI/trust-domain would otherwise make the mTLS side well-formed.
    let both_xc = target_with_tags(&[
        (
            ferrum_edge::proxy::mesh_mtls_pool::MESH_MTLS_TARGET_TAG,
            "true",
        ),
        (ferrum_edge::proxy::hbone_pool::HBONE_TARGET_TAG, "true"),
        (
            ferrum_edge::proxy::mesh_mtls_pool::MESH_CROSS_CLUSTER_TAG,
            "true",
        ),
        (
            ferrum_edge::proxy::mesh_mtls_pool::MESH_EASTWEST_SNI_TAG,
            "svc-c.ferrum.svc.cluster.local",
        ),
        (
            ferrum_edge::proxy::mesh_mtls_pool::MESH_TRUST_DOMAIN_TAG,
            "cluster-b.local",
        ),
    ]);
    assert_eq!(
        classify_grpc_mesh_dispatch(&both_xc),
        GrpcMeshDispatch::RefuseCrossCluster
    );
}

#[test]
fn grpc_mesh_dispatch_conflicting_tags_take_the_stricter_refusal() {
    use grpc_proxy::{GrpcMeshDispatch, classify_grpc_mesh_dispatch};
    // Both transport tags on one target should not happen (topologies are
    // mutually exclusive), but if it does the target must NOT fall through to
    // the mesh-mTLS dispatch — HBONE wins as a refusal.
    let both = target_with_tags(&[
        (
            ferrum_edge::proxy::mesh_mtls_pool::MESH_MTLS_TARGET_TAG,
            "true",
        ),
        (ferrum_edge::proxy::hbone_pool::HBONE_TARGET_TAG, "true"),
    ]);
    assert_eq!(
        classify_grpc_mesh_dispatch(&both),
        GrpcMeshDispatch::RefuseHbone
    );
}

#[test]
fn grpc_mesh_dispatch_cross_cluster_tag_alone_still_refuses() {
    use grpc_proxy::{GrpcMeshDispatch, classify_grpc_mesh_dispatch};
    // `mesh.cross_cluster` without a transport tag is not a shape the
    // materializers produce, but the pre-existing gRPC guard refused it and
    // the classifier preserves that fail-closed posture (never direct-dial a
    // target that claims to be cross-cluster).
    let xc_only = target_with_tags(&[(
        ferrum_edge::proxy::mesh_mtls_pool::MESH_CROSS_CLUSTER_TAG,
        "true",
    )]);
    assert_eq!(
        classify_grpc_mesh_dispatch(&xc_only),
        GrpcMeshDispatch::RefuseCrossClusterNoTransport
    );
}

// ── Mesh-mTLS gRPC receive limit (issue #2003 codex r1-3) ──

#[test]
fn mesh_request_body_limit_selects_grpc_recv_limit_for_grpc_flavored_requests() {
    // gRPC-flavored uploads (native application/grpc or grpc_web-translated)
    // mirror the direct gRPC pool's receive limit; plain HTTP keeps the
    // general request-body limit. Defaults: 10 MiB HTTP vs 4 MiB gRPC — a
    // 6 MiB gRPC upload must trip the gRPC limit, not slip under the HTTP one.
    let http_limit = 10 * 1024 * 1024;
    let grpc_limit = 4 * 1024 * 1024;
    assert_eq!(
        grpc_proxy::mesh_request_body_limit(true, http_limit, grpc_limit),
        grpc_limit
    );
    assert_eq!(
        grpc_proxy::mesh_request_body_limit(false, http_limit, grpc_limit),
        http_limit
    );
}

#[test]
fn mesh_request_body_limit_zero_means_unlimited_per_knob_not_cross_inherited() {
    // `0` = unlimited for whichever knob is selected; the other knob's value
    // must never leak across flavors.
    assert_eq!(grpc_proxy::mesh_request_body_limit(true, 10, 0), 0);
    assert_eq!(grpc_proxy::mesh_request_body_limit(false, 0, 10), 0);
}

#[test]
fn grpc_request_body_too_large_backend_response_is_trailers_only_resource_exhausted() {
    use ferrum_edge::retry::{ErrorClass, ResponseBody};

    let max = 4 * 1024 * 1024;
    let resp = grpc_proxy::grpc_request_body_too_large_backend_response(
        "grpc-test",
        Some("10.0.0.9".to_string()),
        Some(6 * 1024 * 1024),
        max,
    );
    // Mirrors the direct gRPC pool's oversize rejection: gRPC errors ride
    // HTTP 200 with the outcome in grpc-status (8 = RESOURCE_EXHAUSTED).
    assert_eq!(resp.status_code, 200);
    assert_eq!(
        resp.headers.get("grpc-status").map(String::as_str),
        Some("8")
    );
    assert_eq!(
        resp.headers.get("content-type").map(String::as_str),
        Some("application/grpc")
    );
    let message = resp
        .headers
        .get("grpc-message")
        .expect("refusal must carry grpc-message");
    assert!(
        message.contains(&max.to_string()),
        "grpc-message should name the limit: {message}"
    );
    // RequestBodyTooLarge keeps backend-health accounting NEUTRAL (the
    // backend was never at fault) instead of banking the 200 as a success.
    assert_eq!(resp.error_class, Some(ErrorClass::RequestBodyTooLarge));
    assert!(!resp.connection_error);
    assert_eq!(resp.backend_resolved_ip.as_deref(), Some("10.0.0.9"));
    match resp.body {
        ResponseBody::Buffered(body) => {
            assert!(body.is_empty(), "Trailers-Only refusal carries no body")
        }
        _ => panic!("expected a buffered (empty, trailers-only) refusal body"),
    }
}

// ── gRPC mesh fall-through classifier (issue #2003 codex r2 finding 1) ──────
//
// Only PASS-THROUGH gRPC-Web may fall through the gRPC branch onto a
// refuse-classified mesh transport: gRPC-Web the `grpc_web` plugin TRANSLATED
// is wire-native gRPC by dispatch time, so riding the HBONE HTTP/1.1 inner
// tunnel (or the cross-cluster paths) would silently drop its trailers — it
// must fail closed inside the branch exactly like native gRPC.

#[test]
fn grpc_mesh_fall_through_allows_only_pass_through_grpc_web_on_refused_transports() {
    use grpc_proxy::{GrpcMeshDispatch, grpc_mesh_dispatch_falls_through};
    for refused in [
        GrpcMeshDispatch::RefuseHbone,
        GrpcMeshDispatch::RefuseCrossCluster,
    ] {
        // Pass-through gRPC-Web (no native content-type, no translation
        // marker): body-framed trailers ride the HTTP-family transport.
        assert!(
            grpc_mesh_dispatch_falls_through(refused, false, false, true),
            "pass-through gRPC-Web must keep riding {refused:?} like plain HTTP"
        );
        // Native gRPC: refuse in-branch (Trailers-Only UNAVAILABLE).
        assert!(
            !grpc_mesh_dispatch_falls_through(refused, true, false, true),
            "native gRPC must fail closed for {refused:?}"
        );
        // Translated gRPC-Web: outbound is wire-native gRPC — refuse
        // in-branch, never tunnel it as trailerless native gRPC.
        assert!(
            !grpc_mesh_dispatch_falls_through(refused, false, true, true),
            "grpc_web-translated requests must fail closed for {refused:?}"
        );
    }
    assert!(
        !grpc_mesh_dispatch_falls_through(
            GrpcMeshDispatch::RefuseCrossClusterNoTransport,
            false,
            false,
            true
        ),
        "a cross-cluster-only target has no mesh transport for pass-through gRPC-Web to use"
    );
    // A malformed cross-cluster Sidecar mesh-mTLS target (missing SNI/trust
    // domain) never falls through EITHER — even pass-through gRPC-Web would
    // fail closed at the mesh-mTLS dispatch, so refuse cleanly in-branch.
    for (native_ct, translated) in [(false, false), (true, false), (false, true)] {
        assert!(
            !grpc_mesh_dispatch_falls_through(
                GrpcMeshDispatch::RefuseCrossClusterMalformed,
                native_ct,
                translated,
                true
            ),
            "malformed cross-cluster mesh-mTLS must fail closed for \
             native_ct={native_ct} translated={translated}"
        );
    }
}

#[test]
fn grpc_mesh_fall_through_mesh_mtls_requires_streamable_request_body() {
    use grpc_proxy::{GrpcMeshDispatch, grpc_mesh_dispatch_falls_through};
    // Same-cluster AND cross-cluster Sidecar mesh-mTLS carry native gRPC
    // (streaming trailer relay) AND binary translated gRPC-Web (streaming
    // body-framed trailer conversion) down the generic mesh path when the
    // request body can stream — the cross-cluster variant rides the SAME pool's
    // east-west branch.
    for dispatch in [
        GrpcMeshDispatch::MeshMtls,
        GrpcMeshDispatch::MeshMtlsCrossCluster,
    ] {
        for (native_ct, translated) in [(true, false), (false, true), (false, false)] {
            assert!(
                grpc_mesh_dispatch_falls_through(dispatch, native_ct, translated, true),
                "{dispatch:?} must fall through for native_ct={native_ct} translated={translated}"
            );
            assert!(
                !grpc_mesh_dispatch_falls_through(
                    GrpcMeshDispatch::Direct,
                    native_ct,
                    translated,
                    true
                ),
                "Direct targets stay on the direct gRPC pool"
            );
        }
        assert!(
            !grpc_mesh_dispatch_falls_through(dispatch, false, true, false),
            "text-mode translated gRPC-Web still needs request-body buffering, which \
             mesh-mTLS dispatch refuses ({dispatch:?})"
        );
    }
}

// ── Streaming gRPC response timeout regime (codex r2 finding 6) ─────────────
//
// `grpc_streaming_response_deadline` is shared by the direct gRPC pool's
// streaming arm and the mesh-mTLS StreamingH2 relay: a client `grpc-timeout`
// becomes an ABSOLUTE deadline anchored at request receipt with the per-frame
// idle guard disabled; without one the operator read timeout applies per
// frame.

#[test]
fn grpc_streaming_response_deadline_reuses_typed_absolute_and_disables_per_frame() {
    let absolute = tokio::time::Instant::now() + std::time::Duration::from_secs(4);
    let (per_frame_ms, deadline) =
        grpc_proxy::grpc_streaming_response_deadline(Some(absolute), 30_000);
    assert_eq!(
        per_frame_ms, 0,
        "a client deadline replaces the per-frame idle regime"
    );
    assert_eq!(deadline, Some(absolute));
}

#[test]
fn grpc_streaming_response_deadline_preserves_already_elapsed_instant() {
    let expired = tokio::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(60))
        .expect("one minute before now is representable");
    let (per_frame_ms, deadline) =
        grpc_proxy::grpc_streaming_response_deadline(Some(expired), 30_000);
    assert_eq!(per_frame_ms, 0);
    assert_eq!(deadline, Some(expired));
}

#[test]
fn grpc_streaming_response_deadline_no_client_budget_falls_back_per_frame() {
    let (per_frame_ms, deadline) = grpc_proxy::grpc_streaming_response_deadline(None, 30_000);
    assert_eq!(
        per_frame_ms, 30_000,
        "without a client deadline the operator read timeout applies per frame"
    );
    assert!(deadline.is_none());
    // 0 + None (no client deadline, no operator fallback) = unbounded, for
    // long-lived server/bidi streams that legitimately idle.
    let (per_frame_ms, deadline) = grpc_proxy::grpc_streaming_response_deadline(None, 0);
    assert_eq!(per_frame_ms, 0);
    assert!(deadline.is_none());
}

#[test]
fn grpc_streaming_response_deadline_does_not_rearm_between_consumers() {
    let absolute = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    let (_, direct) = grpc_proxy::grpc_streaming_response_deadline(Some(absolute), 10_000);
    let (_, mesh) = grpc_proxy::grpc_streaming_response_deadline(Some(absolute), 20_000);
    assert_eq!(direct, mesh);
    assert_eq!(direct, Some(absolute));
}

// ── Mesh gRPC limit ordering (codex r2 finding 4) ───────────────────────────
//
// The dispatch-branch declared-Content-Length check must select the gRPC
// receive limit for gRPC-flavored requests BEFORE the generic HTTP check can
// fire, in BOTH orderings of the two knobs — the direct gRPC pool never
// applies `max_request_body_size_bytes` to a gRPC body.

#[test]
fn mesh_request_body_limit_grpc_flavor_wins_in_both_knob_orderings() {
    let two_mib = 2 * 1024 * 1024;
    let six_mib = 6 * 1024 * 1024;

    // HTTP limit (1 MiB) < gRPC limit (4 MiB): a 2 MiB gRPC body is IN
    // budget — the generic 413 must not fire early with the smaller limit.
    let http_limit = 1024 * 1024;
    let grpc_limit = 4 * 1024 * 1024;
    let selected = grpc_proxy::mesh_request_body_limit(true, http_limit, grpc_limit);
    assert_eq!(selected, grpc_limit);
    assert!(two_mib <= selected, "in-budget gRPC body must be admitted");
    assert!(six_mib > selected, "over-budget gRPC body must be rejected");

    // gRPC limit (4 MiB) < HTTP limit (10 MiB): a 6 MiB gRPC body must trip
    // the gRPC limit even though the HTTP limit would admit it.
    let http_limit = 10 * 1024 * 1024;
    let selected = grpc_proxy::mesh_request_body_limit(true, http_limit, grpc_limit);
    assert_eq!(selected, grpc_limit);
    assert!(six_mib > selected);
    // Plain HTTP keeps the general limit in both orderings.
    assert_eq!(
        grpc_proxy::mesh_request_body_limit(false, http_limit, grpc_limit),
        http_limit
    );
}

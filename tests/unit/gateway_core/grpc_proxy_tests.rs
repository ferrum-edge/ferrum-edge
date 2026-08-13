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
        backend_proxy_protocol: None,
        stream_match: None,
        compiled_stream_match: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        pending_limit_scope: None,
    }
}

fn headers_with_content_type(ct: &str) -> hyper::HeaderMap {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-type", ct.parse().unwrap());
    headers
}

/// Test-only initial-header policy used to exercise protocol boundary defenses
/// with names that production policy constructors reject at admission.
struct SyntheticInitialHeaderPolicy {
    names: Vec<String>,
    values: HashMap<String, String>,
}

impl SyntheticInitialHeaderPolicy {
    fn new(values: &[(&str, &str)]) -> Self {
        let values: HashMap<String, String> = values
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), (*value).to_string()))
            .collect();
        let names = values.keys().cloned().collect();
        Self { names, values }
    }
}

impl Plugin for SyntheticInitialHeaderPolicy {
    fn name(&self) -> &str {
        "synthetic_initial_header_policy"
    }

    fn is_initial_response_header_policy(&self) -> bool {
        true
    }

    fn apply_initial_response_header_policy(&self, response_headers: &mut HashMap<String, String>) {
        response_headers.extend(self.values.clone());
    }

    fn initial_response_header_policy_names(&self) -> &[String] {
        &self.names
    }
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
    // Every H3-to-gRPC dispatch path folds its prebuilt backend header map
    // through `merge_proxy_headers_for_prebuilt_h3_grpc`, which is the single
    // place the trusted assertion overlay is applied. Guard both halves of that
    // contract: one overlay site inside the shared helper, and no dispatch path
    // that builds its merge view without it.
    let production = source
        .split("#[cfg(test)]")
        .next()
        .expect("cross_protocol production source section");

    assert_eq!(
        helper
            .matches("trusted_plugin_assertion_proxy_headers(proxy_headers)")
            .count(),
        1,
        "the trusted assertion overlay must be applied in exactly one shared merge helper"
    );
    assert_eq!(
        production
            .matches("trusted_plugin_assertion_proxy_headers(proxy_headers)")
            .count(),
        1,
        "no H3-to-gRPC dispatch may apply the trusted assertion map outside the shared helper"
    );
    assert_eq!(
        production
            .matches("merge_proxy_headers_for_prebuilt_h3_grpc(&initial_hmap, proxy_headers)")
            .count(),
        1,
        "the buffered H3-to-gRPC dispatch must build its merge view through the shared helper"
    );
    assert_eq!(
        production
            .matches("merge_proxy_headers_for_prebuilt_h3_grpc(&hmap, proxy_headers)")
            .count(),
        2,
        "both streaming H3-to-gRPC dispatches must build their merge view through the shared helper"
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
        .find("transport.get_sender(proxy)")
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
fn h2c_settings_observer_preserves_vectored_writes() {
    let source = include_str!("../../../src/proxy/h2c_preface.rs");
    let start = source
        .find("impl<T: AsyncWrite + Unpin> AsyncWrite for H2cPrefaceIo<T>")
        .expect("H2cPrefaceIo AsyncWrite implementation not found");
    let implementation = &source[start..];
    let end = implementation
        .find("\n}\n\n/// Why an h2c connection")
        .expect("H2cPrefaceIo AsyncWrite implementation end not found");
    let implementation = &implementation[..end];

    assert!(
        implementation.contains("fn poll_write_vectored(")
            && implementation.contains(".poll_write_vectored(cx, bufs)"),
        "the lifetime h2c wrapper must forward the inner transport's scatter/gather writes"
    );
    assert!(
        implementation.contains("fn is_write_vectored(&self)")
            && implementation.contains("self.inner.is_write_vectored()"),
        "the h2c wrapper must advertise the inner transport capability"
    );

    assert!(
        source.contains("fn initial_settings_header_is_well_formed(&self)")
            && source.contains("self.first_frame_header[4] & 0x1 == 0")
            && source.contains("stream_id == 0")
            && source.contains("payload_len <= DEFAULT_MAX_FRAME_SIZE")
            && source.contains("payload_len % 6 == 0"),
        "raw readiness must reject an ACK, nonzero stream, oversized frame, or malformed SETTINGS payload"
    );
    assert!(
        source.contains("let post_observation = std::future::poll_fn(|cx|")
            && source.contains("Pin::new(&mut *conn).poll(cx)"),
        "Hyper must receive one post-observation poll so a protocol error wins the readiness race"
    );

    // Both h2c transports must establish through the shared observer: hyper's
    // client handshake proves only the client half, so a second, private
    // implementation is exactly the drift this guard exists to prevent.
    for consumer in [
        include_str!("../../../src/proxy/grpc_proxy.rs"),
        include_str!("../../../src/proxy/unix_backend.rs"),
    ] {
        assert!(
            consumer.contains("await_peer_settings("),
            "every h2c transport must gate its sender on the observed peer preface"
        );
    }
}

/// The NESTED HTTP/2 connection the Ambient HBONE gRPC transport runs inside its
/// CONNECT byte tunnel is cleartext h2c to the destination app, so it needs the
/// SAME peer-preface admission the direct-dial h2c pool applies (issue #3284).
///
/// hyper's handshake resolves as soon as the CLIENT preface is written, and the
/// outer CONNECT only proves the destination's relay reached the app socket —
/// so without this an app that is not an HTTP/2 server looks like an established
/// sender (and misclassifies as something other than an h2c handshake failure),
/// and an app that answers nothing stalls the RPC past the connect budget.
#[test]
fn nested_hbone_grpc_transport_awaits_the_destination_apps_h2c_preface() {
    let source = include_str!("../../../src/proxy/grpc_proxy.rs");
    let start = source
        .find("async fn open_hbone_grpc_sender(")
        .expect("the Ambient HBONE gRPC sender must exist");
    let body = &source[start..];
    let end = body
        .find("\n}\n")
        .expect("the Ambient HBONE gRPC sender must terminate");
    let body = &body[..end];

    // The observer lives in the shared `proxy::h2c_preface` module (issue
    // #3261 extracted it so the Unix h2c transport reuses one implementation),
    // so match the shared type rather than a module-private copy.
    let observer_at = body
        .find("h2c_preface::H2cPrefaceIo::new(")
        .expect("the nested HTTP/2 client must run over the shared h2c preface observer");
    let handshake_at = body
        .find("builder.handshake(io)")
        .expect("the nested HTTP/2 client must hand the wrapped IO to hyper's handshake");
    assert!(
        observer_at < handshake_at,
        "the CONNECT byte tunnel must be wrapped in the shared preface observer \
         before hyper's handshake, not handed over bare"
    );
    assert!(
        body[observer_at..handshake_at].contains("tunnel,"),
        "the observer must wrap the CONNECT byte tunnel itself, not another transport"
    );
    assert!(
        body.contains("await_peer_settings(&mut connection"),
        "the nested sender must be admitted only after the destination app's own \
         HTTP/2 connection preface"
    );
    assert_eq!(
        body.matches("GrpcBackendUnavailableKind::H2cHandshake")
            .count(),
        2,
        "both the client-side handshake failure and the peer-preface failure must \
         classify as an h2c handshake failure, never as an outer TLS/mesh failure"
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
    let policy: Arc<dyn Plugin> = Arc::new(SyntheticInitialHeaderPolicy::new(&[
        ("x-synthetic-policy", "enforced"),
        ("content-type", "text/plain"),
        ("content-length", "999"),
        ("transfer-encoding", "chunked"),
        ("grpc-status", "0"),
        ("grpc-message", "policy override"),
        ("grpc-status-details-bin", "hostile"),
    ]));

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
fn grpc_web_reject_finalizer_strips_connection_nominated_extensions() {
    let mut response = ferrum_edge::plugins::grpc_web::error_response_for_content_type(
        "application/grpc-web+proto",
        14,
        "backend unavailable",
    );
    let finalized_headers = HashMap::from([
        (
            "Connection".to_string(),
            "keep-alive, X-Policy-Hop".to_string(),
        ),
        ("X-Policy-Hop".to_string(), "must-not-leak".to_string()),
        ("x-end-to-end".to_string(), "preserved".to_string()),
    ]);

    ferrum_edge::_test_support::finalize_grpc_web_error_response_headers(
        &mut response,
        &[],
        Some(&finalized_headers),
    );

    for removed in ["connection", "keep-alive", "x-policy-hop"] {
        assert!(
            !response
                .headers
                .keys()
                .any(|name| name.eq_ignore_ascii_case(removed)),
            "{removed} crossed the generated gRPC-Web error boundary"
        );
    }
    assert_eq!(
        response.headers.get("x-end-to-end").map(String::as_str),
        Some("preserved")
    );
    let expected_content_length = response.body.len().to_string();
    assert_eq!(
        response.headers.get("content-length"),
        Some(&expected_content_length)
    );
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
        None,
        &proxy,
        "http://127.0.0.1:1/test.Service/Method",
        &grpc_proxy::GrpcDispatchTransport::Direct(&pool),
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
    let policy: Arc<dyn Plugin> = Arc::new(SyntheticInitialHeaderPolicy::new(&[
        ("content-length", "1"),
        ("x-policy", "gateway-policy"),
    ]));
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
// gRPC pool: a pump task feeds request DATA/trailer frames (or `Err(())` on a
// frontend upload failure) into the channel, and hyper drives the upload by
// polling this body in the background. These tests exercise the body directly —
// proving frames flow incrementally (not buffered), the size limit is enforced
// incrementally against DATA, trailers retain their frame boundary, and a
// frontend error becomes a body error (backend RST) rather than a clean
// END_STREAM the backend would mistake for a completed request.

/// Fixture returned by [`grpc_channel_body`]: pump sender, channel body under
/// test, size/cancellation signals, and backend-forwarded DATA accounting.
type GrpcChannelBodyFixture = (
    tokio::sync::mpsc::Sender<Result<http_body::Frame<bytes::Bytes>, ()>>,
    grpc_proxy::GrpcBody,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    std::sync::Arc<std::sync::atomic::AtomicU64>,
);

fn grpc_channel_body(max_bytes: usize) -> GrpcChannelBodyFixture {
    let (tx, receiver) =
        tokio::sync::mpsc::channel::<Result<http_body::Frame<bytes::Bytes>, ()>>(8);
    let exceeded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let forwarded = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let body = grpc_proxy::GrpcBody::Channel {
        receiver,
        bytes_seen: 0,
        max_bytes,
        exceeded: std::sync::Arc::clone(&exceeded),
        cancelled: std::sync::Arc::clone(&cancelled),
        cancelled_terminal: false,
        forwarded_bytes: std::sync::Arc::clone(&forwarded),
        upload_observer: None,
        grpc_messages: None,
        grpc_scanner: None,
    };
    (tx, body, exceeded, cancelled, forwarded)
}

#[tokio::test]
async fn grpc_channel_body_forwards_frames_in_order_then_clean_eof() {
    use http_body_util::BodyExt;
    use std::sync::atomic::Ordering;

    let (tx, body, exceeded, _cancelled, forwarded) = grpc_channel_body(0); // 0 = unlimited
    let pump = tokio::spawn(async move {
        tx.send(Ok(http_body::Frame::data(bytes::Bytes::from_static(
            b"msg1",
        ))))
        .await
        .unwrap();
        tx.send(Ok(http_body::Frame::data(bytes::Bytes::from_static(
            b"msg2",
        ))))
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
    assert_eq!(forwarded.load(Ordering::Relaxed), 8);
}

#[tokio::test]
async fn grpc_channel_body_enforces_size_limit_incrementally() {
    use http_body_util::BodyExt;
    use std::sync::atomic::Ordering;

    // 4-byte ceiling: the first 3-byte frame is under the limit; the second
    // pushes the running total to 6 and must trip the limit *mid-stream* (not
    // only after the whole body is collected).
    let (tx, body, exceeded, _cancelled, forwarded) = grpc_channel_body(4);
    let pump = tokio::spawn(async move {
        let _ = tx
            .send(Ok(http_body::Frame::data(bytes::Bytes::from_static(
                b"abc",
            ))))
            .await;
        let _ = tx
            .send(Ok(http_body::Frame::data(bytes::Bytes::from_static(
                b"def",
            ))))
            .await;
        let _ = tx
            .send(Ok(http_body::Frame::data(bytes::Bytes::from_static(
                b"ghi",
            ))))
            .await;
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
    assert_eq!(forwarded.load(Ordering::Relaxed), 3);
}

#[tokio::test]
async fn grpc_channel_body_propagates_frontend_error_as_body_error() {
    use http_body_util::BodyExt;
    use std::sync::atomic::Ordering;

    let (tx, body, exceeded, _cancelled, forwarded) = grpc_channel_body(0);
    let pump = tokio::spawn(async move {
        let _ = tx
            .send(Ok(http_body::Frame::data(bytes::Bytes::from_static(
                b"partial",
            ))))
            .await;
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
    assert_eq!(forwarded.load(Ordering::Relaxed), 7);
}

#[tokio::test]
async fn grpc_channel_body_forwards_request_trailers_after_data() {
    use http_body_util::BodyExt;

    let (tx, mut body, _exceeded, _cancelled, forwarded) = grpc_channel_body(64);
    let pump = tokio::spawn(async move {
        tx.send(Ok(http_body::Frame::data(bytes::Bytes::from_static(
            b"message",
        ))))
        .await
        .unwrap();
        let mut trailers = http::HeaderMap::new();
        trailers.insert(
            "x-request-checksum",
            http::HeaderValue::from_static("sha256:test"),
        );
        tx.send(Ok(http_body::Frame::trailers(trailers)))
            .await
            .unwrap();
    });

    let data = body
        .frame()
        .await
        .expect("data frame")
        .expect("data frame ok");
    assert_eq!(data.into_data().expect("DATA").as_ref(), b"message");
    let trailers = body
        .frame()
        .await
        .expect("trailers frame")
        .expect("trailers frame ok")
        .into_trailers()
        .expect("TRAILERS");
    assert_eq!(trailers.get("x-request-checksum").unwrap(), "sha256:test");
    assert!(
        body.frame().await.is_none(),
        "trailers must terminate the body"
    );
    assert_eq!(forwarded.load(std::sync::atomic::Ordering::Relaxed), 7);
    pump.await.unwrap();
}

#[tokio::test]
async fn grpc_channel_body_cancellation_preempts_queued_data_with_error() {
    use http_body_util::BodyExt;
    use std::sync::atomic::Ordering;

    let (tx, mut body, exceeded, cancelled, forwarded) = grpc_channel_body(64);
    tx.send(Ok(http_body::Frame::data(bytes::Bytes::from_static(
        b"must-not-cross-after-cancel",
    ))))
    .await
    .unwrap();
    cancelled.store(true, Ordering::Release);

    let error = body
        .frame()
        .await
        .expect("cancellation frame")
        .expect_err("cancellation must error the backend request body");
    assert!(
        error
            .to_string()
            .contains("cancelled before downstream EOF")
    );
    assert!(body.frame().await.is_none());
    assert!(!exceeded.load(Ordering::Acquire));
    assert_eq!(forwarded.load(Ordering::Relaxed), 0);
    drop(tx);
}

#[tokio::test]
async fn grpc_channel_body_cancellation_stays_terminal_after_a_pending_poll() {
    use http_body::Body;
    use http_body_util::BodyExt;
    use std::future::poll_fn;
    use std::sync::atomic::Ordering;
    use std::task::Poll;

    let (tx, mut body, exceeded, cancelled, forwarded) = grpc_channel_body(64);
    poll_fn(|cx| match std::pin::Pin::new(&mut body).poll_frame(cx) {
        Poll::Pending => Poll::Ready(()),
        Poll::Ready(frame) => panic!("empty open channel unexpectedly yielded {frame:?}"),
    })
    .await;

    cancelled.store(true, Ordering::Release);
    tx.send(Ok(http_body::Frame::data(bytes::Bytes::from_static(
        b"queued-after-pending",
    ))))
    .await
    .unwrap();

    let error = body
        .frame()
        .await
        .expect("cancellation frame")
        .expect_err("published cancellation must preempt newly queued data");
    assert!(
        error
            .to_string()
            .contains("cancelled before downstream EOF")
    );
    assert!(body.frame().await.is_none());
    assert!(!exceeded.load(Ordering::Acquire));
    assert_eq!(forwarded.load(Ordering::Relaxed), 0);
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
fn grpc_mesh_dispatch_same_cluster_hbone_classifies_for_transport_materialization() {
    use grpc_proxy::{GrpcMeshDispatch, classify_grpc_mesh_dispatch};
    let target = target_with_tags(&[(ferrum_edge::proxy::hbone_pool::HBONE_TARGET_TAG, "true")]);
    assert_eq!(
        classify_grpc_mesh_dispatch(&target),
        GrpcMeshDispatch::Hbone,
        "Ambient HBONE must resolve through the nested-HTTP/2 transport, never the direct pool"
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
fn grpc_mesh_dispatch_cross_cluster_ambient_hbone_classifies_for_east_west_transport() {
    use grpc_proxy::{GrpcMeshDispatch, classify_grpc_mesh_dispatch};
    // Cross-cluster Ambient HBONE uses the same nested h2c application
    // transport over the east-west CONNECT dial as its same-cluster sibling.
    let hbone_xc = target_with_tags(&[
        (ferrum_edge::proxy::hbone_pool::HBONE_TARGET_TAG, "true"),
        (
            ferrum_edge::proxy::mesh_mtls_pool::MESH_CROSS_CLUSTER_TAG,
            "true",
        ),
    ]);
    assert_eq!(
        classify_grpc_mesh_dispatch(&hbone_xc),
        GrpcMeshDispatch::HboneCrossCluster,
        "cross-cluster Ambient HBONE must resolve through its east-west nested-HTTP/2 transport"
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
        GrpcMeshDispatch::HboneCrossCluster
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
    assert_eq!(classify_grpc_mesh_dispatch(&both), GrpcMeshDispatch::Hbone);
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
    for refused in [GrpcMeshDispatch::Hbone, GrpcMeshDispatch::HboneCrossCluster] {
        // Pass-through gRPC-Web (no native content-type, no translation
        // marker): body-framed trailers ride the HTTP-family transport.
        assert!(
            grpc_mesh_dispatch_falls_through(refused, false, false),
            "pass-through gRPC-Web must keep riding {refused:?} like plain HTTP"
        );
        // Native gRPC: refuse in-branch (Trailers-Only UNAVAILABLE).
        assert!(
            !grpc_mesh_dispatch_falls_through(refused, true, false),
            "native gRPC must fail closed for {refused:?}"
        );
        // Translated gRPC-Web: outbound is wire-native gRPC — refuse
        // in-branch, never tunnel it as trailerless native gRPC.
        assert!(
            !grpc_mesh_dispatch_falls_through(refused, false, true),
            "grpc_web-translated requests must fail closed for {refused:?}"
        );
    }
    assert!(
        !grpc_mesh_dispatch_falls_through(
            GrpcMeshDispatch::RefuseCrossClusterNoTransport,
            false,
            false,
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
            ),
            "malformed cross-cluster mesh-mTLS must fail closed for \
             native_ct={native_ct} translated={translated}"
        );
    }
}

#[test]
fn grpc_mesh_fall_through_mesh_mtls_accepts_replayable_request_body() {
    use grpc_proxy::{GrpcMeshDispatch, grpc_mesh_dispatch_falls_through};
    // Same-cluster AND cross-cluster Sidecar mesh-mTLS carry native gRPC
    // (streaming trailer relay) AND binary translated gRPC-Web (streaming
    // body-framed trailer conversion) down the generic mesh path when the
    // request body streams or was finalized into replayable bytes — the
    // cross-cluster variant rides the SAME pool's east-west branch.
    for dispatch in [
        GrpcMeshDispatch::MeshMtls,
        GrpcMeshDispatch::MeshMtlsCrossCluster,
    ] {
        for (native_ct, translated) in [(true, false), (false, true), (false, false)] {
            assert!(
                grpc_mesh_dispatch_falls_through(dispatch, native_ct, translated),
                "{dispatch:?} must fall through for native_ct={native_ct} translated={translated}"
            );
            assert!(
                !grpc_mesh_dispatch_falls_through(GrpcMeshDispatch::Direct, native_ct, translated,),
                "Direct targets stay on the direct gRPC pool"
            );
        }
        assert!(grpc_mesh_dispatch_falls_through(dispatch, false, true));
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

// ── gRPC dispatch transport materialization (issue #3284) ───────────────────
//
// `classify_grpc_mesh_dispatch` says WHICH transport class a target belongs to;
// `GrpcDispatchTransport::for_target` is what every dispatch surface actually
// materializes from it. There is deliberately no "direct dial anyway" arm: a
// mesh-tagged target either resolves its authenticated transport or errors, so
// a resolution failure fails closed instead of silently bypassing SVID-mTLS,
// identity pinning, and mesh authz identity.

struct TransportTestPools {
    grpc: grpc_proxy::GrpcConnectionPool,
    mesh_mtls: ferrum_edge::proxy::mesh_mtls_pool::MeshMtlsConnectionPool,
    hbone: ferrum_edge::proxy::hbone_pool::HboneConnectionPool,
}

impl TransportTestPools {
    fn new() -> Self {
        let svid_slot = || std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None)));
        Self {
            grpc: grpc_proxy::GrpcConnectionPool::default(),
            mesh_mtls: ferrum_edge::proxy::mesh_mtls_pool::MeshMtlsConnectionPool::new(
                ferrum_edge::config::PoolConfig::default(),
                ferrum_edge::dns::DnsCache::new(ferrum_edge::dns::DnsConfig::default()),
                svid_slot(),
                8,
            ),
            hbone: ferrum_edge::proxy::hbone_pool::HboneConnectionPool::new(
                ferrum_edge::config::PoolConfig::default(),
                ferrum_edge::dns::DnsCache::new(ferrum_edge::dns::DnsConfig::default()),
                svid_slot(),
                8,
            ),
        }
    }

    /// One named lifetime ties the pools and the target together, because
    /// `for_target` borrows all four for the SAME lifetime as the transport it
    /// returns.
    fn resolve<'a>(
        &'a self,
        target: Option<&'a ferrum_edge::config::types::UpstreamTarget>,
    ) -> Result<grpc_proxy::GrpcDispatchTransport<'a>, grpc_proxy::GrpcTransportError> {
        grpc_proxy::GrpcDispatchTransport::for_target(
            &self.grpc,
            &self.mesh_mtls,
            &self.hbone,
            target,
        )
    }
}

#[tokio::test]
async fn grpc_transport_for_untagged_and_absent_targets_is_the_direct_pool() {
    let pools = TransportTestPools::new();
    let direct = pools
        .resolve(None)
        .expect("no selected target keeps the direct pool");
    assert_eq!(direct.label(), "direct");

    let untagged = target_with_tags(&[("subset", "v2")]);
    let direct = pools
        .resolve(Some(&untagged))
        .expect("an untagged target keeps the direct pool");
    assert_eq!(direct.label(), "direct");
}

/// A Sidecar `ingress[]` Unix-socket target must FAIL CLOSED here for BOTH
/// wire protocols (issue #3261 × #3284). `GrpcDispatchTransport` materializes
/// network transports only; a Unix target's `host:port` is a schema-only
/// loopback placeholder, so a `Direct` fallback would dial an unrelated
/// listener instead of the socket — the exact placeholder-TCP fallback the Unix
/// ingress work forbids. The supported h2c Unix dispatch is reached through the
/// generic HTTP-family path, which never routes through this resolver.
#[tokio::test]
async fn grpc_transport_for_unix_socket_targets_fails_closed_for_both_protocols() {
    let pools = TransportTestPools::new();
    let unix = ferrum_edge::proxy::unix_backend::MESH_UNIX_SOCKET_TAG;
    let h2c = ferrum_edge::proxy::unix_backend::MESH_UNIX_SOCKET_H2C_TAG;
    let secret_path = "/run/ferrum/tenant-a/app.sock";

    for (label, is_h2c) in [("h2c", "true"), ("http1", "false")] {
        let target = target_with_tags(&[(unix, secret_path), (h2c, is_h2c)]);
        let error = pools
            .resolve(Some(&target))
            .err()
            .expect("a unix-socket target must never materialize a network transport");
        assert!(
            matches!(error, grpc_proxy::GrpcTransportError::Unsupported { .. }),
            "{label}: a unix-socket target is unsupported here, not an identity failure"
        );
        assert_eq!(
            error.diagnostic(),
            grpc_proxy::GrpcTransportDiagnostic::MeshUnixSocket,
            "{label}: the diagnostic must name the unix transport tag"
        );
        assert!(
            !error.message().contains(secret_path)
                && !error.diagnostic().as_str().contains(secret_path),
            "{label}: neither the client message nor the diagnostic may echo the socket path"
        );
    }
}

#[tokio::test]
async fn grpc_transport_for_same_cluster_mesh_mtls_resolves_the_sidecar_transport() {
    let pools = TransportTestPools::new();
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
    let transport = pools
        .resolve(Some(&target))
        .expect("same-cluster mesh.mtls must resolve the SVID-mTLS transport");
    assert_eq!(
        transport.label(),
        "mesh_mtls",
        "a mesh.mtls target must never fall back to the direct-dial gRPC pool"
    );
}

#[tokio::test]
async fn grpc_transport_for_wellformed_cross_cluster_mesh_mtls_resolves_the_sidecar_transport() {
    let pools = TransportTestPools::new();
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
            "orders.default.svc.cluster.local",
        ),
        (
            ferrum_edge::proxy::mesh_mtls_pool::MESH_TRUST_DOMAIN_TAG,
            "remote.local",
        ),
    ]);
    let transport = pools
        .resolve(Some(&target))
        .expect("well-formed cross-cluster mesh.mtls rides the east-west branch");
    assert_eq!(transport.label(), "mesh_mtls");
}

// Issue #3284 requires BOTH mesh transports, same-cluster and cross-cluster.
// A `mesh.hbone` target must therefore resolve the nested-HTTP/2 HBONE
// transport, never the direct-dial pool and never a silent refusal.
#[tokio::test]
async fn grpc_transport_for_same_cluster_hbone_resolves_the_ambient_transport() {
    let pools = TransportTestPools::new();
    let target = target_with_tags(&[
        (ferrum_edge::proxy::hbone_pool::HBONE_TARGET_TAG, "true"),
        (
            ferrum_edge::proxy::hbone_pool::MESH_SPIFFE_ID_TAG,
            "spiffe://cluster.local/ns/default/sa/orders",
        ),
    ]);
    let transport = pools
        .resolve(Some(&target))
        .expect("same-cluster mesh.hbone must resolve the Ambient HBONE transport");
    assert_eq!(
        transport.label(),
        "hbone",
        "a mesh.hbone target must never fall back to the direct-dial gRPC pool"
    );
}

#[tokio::test]
async fn grpc_transport_for_wellformed_cross_cluster_hbone_resolves_the_ambient_transport() {
    let pools = TransportTestPools::new();
    let target = target_with_tags(&[
        (ferrum_edge::proxy::hbone_pool::HBONE_TARGET_TAG, "true"),
        (
            ferrum_edge::proxy::mesh_mtls_pool::MESH_CROSS_CLUSTER_TAG,
            "true",
        ),
        (
            ferrum_edge::proxy::mesh_mtls_pool::MESH_EASTWEST_SNI_TAG,
            "orders.default.svc.cluster.local",
        ),
        (
            ferrum_edge::proxy::mesh_mtls_pool::MESH_TRUST_DOMAIN_TAG,
            "remote.local",
        ),
        (
            ferrum_edge::proxy::hbone_pool::HBONE_DIAL_HOST_TAG,
            "10.9.0.7",
        ),
        (
            ferrum_edge::proxy::hbone_pool::HBONE_AUTHORITY_HOST_TAG,
            "10.244.3.9",
        ),
    ]);
    let transport = pools
        .resolve(Some(&target))
        .expect("well-formed cross-cluster mesh.hbone rides the east-west branch");
    assert_eq!(transport.label(), "hbone");
}

#[tokio::test]
async fn grpc_transport_for_mesh_mtls_without_a_pinned_peer_fails_closed() {
    let pools = TransportTestPools::new();
    // Same-cluster `mesh.mtls` REQUIRES a resolvable `mesh.spiffe_id` pin; a
    // corrupt one must refuse before any dial rather than downgrade to
    // trust-domain-only verification.
    for pin in ["", "not-a-spiffe-id"] {
        let target = target_with_tags(&[
            (
                ferrum_edge::proxy::mesh_mtls_pool::MESH_MTLS_TARGET_TAG,
                "true",
            ),
            (ferrum_edge::proxy::hbone_pool::MESH_SPIFFE_ID_TAG, pin),
        ]);
        let error = pools
            .resolve(Some(&target))
            .err()
            .unwrap_or_else(|| panic!("an unresolvable pinned peer ({pin:?}) must fail closed"));
        assert!(
            matches!(
                error,
                grpc_proxy::GrpcTransportError::UnmaterializableIdentity { .. }
            ),
            "expected an unmaterializable-identity refusal, got {error:?}"
        );
        assert_eq!(
            error.diagnostic(),
            grpc_proxy::GrpcTransportDiagnostic::MeshSpiffeId,
            "a missing/corrupt pin must name mesh.spiffe_id, not a collapsed generic"
        );
        assert_eq!(
            error.diagnostic().as_str(),
            "mesh.spiffe_id",
            "the redacted diagnostic label is the tag name only"
        );
        assert!(
            !error.message().contains(pin) || pin.is_empty(),
            "a refusal message must not echo the target's identity metadata"
        );
        let debug = format!("{error:?}");
        assert!(
            !debug.contains(pin) || pin.is_empty(),
            "Debug must not echo the raw pin either"
        );
    }
}

// A `mesh.hbone` target whose dial metadata is corrupt must fail closed at
// materialization, exactly like the mesh-mTLS arm — never dial the synthetic
// cross-cluster identity, never downgrade a corrupt pin to unpinned.
#[tokio::test]
async fn grpc_transport_for_hbone_with_unusable_dial_metadata_fails_closed() {
    let pools = TransportTestPools::new();
    let hbone = ferrum_edge::proxy::hbone_pool::HBONE_TARGET_TAG;
    let xc = ferrum_edge::proxy::mesh_mtls_pool::MESH_CROSS_CLUSTER_TAG;
    let sni = ferrum_edge::proxy::mesh_mtls_pool::MESH_EASTWEST_SNI_TAG;
    let secret_sni = "orders.internal.example.com";

    for (label, tags, expected) in [
        (
            "corrupt pinned peer",
            vec![
                (hbone, "true"),
                (
                    ferrum_edge::proxy::hbone_pool::MESH_SPIFFE_ID_TAG,
                    "not-a-spiffe-id",
                ),
            ],
            grpc_proxy::GrpcTransportDiagnostic::MeshSpiffeId,
        ),
        (
            "empty dial host override",
            vec![
                (hbone, "true"),
                (ferrum_edge::proxy::hbone_pool::HBONE_DIAL_HOST_TAG, " "),
            ],
            grpc_proxy::GrpcTransportDiagnostic::MeshHboneDialHost,
        ),
        (
            "empty CONNECT authority host override",
            vec![
                (hbone, "true"),
                (
                    ferrum_edge::proxy::hbone_pool::HBONE_AUTHORITY_HOST_TAG,
                    "  ",
                ),
            ],
            grpc_proxy::GrpcTransportDiagnostic::MeshHboneAuthorityHost,
        ),
        (
            "cross-cluster missing the CONNECT authority host",
            vec![
                (hbone, "true"),
                (xc, "true"),
                (sni, secret_sni),
                (
                    ferrum_edge::proxy::mesh_mtls_pool::MESH_TRUST_DOMAIN_TAG,
                    "remote.local",
                ),
            ],
            grpc_proxy::GrpcTransportDiagnostic::MeshHboneAuthorityHost,
        ),
        (
            "cross-cluster missing the remote trust domain",
            vec![
                (hbone, "true"),
                (xc, "true"),
                (sni, secret_sni),
                (
                    ferrum_edge::proxy::hbone_pool::HBONE_AUTHORITY_HOST_TAG,
                    "10.244.3.9",
                ),
            ],
            grpc_proxy::GrpcTransportDiagnostic::MeshTrustDomain,
        ),
        (
            "cross-cluster missing the destination SNI override",
            vec![
                (hbone, "true"),
                (xc, "true"),
                (
                    ferrum_edge::proxy::mesh_mtls_pool::MESH_TRUST_DOMAIN_TAG,
                    "remote.local",
                ),
                (
                    ferrum_edge::proxy::hbone_pool::HBONE_AUTHORITY_HOST_TAG,
                    "10.244.3.9",
                ),
            ],
            grpc_proxy::GrpcTransportDiagnostic::MeshEastwestSni,
        ),
    ] {
        let target = target_with_tags(&tags);
        let error = pools
            .resolve(Some(&target))
            .err()
            .unwrap_or_else(|| panic!("{label} must fail closed, never dial"));
        assert!(
            matches!(
                error,
                grpc_proxy::GrpcTransportError::UnmaterializableIdentity { .. }
            ),
            "{label}: expected an unmaterializable-identity refusal, got {error:?}"
        );
        assert_eq!(
            error.diagnostic(),
            expected,
            "{label}: diagnostic must name the failed mesh tag/contract"
        );
        assert!(
            !error.message().contains(secret_sni)
                && !error.message().contains("not-a-spiffe-id")
                && !error.message().contains("remote.local"),
            "{label}: a client-visible refusal must not leak the target's mesh metadata"
        );
        let debug = format!("{error:?}");
        assert!(
            !debug.contains(secret_sni)
                && !debug.contains("not-a-spiffe-id")
                && !debug.contains("remote.local"),
            "{label}: Debug must stay redacted of tag values"
        );
    }
}

#[tokio::test]
async fn grpc_transport_for_unsupported_mesh_classes_fails_closed_with_a_metadata_free_message() {
    let pools = TransportTestPools::new();
    let mtls = ferrum_edge::proxy::mesh_mtls_pool::MESH_MTLS_TARGET_TAG;
    let hbone = ferrum_edge::proxy::hbone_pool::HBONE_TARGET_TAG;
    let xc = ferrum_edge::proxy::mesh_mtls_pool::MESH_CROSS_CLUSTER_TAG;
    let sni = ferrum_edge::proxy::mesh_mtls_pool::MESH_EASTWEST_SNI_TAG;
    let secret_sni = "orders.internal.example.com";

    for (label, tags, expected) in [
        // Cross-cluster with NO transport tag at all: malformed.
        (
            "cross-cluster untagged",
            vec![(xc, "true")],
            grpc_proxy::GrpcTransportDiagnostic::CrossClusterMissingTransport,
        ),
        // Cross-cluster Sidecar mesh-mTLS missing its remote trust domain.
        (
            "cross-cluster mtls missing trust domain",
            vec![(mtls, "true"), (xc, "true"), (sni, secret_sni)],
            grpc_proxy::GrpcTransportDiagnostic::MeshTrustDomain,
        ),
        // Cross-cluster Sidecar mesh-mTLS missing its destination SNI.
        (
            "cross-cluster mtls missing SNI",
            vec![
                (mtls, "true"),
                (xc, "true"),
                (
                    ferrum_edge::proxy::mesh_mtls_pool::MESH_TRUST_DOMAIN_TAG,
                    "remote.local",
                ),
            ],
            grpc_proxy::GrpcTransportDiagnostic::MeshEastwestSni,
        ),
        // BOTH transport tags: the topologies are mutually exclusive, so this
        // is a corrupted target and picking either hop would be a guess.
        (
            "ambiguous same-cluster transport",
            vec![(mtls, "true"), (hbone, "true")],
            grpc_proxy::GrpcTransportDiagnostic::ConflictingMeshTransports,
        ),
        (
            "ambiguous cross-cluster transport",
            vec![(mtls, "true"), (hbone, "true"), (xc, "true")],
            grpc_proxy::GrpcTransportDiagnostic::ConflictingMeshTransports,
        ),
    ] {
        let target = target_with_tags(&tags);
        let error = pools
            .resolve(Some(&target))
            .err()
            .unwrap_or_else(|| panic!("{label} must fail closed, never direct-dial"));
        assert!(
            matches!(error, grpc_proxy::GrpcTransportError::Unsupported { .. }),
            "{label}: expected an unsupported-transport refusal, got {error:?}"
        );
        assert_eq!(
            error.diagnostic(),
            expected,
            "{label}: diagnostic must name the failed mesh tag/contract"
        );
        assert!(
            !error.message().contains(secret_sni)
                && !error.message().contains("orders.default.svc.cluster.local")
                && !error.message().contains("remote.local"),
            "{label}: a client-visible refusal must not leak the target's mesh metadata"
        );
        let debug = format!("{error:?}");
        assert!(
            !debug.contains(secret_sni) && !debug.contains("remote.local"),
            "{label}: Debug must stay redacted of tag values"
        );
    }
}

#[tokio::test]
async fn grpc_transport_diagnostic_labels_are_tag_names_never_values() {
    // Closed set of redacted labels: every category is either a mesh tag name
    // or a contract id. None may embed a sample secret from a refusal fixture.
    let secret_spiffe = "spiffe://cluster.local/ns/payments/sa/ledger";
    let secret_sni = "ledger.payments.svc.cluster.local";
    let secret_td = "payments.remote.local";
    let secret_host = "10.244.9.9";

    for category in [
        grpc_proxy::GrpcTransportDiagnostic::MeshSpiffeId,
        grpc_proxy::GrpcTransportDiagnostic::MeshHboneDialHost,
        grpc_proxy::GrpcTransportDiagnostic::MeshHboneAuthorityHost,
        grpc_proxy::GrpcTransportDiagnostic::MeshEastwestSni,
        grpc_proxy::GrpcTransportDiagnostic::MeshTrustDomain,
        grpc_proxy::GrpcTransportDiagnostic::ConflictingMeshTransports,
        grpc_proxy::GrpcTransportDiagnostic::CrossClusterMissingTransport,
        grpc_proxy::GrpcTransportDiagnostic::MeshUnixSocket,
    ] {
        let label = category.as_str();
        assert!(
            !label.is_empty() && !label.contains(secret_spiffe) && !label.contains(secret_sni),
            "diagnostic label must stay field-shaped: {label}"
        );
        assert!(
            !label.contains(secret_td) && !label.contains(secret_host),
            "diagnostic label must not embed sample secrets: {label}"
        );
    }

    assert_eq!(
        grpc_proxy::GrpcTransportDiagnostic::MeshSpiffeId.as_str(),
        "mesh.spiffe_id"
    );
    assert_eq!(
        grpc_proxy::GrpcTransportDiagnostic::MeshHboneDialHost.as_str(),
        "mesh.hbone_dial_host"
    );
    assert_eq!(
        grpc_proxy::GrpcTransportDiagnostic::MeshHboneAuthorityHost.as_str(),
        "mesh.hbone_authority_host"
    );
    assert_eq!(
        grpc_proxy::GrpcTransportDiagnostic::MeshEastwestSni.as_str(),
        "mesh.eastwest_sni"
    );
    assert_eq!(
        grpc_proxy::GrpcTransportDiagnostic::MeshTrustDomain.as_str(),
        "mesh.trust_domain"
    );
    assert_eq!(
        grpc_proxy::GrpcTransportDiagnostic::ConflictingMeshTransports.as_str(),
        "conflicting_mesh_transports"
    );
    assert_eq!(
        grpc_proxy::GrpcTransportDiagnostic::CrossClusterMissingTransport.as_str(),
        "cross_cluster_missing_transport"
    );
    // The unix label is the reserved TAG NAME, never the configured path.
    assert_eq!(
        grpc_proxy::GrpcTransportDiagnostic::MeshUnixSocket.as_str(),
        "mesh.unix_socket"
    );
    assert_eq!(
        grpc_proxy::GrpcTransportDiagnostic::MeshUnixSocket.as_str(),
        ferrum_edge::proxy::unix_backend::MESH_UNIX_SOCKET_TAG
    );
}

#[tokio::test]
async fn grpc_transport_mesh_mtls_cross_cluster_dial_plan_failures_are_field_specific() {
    // When classification admits a well-formed cross-cluster mesh.mtls target
    // but dial-plan re-resolution later fails (tags mutated / empty), the
    // diagnostic must still name the failed east-west field — not collapse to
    // a generic unmaterializable bucket.
    let pools = TransportTestPools::new();
    let mtls = ferrum_edge::proxy::mesh_mtls_pool::MESH_MTLS_TARGET_TAG;
    let xc = ferrum_edge::proxy::mesh_mtls_pool::MESH_CROSS_CLUSTER_TAG;
    let sni = ferrum_edge::proxy::mesh_mtls_pool::MESH_EASTWEST_SNI_TAG;
    let td = ferrum_edge::proxy::mesh_mtls_pool::MESH_TRUST_DOMAIN_TAG;
    let secret_sni = "orders.internal.example.com";
    let secret_td = "remote.local";

    // Classifier-level malformed path (Unsupported) already covered above; here
    // the same missing fields go through dial-plan resolve for an HBONE-shaped
    // same-cluster pin failure on mesh.mtls.
    let empty_pin = target_with_tags(&[
        (mtls, "true"),
        (ferrum_edge::proxy::hbone_pool::MESH_SPIFFE_ID_TAG, ""),
    ]);
    let err = pools
        .resolve(Some(&empty_pin))
        .err()
        .expect("empty mesh.spiffe_id must fail closed");
    assert_eq!(
        err.diagnostic(),
        grpc_proxy::GrpcTransportDiagnostic::MeshSpiffeId
    );
    assert!(!err.message().contains(secret_sni));

    // Cross-cluster mtls missing SNI is Unsupported + MeshEastwestSni (classifier).
    let missing_sni = target_with_tags(&[(mtls, "true"), (xc, "true"), (td, secret_td)]);
    let err = pools
        .resolve(Some(&missing_sni))
        .err()
        .expect("missing SNI must fail closed");
    assert!(matches!(
        err,
        grpc_proxy::GrpcTransportError::Unsupported { .. }
    ));
    assert_eq!(
        err.diagnostic(),
        grpc_proxy::GrpcTransportDiagnostic::MeshEastwestSni
    );
    assert!(!err.message().contains(secret_td));

    // Cross-cluster mtls missing trust domain is Unsupported + MeshTrustDomain.
    let missing_td = target_with_tags(&[(mtls, "true"), (xc, "true"), (sni, secret_sni)]);
    let err = pools
        .resolve(Some(&missing_td))
        .err()
        .expect("missing trust domain must fail closed");
    assert!(matches!(
        err,
        grpc_proxy::GrpcTransportError::Unsupported { .. }
    ));
    assert_eq!(
        err.diagnostic(),
        grpc_proxy::GrpcTransportDiagnostic::MeshTrustDomain
    );
    assert!(!err.message().contains(secret_sni));
}

// ── Standard H1/H2 frontend: native gRPC over Ambient HBONE (issue #3728) ────
//
// The nested-HTTP/2-over-HBONE transport was wired for the H3 gRPC bridge first
// (#3284) while the standard frontend still refused a `mesh.hbone` target
// pre-dial. These guards pin the wiring that removed that protocol-dependent
// capability boundary: BOTH frontends must materialize the transport through the
// SAME resolver, before any dial, on every attempt.

/// The standard native-gRPC branch must no longer hard-wire
/// `GrpcDispatchTransport::Direct`, and both frontends must reach the transport
/// through the one shared resolver — otherwise H2 and H3 can drift on target
/// validation, identity enforcement, and error mapping for the same route.
#[test]
fn standard_grpc_frontend_and_h3_bridge_share_one_mesh_transport_resolver() {
    const FOR_TARGET: &str = "GrpcDispatchTransport::for_target(";
    const SHARED_RESOLVER: &str = "resolve_grpc_dispatch_transport(";
    let proxy_src = include_str!("../../../src/proxy/mod.rs");
    let h3_src = include_str!("../../../src/http3/cross_protocol.rs");

    assert!(
        proxy_src.contains("pub(crate) fn resolve_grpc_dispatch_transport<'a>("),
        "the shared native-gRPC transport resolver must live in proxy/mod.rs"
    );
    assert_eq!(
        proxy_src.matches(FOR_TARGET).count(),
        1,
        "exactly ONE call site may materialize a gRPC dispatch transport in \
         proxy/mod.rs — a second one is the drift this resolver exists to prevent"
    );
    assert!(
        h3_src.contains("crate::proxy::resolve_grpc_dispatch_transport(state, target)"),
        "the H3 gRPC bridge must delegate to the SHARED resolver, not re-implement it"
    );
    assert_eq!(
        h3_src.matches(FOR_TARGET).count(),
        0,
        "the H3 bridge must not keep a private materialization path"
    );

    // The native-gRPC branch resolves once for the first attempt and again for
    // every retry attempt (rotation re-binds the dial plan).
    assert_eq!(
        proxy_src.matches(SHARED_RESOLVER).count(),
        2,
        "expected exactly two call sites in proxy/mod.rs: the first attempt and \
         the per-retry-attempt re-resolution"
    );
    assert!(
        !proxy_src.contains("grpc_proxy::GrpcDispatchTransport::Direct(&state.grpc_pool)"),
        "the native-gRPC dispatch sites must use the materialized transport, never \
         a hard-wired direct pool that would bypass a mesh target's secured hop"
    );
}

/// The transport must be materialized BEFORE the backend URL is built and
/// before any dispatch call, so an unresolvable mesh target fails closed with no
/// socket opened and no application byte forwarded.
#[test]
fn standard_grpc_frontend_materializes_the_transport_before_dispatch() {
    let proxy_src = include_str!("../../../src/proxy/mod.rs");
    let resolve_at = proxy_src
        .find("let grpc_transport =")
        .expect("the native-gRPC branch must bind a materialized transport");
    let first_dispatch_at = proxy_src
        .find("grpc_proxy::proxy_grpc_request_core(")
        .expect("the native-gRPC branch must dispatch through proxy_grpc_request_core");
    assert!(
        resolve_at < first_dispatch_at,
        "the transport must be resolved before the first dispatch; \
         resolve@{resolve_at} dispatch@{first_dispatch_at}"
    );

    // The fail-closed arm answers UNAVAILABLE and releases the half-open probe
    // slot instead of letting the armed guard double-release it.
    let tail = &proxy_src[resolve_at..first_dispatch_at];
    assert!(
        tail.contains("grpc_probe_guard.disarm();"),
        "the transport refusal must disarm the RAII probe guard before its \
         explicit release, mirroring the sibling egress-policy reject"
    );
    assert!(
        tail.contains("release_circuit_breaker_probe_on_admission_reject("),
        "the transport refusal must release a HALF_OPEN probe slot it consumed"
    );
}

/// A gRPC retry may rotate between the direct pool and the Ambient HBONE
/// transport — both are hyper HTTP/2 with an identical trailer contract — but
/// must still fail closed on every other class rather than switching response
/// pipelines mid-loop.
#[test]
fn native_grpc_retry_rotation_admits_only_http2_equivalent_transports() {
    let proxy_src = include_str!("../../../src/proxy/mod.rs");
    let screen_at = proxy_src
        .find("Direct gRPC retry rotated onto a mesh target")
        .expect("the retry rotation screen must exist");
    let window = &proxy_src[screen_at.saturating_sub(2000)..screen_at];
    for admitted in [
        "grpc_proxy::GrpcMeshDispatch::Direct",
        "grpc_proxy::GrpcMeshDispatch::Hbone",
        "grpc_proxy::GrpcMeshDispatch::HboneCrossCluster",
    ] {
        assert!(
            window.contains(admitted),
            "the retry rotation screen must admit {admitted}"
        );
    }
    assert!(
        !window.contains("GrpcMeshDispatch::MeshMtls"),
        "a rotation onto a Sidecar mesh-mTLS target must NOT be admitted by the \
         native gRPC retry loop — it does not own that response pipeline"
    );
}

/// The fully-streaming H1/H2 fast path must take an already-materialized
/// transport. It consumes the request body on the wire, so it is never
/// replayable: carrying a mesh transport here is what lets a client-streaming /
/// bidi RPC reach an Ambient target without the gateway buffering the upload.
#[test]
fn grpc_streaming_fast_path_takes_a_materialized_transport_and_never_retries() {
    let src = include_str!("../../../src/proxy/grpc_proxy.rs");
    let start = src
        .find("pub async fn proxy_grpc_request_streaming(")
        .expect("the H1/H2 streaming gRPC entry must exist");
    let signature_end = src[start..]
        .find(") -> Result<GrpcResponseKind, GrpcProxyError> {")
        .expect("streaming entry signature must terminate");
    let signature = &src[start..start + signature_end];
    assert!(
        signature.contains("transport: &GrpcDispatchTransport<'_>"),
        "the streaming fast path must accept the caller's materialized transport, \
         not a hard-wired GrpcConnectionPool"
    );
    assert!(
        !signature.contains("grpc_pool: &GrpcConnectionPool"),
        "the streaming fast path must no longer take the direct pool directly"
    );

    // The caller gates this path on "no retry configured", so a partially
    // transmitted streaming upload can never be replayed on any transport.
    let proxy_src = include_str!("../../../src/proxy/mod.rs");
    let fast_path_gate = "grpc_can_use_streaming_fast_path = grpc_should_stream && !grpc_has_retry";
    assert!(
        proxy_src.contains(fast_path_gate),
        "the fully-streaming gRPC fast path must remain mutually exclusive with retry"
    );
}

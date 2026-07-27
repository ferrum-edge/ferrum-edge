//! Source-contract coverage for matched-proxy `allowed_methods` transaction logging.

/// Namespace-qualified protocol-filtered request view. Keying by
/// `(namespace, id)` is what stops a same-id proxy in another tenant from
/// supplying this request's plugin list.
const PROTOCOL_VIEW: &str = "request_view(&proxy.namespace, &proxy.id, request_protocol)";

/// Namespace-qualified gRPC-Web composed request view.
const GRPC_WEB_VIEW: &str = "grpc_web_request_view(&proxy.namespace, &proxy.id)";

#[test]
fn h1_h2_allowed_methods_rejection_logs_before_request_hooks() {
    let source = include_str!("../../../src/proxy/mod.rs");
    let method_filter = source
        .find("// Per-proxy HTTP method filtering (checked before plugins to save work).")
        .expect("H1/H2 allowed_methods gate");
    let region = &source[method_filter..];
    let log = region
        .find("log_pre_backend_rejected_request(")
        .map(|offset| method_filter + offset)
        .expect("405 path must call log_pre_backend_rejected_request");
    let phase = region
        .find("\"allowed_methods\"")
        .map(|offset| method_filter + offset)
        .expect("405 path must use rejection_phase allowed_methods");
    let grpc_post = region
        .find("// gRPC spec mandates POST method.")
        .map(|offset| method_filter + offset)
        .expect("gRPC POST gate must follow allowed_methods");
    let plugin_view = source
        .find("let plugin_cache_view = if grpc_web_request {")
        .expect("full plugin-cache view must load before method admission");
    let on_request = region
        .find("plugin.on_request_received(&mut ctx),")
        .map(|offset| method_filter + offset)
        .expect("on_request_received must remain after method admission");

    assert!(log < grpc_post);
    assert!(phase < grpc_post);
    assert!(plugin_view < log);
    assert!(grpc_post < on_request);

    let logging_slice = &source[plugin_view..grpc_post];
    assert!(
        logging_slice.contains(GRPC_WEB_VIEW) && logging_slice.contains(PROTOCOL_VIEW),
        "405 logging must select the namespace-qualified, protocol-appropriate plugin-cache view"
    );
    assert!(
        !logging_slice.contains("on_request_received("),
        "405 logging must not run ordinary request hooks"
    );
    assert!(
        logging_slice.contains("build_grpc_web_reject_response(&[],"),
        "405 response shaping must keep an empty plugin list so request/after_proxy hooks stay skipped"
    );
}

#[test]
fn h3_allowed_methods_rejection_logs_before_request_hooks() {
    let source = include_str!("../../../src/http3/server.rs");
    let method_filter = source
        .find("// Per-proxy HTTP method filtering (checked before plugins to save work).")
        .expect("H3 allowed_methods gate");
    let region = &source[method_filter..];
    let log = region
        .find("log_pre_backend_rejected_request(")
        .expect("H3 405 path must call log_pre_backend_rejected_request");
    let phase = region
        .find("\"allowed_methods\"")
        .expect("H3 405 path must use rejection_phase allowed_methods");
    let grpc_post = region
        .find("// gRPC spec mandates POST.")
        .expect("H3 gRPC POST gate must follow allowed_methods");
    let on_request = region
        .find("plugin.on_request_received(&mut ctx),")
        .expect("H3 on_request_received must remain after method admission");

    assert!(log < grpc_post);
    assert!(phase < grpc_post);
    assert!(grpc_post < on_request);

    let logging_slice = &region[..grpc_post];
    assert!(
        logging_slice.contains(GRPC_WEB_VIEW) && logging_slice.contains(PROTOCOL_VIEW),
        "H3 405 logging must select the namespace-qualified, protocol-appropriate cache view"
    );
    assert!(
        !logging_slice.contains("on_request_received("),
        "H3 405 logging must not run ordinary request hooks"
    );
}

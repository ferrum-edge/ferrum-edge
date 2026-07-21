//! Source-contract coverage for matched-proxy `allowed_methods` transaction logging.

#[test]
fn h1_h2_allowed_methods_rejection_logs_before_request_hooks() {
    let source = include_str!("../../../src/proxy/mod.rs");
    let method_filter = source
        .find("// Per-proxy HTTP method filtering (checked before plugins to save work).")
        .expect("H1/H2 allowed_methods gate");
    let region = &source[method_filter..];
    let log = region
        .find("log_rejected_request(")
        .expect("405 path must call log_rejected_request");
    let phase = region
        .find("\"allowed_methods\"")
        .expect("405 path must use rejection_phase allowed_methods");
    let grpc_post = region
        .find("// gRPC spec mandates POST method.")
        .expect("gRPC POST gate must follow allowed_methods");
    let plugin_view = region
        .find(
            "let plugin_cache_view = epoch.plugin_cache.request_view(&proxy.id, request_protocol);",
        )
        .expect("full plugin-cache view must load after method admission");
    let on_request = region
        .find("plugin.on_request_received(&mut ctx),")
        .expect("on_request_received must remain after method admission");

    assert!(log < grpc_post);
    assert!(phase < grpc_post);
    assert!(grpc_post < plugin_view);
    assert!(plugin_view < on_request);

    let logging_slice = &region[..grpc_post];
    assert!(
        logging_slice.contains("request_view(&proxy.id, request_protocol)"),
        "405 logging must select the protocol-filtered plugin-cache view"
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
        .find("log_rejected_request(")
        .expect("H3 405 path must call log_rejected_request");
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
        logging_slice.contains("grpc_web_request_view(&proxy.id)")
            && logging_slice.contains("request_view(&proxy.id, request_protocol)"),
        "H3 405 logging must select the protocol-appropriate plugin-cache view"
    );
    assert!(
        !logging_slice.contains("on_request_received("),
        "H3 405 logging must not run ordinary request hooks"
    );
}

//! Source-contract guards for the public custom-plugin lifecycle documentation.
//!
//! Runtime behavior is exercised by the hosted-only functional protocol matrix;
//! these guards make the routing and logging boundaries fail visibly if the
//! H1/H2 or H3 control-flow markers move without the public contract changing.
//! The separate `example_audit_plugin` persistence/lifecycle work owns its own
//! contracts, so this module deliberately does not pin that file's text.

const PROXY_SOURCE: &str = include_str!("../../src/proxy/mod.rs");
const H3_SOURCE: &str = include_str!("../../src/http3/server.rs");
const TRAIT_SOURCE: &str = include_str!("../../src/plugins/mod.rs");
const EXAMPLE_SOURCE: &str = include_str!("../../custom_plugins/examples/example_plugin.rs");
const CUSTOM_PLUGIN_GUIDE: &str = include_str!("../../CUSTOM_PLUGINS.md");
const EXECUTION_ORDER_GUIDE: &str = include_str!("../../docs/plugin_execution_order.md");

fn assert_markers_in_order(source: &str, surface: &str, markers: &[&str]) {
    let mut offset = 0;
    for marker in markers {
        let relative = source[offset..]
            .find(marker)
            .unwrap_or_else(|| panic!("{surface} is missing lifecycle marker: {marker}"));
        offset += relative + marker.len();
    }
}

#[test]
fn h1_h2_route_miss_and_method_rejection_precede_request_hooks() {
    assert_markers_in_order(
        PROXY_SOURCE,
        "H1/H2 proxy",
        &[
            "No route matched for request path",
            "StatusCode::NOT_FOUND",
            // The request-scoped view is selected once before method admission
            // so the 405 logging path reuses it, and it stays keyed by
            // `(namespace, id)` so a same-id proxy in another tenant cannot
            // supply this request's plugin list.
            "let plugin_cache_view = if grpc_web_request {",
            "request_view(&proxy.namespace, &proxy.id, request_protocol)",
            "// Per-proxy HTTP method filtering (checked before plugins to save work).",
            "StatusCode::METHOD_NOT_ALLOWED",
            "log_pre_backend_rejected_request(",
            "\"allowed_methods\"",
            "// gRPC spec mandates POST method.",
            "StatusCode::BAD_REQUEST",
            "// Execute on_request_received hooks",
            "await_request_plugin_deadline_with_provenance(",
            "plugin.on_request_received(&mut ctx),",
        ],
    );
}

#[test]
fn h3_route_miss_and_method_rejection_precede_request_hooks() {
    assert_markers_in_order(
        H3_SOURCE,
        "H3 proxy",
        &[
            "StatusCode::NOT_FOUND",
            "// Per-proxy HTTP method filtering (checked before plugins to save work).",
            "StatusCode::METHOD_NOT_ALLOWED",
            "log_pre_backend_rejected_request(",
            "\"allowed_methods\"",
            "// gRPC spec mandates POST.",
            "StatusCode::BAD_REQUEST",
            "// Execute on_request_received hooks",
            "await_request_plugin_deadline_with_provenance(",
            "plugin.on_request_received(&mut ctx),",
        ],
    );
}

#[test]
fn h1_h2_buffered_terminal_logging_precedes_response_construction() {
    assert_markers_in_order(
        PROXY_SOURCE,
        "H1/H2 buffered terminal path",
        &[
            "let deferred_logger: Option<Arc<crate::proxy::deferred_log::DeferredTransactionLogger>> =",
            "if body_will_stream {",
            "DeferredTransactionLogger::new_with_start_time(",
            "} else {",
            "crate::plugins::log_with_mirror_before_buffered_response(&plugins, summary, &ctx)",
            "record_request(&state, response_status);",
            "// Build final response",
            "let mut resp_builder = Response::builder()",
        ],
    );
}

#[test]
fn h3_buffered_response_is_sent_before_terminal_logging() {
    assert_markers_in_order(
        H3_SOURCE,
        "H3 buffered terminal path",
        &[
            "// ===== BUFFERED RESPONSE PATH =====",
            "run_deadline_bounded_response_committed_hooks(",
            "// Build and send buffered response",
            "apply_response_headers(Response::builder().status(status), &response_headers);",
            "let response_headers_sent = await_buffered_h3_write!(stream.send_response(resp));",
            "// Transaction logging follows downstream response completion",
            "let summary = TransactionSummary {",
            "crate::plugins::log_with_mirror(&plugins, &summary, &ctx).await;",
        ],
    );
}

#[test]
fn trait_example_and_guides_describe_the_same_request_boundary() {
    assert!(
        TRAIT_SOURCE
            .contains("Called after routing and per-proxy allowed-method admission succeed.")
    );
    assert!(
        EXAMPLE_SOURCE
            .contains("Called after a route matches and its allowed-method check succeeds.")
    );
    assert!(
        CUSTOM_PLUGIN_GUIDE.contains(
            "returns 404 without running any global or scoped `on_request_received` hook."
        )
    );
    assert!(
        CUSTOM_PLUGIN_GUIDE.contains(
            "matched request with a disallowed method returns 405 without running either"
        )
    );
    assert!(CUSTOM_PLUGIN_GUIDE.contains("rejection_phase = \"allowed_methods\""));
    assert!(
        EXECUTION_ORDER_GUIDE
            .contains("`on_request_received` is therefore a post-route, post-allowed-method hook")
    );
    assert!(EXECUTION_ORDER_GUIDE.contains("rejection_phase = \"allowed_methods\""));
    for source in [
        TRAIT_SOURCE,
        EXAMPLE_SOURCE,
        CUSTOM_PLUGIN_GUIDE,
        EXECUTION_ORDER_GUIDE,
    ] {
        assert!(
            source.contains("Native gRPC requests must also use `POST` before this hook runs.")
        );
    }
}

#[test]
fn trait_example_and_guides_describe_buffered_streaming_and_h3_log_timing() {
    for source in [TRAIT_SOURCE, CUSTOM_PLUGIN_GUIDE, EXECUTION_ORDER_GUIDE] {
        assert!(
            source.contains("await"),
            "logging contract must name awaited hooks"
        );
        assert!(
            source.contains("sequential"),
            "logging contract must name sequential invocation"
        );
        assert!(
            source.contains("Native H3") || source.contains("native-H3"),
            "logging contract must distinguish native H3"
        );
    }
    assert!(EXAMPLE_SOURCE.contains("Hyper-owned streamed bodies spawn logging"));
    assert!(H3_SOURCE.contains("# Why H3 does not use `DeferredTransactionLogger`"));
    assert!(H3_SOURCE.contains("drives the\n/// QUIC send stream to completion synchronously"));
}

#[test]
fn deadline_bearing_buffered_logging_uses_owned_bounded_cleanup() {
    let helper = TRAIT_SOURCE
        .split("pub async fn log_with_mirror_before_buffered_response(")
        .nth(1)
        .expect("deadline-aware buffered logging helper")
        .split("async fn collect_mirror_result(")
        .next()
        .expect("bounded deadline-aware buffered logging helper");
    assert!(helper.contains("if ctx.grpc_deadline_at().is_none()"));
    assert!(helper.contains("log_with_mirror(plugins, &summary, ctx).await;"));
    assert!(helper.contains("let plugins = plugins.to_vec();"));
    assert!(helper.contains("let ctx = ctx.clone();"));
    assert!(helper.contains("crate::observability_delivery::spawn_deadline_cleanup(async move"));
    assert!(helper.contains("std::time::Duration::from_secs(5)"));
}

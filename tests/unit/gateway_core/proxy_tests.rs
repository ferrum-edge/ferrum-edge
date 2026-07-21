use chrono::Utc;
use ferrum_edge::_test_support::{
    apply_effective_backend_scheme_headers_for_test, collect_forwardable_websocket_headers_for_test,
};
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, DispatchKind, GatewayConfig, Proxy, UpstreamTarget,
};
use ferrum_edge::proxy::client_ip::TrustedProxies;
use ferrum_edge::proxy::headers::merge_proxy_headers_and_strip_for_grpc;
use ferrum_edge::proxy::{
    apply_trusted_forwarded_request_scheme, build_backend_effective_path, build_backend_url,
    build_backend_url_with_target, normalize_request_authority_for_signing,
    retry_target_preserves_backend_path,
};
use ferrum_edge::router_cache::RouterCache;
use std::collections::HashMap;

#[test]
fn terminal_final_body_dispatch_follows_path_policy_and_precedes_backend_breaker() {
    let src = include_str!("../../../src/proxy/mod.rs");
    let request_scoped_gate = src
        .find("let has_terminal_body_dispatch = capabilities")
        .expect("terminal dispatch must retain a request-scoped applicability gate");
    let terminal_dispatch = src
        .find("if final_body_before_backend_dispatch {")
        .expect("terminal final-body dispatch gate must remain present");
    let selection = src
        .find("let selection = backend_dispatch::select_upstream_target(")
        .expect("selected-target lookup must remain present");
    let path_policy = src[selection..]
        .find("if backend_path_is_policy_bound {")
        .map(|offset| selection + offset)
        .expect("selected backend-path policy must remain present");
    let routing_deferred = src[path_policy..terminal_dispatch]
        .find("BackendPathBeforeProxyPass::RoutingHeaderDeferred")
        .map(|offset| path_policy + offset)
        .expect("routing-header deferred pass must remain present");
    let remaining_deferred = src[routing_deferred..terminal_dispatch]
        .find("BackendPathBeforeProxyPass::RemainingDeferred")
        .map(|offset| routing_deferred + offset)
        .expect("remaining deferred pass must remain present");
    let breaker = src[terminal_dispatch..]
        .find("// Circuit breaker check")
        .map(|offset| terminal_dispatch + offset)
        .expect("backend circuit-breaker gate must remain present");
    let provider_hook = src[terminal_dispatch..breaker]
        .find("run_final_request_body_hooks(")
        .expect("terminal final-body hook must run before the backend breaker");
    let synthetic_pipeline = src[terminal_dispatch..breaker]
        .find("finalize_reject_response_with_after_proxy_hooks(")
        .expect("terminal response must use the synthetic response pipeline");
    let backend_transport = src
        .find("async fn proxy_to_backend(")
        .expect("backend transport function must remain present");

    let applicability = &src[request_scoped_gate..terminal_dispatch];
    assert!(applicability.contains("if let Some(transformed_headers)"));
    assert!(applicability.contains("std::mem::swap(&mut ctx.headers, transformed_headers)"));
    assert!(applicability.contains("final_request_body_requirements("));
    let helper = src
        .split("pub(crate) fn final_request_body_requirements(")
        .nth(1)
        .expect("shared final-body applicability helper must remain present")
        .split("pub(crate) fn request_body_requirements_before_authenticate(")
        .next()
        .expect("shared final-body applicability helper must remain bounded");
    assert!(helper.contains("plugin.should_buffer_request_body(ctx)"));
    assert!(helper.contains("plugin.requires_final_request_body_before_backend_dispatch()"));
    assert!(provider_hook < synthetic_pipeline);
    assert!(request_scoped_gate < terminal_dispatch);
    assert!(selection < path_policy);
    assert!(path_policy < routing_deferred);
    assert!(routing_deferred < remaining_deferred);
    assert!(remaining_deferred < terminal_dispatch);
    assert!(terminal_dispatch < breaker);
    assert!(breaker < backend_transport);
}

fn test_proxy() -> Proxy {
    Proxy {
        id: "test".into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("Test Proxy".into()),
        hosts: vec![],
        listen_path: Some("/api/v1".to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "backend.example.com".into(),
        backend_port: 3000,
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

#[test]
fn test_build_backend_url_strip() {
    let proxy = test_proxy();
    let url = build_backend_url(
        &proxy,
        "/api/v1/users/123",
        "",
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
    );
    assert_eq!(url, "http://backend.example.com:3000/users/123");
}

#[test]
fn test_build_backend_url_no_strip() {
    let mut proxy = test_proxy();
    proxy.strip_listen_path = false;
    let url = build_backend_url(
        &proxy,
        "/api/v1/users/123",
        "",
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
    );
    assert_eq!(url, "http://backend.example.com:3000/api/v1/users/123");
}

#[test]
fn test_build_backend_url_with_backend_path() {
    let mut proxy = test_proxy();
    proxy.backend_path = Some("/internal".into());
    let url = build_backend_url(
        &proxy,
        "/api/v1/users",
        "",
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
    );
    assert_eq!(url, "http://backend.example.com:3000/internal/users");
}

#[test]
fn test_build_backend_url_with_relative_backend_path() {
    let mut proxy = test_proxy();
    proxy.backend_path = Some("internal".into());
    let url = build_backend_url(
        &proxy,
        "/api/v1/users",
        "",
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
    );
    assert_eq!(url, "http://backend.example.com:3000/internal/users");
}

#[test]
fn test_build_backend_url_with_query() {
    let proxy = test_proxy();
    let url = build_backend_url(
        &proxy,
        "/api/v1/search",
        "q=hello&page=1",
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
    );
    assert_eq!(url, "http://backend.example.com:3000/search?q=hello&page=1");
}

#[test]
fn test_build_backend_url_target_path_overrides_backend_path() {
    let mut proxy = test_proxy();
    proxy.backend_path = Some("/v1".into());
    let url = build_backend_url_with_target(
        &proxy,
        "/api/v1/users",
        "",
        "target.example.com",
        9090,
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
        Some("/v2"),
    );
    assert_eq!(url, "http://target.example.com:9090/v2/users");
}

#[test]
fn request_phase_deadline_rejects_preserve_grpc_web_framing() {
    let source = include_str!("../../../src/proxy/mod.rs");
    let phase = source
        .find("// Execute on_request_received hooks")
        .expect("request hook phase must remain present");
    let phase = &source[phase..];
    let end = phase
        .find("// Materialize query params before authentication")
        .expect("request hook phase must remain bounded");
    let phase = &phase[..end];
    assert!(phase.contains("build_grpc_web_reject_response("));
    assert!(phase.contains("grpc_web_response_content_type,"));

    let helper = source
        .find("async fn build_grpc_web_reject_response(")
        .expect("request rejection writer must remain flavor-aware");
    let helper = &source[helper..];
    let helper_end = helper
        .find("async fn run_backend_path_plugins_or_build_reject(")
        .expect("request rejection helper must remain bounded");
    let helper = &helper[..helper_end];
    assert!(helper.contains("error_response_for_content_type("));
    assert!(helper.contains("finalize_grpc_web_error_response_headers("));
    assert!(helper.contains("build_grpc_web_error_response_from_parts("));
}

#[test]
fn test_build_backend_url_target_path_none_uses_backend_path() {
    let mut proxy = test_proxy();
    proxy.backend_path = Some("/v1".into());
    let url = build_backend_url_with_target(
        &proxy,
        "/api/v1/users",
        "",
        "target.example.com",
        9090,
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
        None,
    );
    assert_eq!(url, "http://target.example.com:9090/v1/users");
}

#[test]
fn test_build_backend_url_target_path_with_no_backend_path() {
    let proxy = test_proxy();
    let url = build_backend_url_with_target(
        &proxy,
        "/api/v1/users",
        "",
        "target.example.com",
        9090,
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
        Some("/service"),
    );
    assert_eq!(url, "http://target.example.com:9090/service/users");
}

#[test]
fn test_build_backend_url_target_path_without_slashes_inserts_separator() {
    let mut proxy = test_proxy();
    proxy.listen_path = Some("/api/v1/".into());
    let url = build_backend_url_with_target(
        &proxy,
        "/api/v1/users",
        "",
        "target.example.com",
        9090,
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
        Some("service"),
    );
    assert_eq!(url, "http://target.example.com:9090/service/users");
}

#[test]
fn test_build_backend_url_target_path_with_query() {
    let proxy = test_proxy();
    let url = build_backend_url_with_target(
        &proxy,
        "/api/v1/search",
        "q=hello",
        "target.example.com",
        9090,
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
        Some("/svc"),
    );
    assert_eq!(url, "http://target.example.com:9090/svc/search?q=hello");
}

#[test]
fn test_backend_effective_grpc_path_uses_prefix_strip() {
    let mut proxy = test_proxy();
    proxy.listen_path = Some("/prefix".into());
    let path =
        build_backend_effective_path(&proxy, "/prefix/pkg.Service/Denied", "/prefix".len(), None);
    assert_eq!(path, "/pkg.Service/Denied");
}

#[test]
fn test_backend_effective_grpc_path_uses_exact_route_backend_path() {
    let mut proxy = test_proxy();
    proxy.listen_path = Some("=/public.Service/Allowed".into());
    proxy.backend_path = Some("/admin.Service/Delete".into());
    let incoming = "/public.Service/Allowed";
    let path = build_backend_effective_path(&proxy, incoming, incoming.len(), None);
    assert_eq!(path, "/admin.Service/Delete");
}

#[test]
fn test_backend_effective_grpc_path_uses_regex_match_length() {
    let mut proxy = test_proxy();
    proxy.listen_path = Some("~^/public\\.Service/Allowed$".into());
    proxy.backend_path = Some("/admin.Service/Delete".into());
    let incoming = "/public.Service/Allowed";
    let path = build_backend_effective_path(&proxy, incoming, incoming.len(), None);
    assert_eq!(path, "/admin.Service/Delete");
}

#[test]
fn test_backend_effective_grpc_path_uses_selected_target_path() {
    let mut proxy = test_proxy();
    proxy.backend_path = Some("/ignored.Service/Method".into());
    let incoming = "/api/v1";
    let path = build_backend_effective_path(
        &proxy,
        incoming,
        incoming.len(),
        Some("/selected.Service/Method"),
    );
    assert_eq!(path, "/selected.Service/Method");
}

#[test]
fn test_backend_effective_path_matches_backend_url_path_assembly() {
    let mut proxy = test_proxy();
    proxy.backend_path = Some("/backend.Service".into());
    let incoming = "/api/v1/Method";
    let strip_len = "/api/v1".len();
    let path = build_backend_effective_path(&proxy, incoming, strip_len, None);
    let url = build_backend_url_with_target(
        &proxy,
        incoming,
        "",
        "target.example.com",
        9090,
        strip_len,
        None,
    );
    assert_eq!(path, "/backend.Service/Method");
    assert_eq!(url, format!("http://target.example.com:9090{path}"));
}

fn retry_target(host: &str, path: Option<&str>) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port: 9090,
        service_port_policy_key: None,
        weight: 100,
        tags: HashMap::new(),
        locality: None,
        path: path.map(str::to_string),
    }
}

#[test]
fn test_backend_path_policy_pins_target_path_across_retries() {
    let mut proxy = test_proxy();
    proxy.backend_path = Some("/pkg.Service".to_string());
    let incoming = "/api/v1/Allowed";
    let strip_len = "/api/v1".len();
    let initial = retry_target("first.example.com", Some("/pkg.Service"));
    let same_method = retry_target("second.example.com", Some("/pkg.Service"));
    let different_method = retry_target("third.example.com", Some("/admin.Service"));
    let explicit_prefix = retry_target("fourth.example.com", Some("/pkg.Service"));
    let proxy_fallback = retry_target("fifth.example.com", None);
    let relative_prefix = retry_target("sixth.example.com", Some("pkg.Service"));

    assert!(retry_target_preserves_backend_path(
        true,
        &proxy,
        incoming,
        strip_len,
        &initial,
        &same_method
    ));
    assert!(!retry_target_preserves_backend_path(
        true,
        &proxy,
        incoming,
        strip_len,
        &initial,
        &different_method
    ));
    assert!(retry_target_preserves_backend_path(
        false,
        &proxy,
        incoming,
        strip_len,
        &initial,
        &different_method
    ));
    assert!(retry_target_preserves_backend_path(
        true,
        &proxy,
        incoming,
        strip_len,
        &explicit_prefix,
        &proxy_fallback
    ));
    assert!(retry_target_preserves_backend_path(
        true,
        &proxy,
        incoming,
        strip_len,
        &relative_prefix,
        &proxy_fallback
    ));
}

#[test]
fn test_backend_path_bound_retries_abort_in_every_h1_h2_dispatch_family() {
    let source = include_str!("../../../src/proxy/mod.rs");
    assert!(source.contains(
        "Aborting gRPC retry because the candidate would change the authorized backend method path"
    ));
    assert!(source.contains(
        "Aborting retry because the candidate would change the authorized backend method path"
    ));
    assert!(source.contains(
        "Aborting WebSocket retry because the candidate would change the authorized backend method path"
    ));
    assert!(source.contains("if retry_admitted_by_cb && !retry_path_mismatch"));
}

#[test]
fn test_deferred_grpc_body_context_preserves_buffered_size_metadata() {
    let source = include_str!("../../../src/proxy/mod.rs");
    let metadata = source
        .split_once("// Store body metadata for plugins that read via ctx.metadata")
        .and_then(|(_, rest)| rest.split_once("// Mirror pre-transform bytes"))
        .map(|(body, _)| body)
        .expect("native gRPC request-body metadata region");
    let size = metadata
        .find("let request_body_size_bytes = grpc_req_body.len().to_string();")
        .expect("buffered gRPC size must be computed once");
    let primary = metadata[size..]
        .find("ctx.metadata.insert(")
        .map(|offset| size + offset)
        .expect("primary request context must receive buffered gRPC size");
    let deferred = metadata[primary..]
        .find("body_hook_ctx.metadata.insert(")
        .map(|offset| primary + offset)
        .expect("deferred final-body context must receive buffered gRPC size");
    assert!(size < primary && primary < deferred);
}

#[test]
fn test_final_request_body_rejects_are_gateway_local_terminal_outcomes() {
    let source = include_str!("../../../src/proxy/mod.rs");
    let conversion = source
        .split_once("fn reject_result_to_backend_response(")
        .and_then(|(_, rest)| rest.split_once("/// Outcome of applying"))
        .map(|(body, _)| body)
        .expect("final request-body rejection conversion");
    assert!(conversion.contains("retry::ErrorClass::RequestBodyTooLarge"));
    assert!(conversion.contains("retry::ErrorClass::DispatchPolicyRejected"));

    let accounting = include_str!("../../../src/proxy/backend_dispatch.rs");
    let neutral = accounting
        .split_once("pub(crate) fn client_side_no_backend_signal(")
        .and_then(|(_, rest)| rest.split_once("/// Whether a deferred streaming outcome"))
        .map(|(body, _)| body)
        .expect("backend-neutral error classification");
    assert!(neutral.contains("ErrorClass::DispatchPolicyRejected"));
}

#[test]
fn test_side_effecting_before_proxy_hooks_run_after_backend_path_policy() {
    let source = include_str!("../../../src/proxy/mod.rs");
    let handler_start = source
        .find("async fn handle_proxy_request_inner(")
        .expect("H1/H2 request handler must remain present");
    let handler = &source[handler_start..];
    let path_policy = handler
        .find("if let Some(response) = run_backend_path_plugins_or_build_reject(")
        .expect("backend-path policy hook must remain present");
    let deferred = handler
        .find("// Hooks that can dispatch external work or synthesize a terminal response")
        .expect("deferred before_proxy pass must remain present");
    assert!(path_policy < deferred);
    assert!(source.contains("BackendPathBeforeProxyPass::RoutingHeaderDeferred"));
    assert!(
        !source.contains("backend_dispatch::upstream_selection_hash_key("),
        "an external deferred hook must not reselect a different target"
    );
    assert!(source.contains("std::mem::replace(&mut ctx.path, original_request_path.clone())"));
    let routing_hook = handler
        .find("BackendPathBeforeProxyPass::RoutingHeaderDeferred")
        .expect("routing-header hook must remain present");
    assert_eq!(
        handler[path_policy..routing_hook]
            .matches("run_backend_path_plugins_or_build_reject(")
            .count(),
        1,
        "H1/H2 must enforce policy exactly once on the pinned path"
    );
    assert!(
        path_policy < routing_hook,
        "stateful path policy must reject before deferred external work"
    );

    let mirror = include_str!("../../../src/plugins/request_mirror.rs");
    assert!(mirror.contains("ctx.authorized_backend_path().unwrap_or(&ctx.path)"));

    for plugin_source in [
        include_str!("../../../src/plugins/fault_injection.rs"),
        include_str!("../../../src/plugins/grpc_deadline.rs"),
        include_str!("../../../src/plugins/request_mirror.rs"),
        include_str!("../../../src/plugins/response_mock.rs"),
        include_str!("../../../src/plugins/serverless_function.rs"),
        include_str!("../../../src/plugins/load_testing.rs"),
    ] {
        assert!(
            plugin_source
                .contains("fn defer_before_proxy_until_backend_path_resolved(&self) -> bool")
        );
    }

    let serverless = include_str!("../../../src/plugins/serverless_function.rs");
    assert!(
        serverless.contains("fn deferred_before_proxy_may_change_routing_headers(&self) -> bool")
    );
}

#[test]
fn test_h1_h2_route_rejects_keep_websocket_precedence_and_grpc_web_headers() {
    let source = include_str!("../../../src/proxy/mod.rs");
    let handler = source
        .find("async fn handle_proxy_request_inner(")
        .map(|start| &source[start..])
        .expect("H1/H2 request handler must remain present");
    let flavor = handler
        .find("let flavor = crate::proxy::backend_dispatch::detect_http_flavor(&req);")
        .expect("wire flavor classification must remain present");
    let websocket_precedence = handler
        .find("let grpc_web_response_content_type_owned = if flavor == HttpFlavor::WebSocket")
        .expect("WebSocket must suppress hostile gRPC-Web Content-Type promotion");
    let routed = handler
        .find("ctx.matched_proxy = Some(Arc::clone(&proxy));")
        .expect("route selection must remain present");
    let protocol = handler
        .find("let request_protocol = match flavor")
        .expect("route-level protocol selection must remain present");

    assert!(flavor < websocket_precedence && websocket_precedence < routed && routed < protocol);
    assert!(
        !handler[routed..protocol].contains("let grpc_web_response_content_type"),
        "route-level rejects must reuse the WebSocket-safe strict classification"
    );
    assert!(handler.contains("build_grpc_web_reject_response("));
    assert!(source.contains(
        "finalize_grpc_web_error_response_headers(&mut translated, &[], Some(&reject.headers));"
    ));
    let finalizer = source
        .find("pub(crate) fn finalize_grpc_web_error_response_headers(")
        .map(|start| &source[start..])
        .expect("gRPC-Web error finalizer must remain present");
    assert!(finalizer.contains("\"grpc-status\","));
    assert!(finalizer.contains("\"grpc-message\","));
}

/// The H1/H2 handler must RETAIN the gRPC-Web representation it just classified,
/// exactly as the H3 frontend does.
///
/// Without it the marker existed only when the `grpc_web` translator plugin was
/// configured, so an H1/H2 pass-through deployment (the backend speaks gRPC-Web
/// itself, the translator is deliberately absent) left
/// `client_grpc_framing_representation` with nothing to read. A backend that
/// omitted `Content-Type` — or a response hook that stripped it — then reached
/// the buffered representation gate as untyped JSON, and valid gRPC-Web frames
/// were replaced with a `502` whenever a response body rule was configured.
///
/// The retention must come from the WebSocket-safe strict classification and run
/// before routing, so it records the client's immutable inbound representation
/// rather than anything a hook could rewrite.
#[test]
fn test_h1_h2_retains_the_negotiated_grpc_web_representation_before_routing() {
    let source = include_str!("../../../src/proxy/mod.rs");
    let handler = source
        .find("async fn handle_proxy_request_inner(")
        .map(|start| &source[start..])
        .expect("H1/H2 request handler must remain present");

    const RETENTION_CALL: &str =
        "crate::plugins::grpc_web::retain_negotiated_response_content_type(&mut ctx, content_type);";

    let classification = handler
        .find("let grpc_web_response_content_type_owned = if flavor == HttpFlavor::WebSocket")
        .expect("WebSocket-safe gRPC-Web negotiation must remain present");
    let retention = handler
        .find(RETENTION_CALL)
        .expect("H1/H2 must retain the negotiated client gRPC-Web representation");
    let routed = handler
        .find("ctx.matched_proxy = Some(Arc::clone(&proxy));")
        .expect("route selection must remain present");

    assert!(
        classification < retention && retention < routed,
        "retention must consume the strict classification and precede routing"
    );

    // Parity with the H3 frontend, which is where this retention originated.
    let h3 = include_str!("../../../src/http3/server.rs");
    assert!(
        h3.contains(RETENTION_CALL),
        "the H3 frontend must keep retaining the same way"
    );
}

#[test]
fn test_backend_path_bound_retries_preflight_before_backoff() {
    let source = include_str!("../../../src/proxy/mod.rs");

    let grpc_retry = source
        .find("// Resolve and validate the next gRPC retry target before")
        .expect("direct gRPC retries must preflight the next target");
    let grpc_after_preflight = &source[grpc_retry..];
    let grpc_mismatch = grpc_after_preflight
        .find("Aborting gRPC retry because the candidate would change")
        .expect("direct gRPC retries must reject a path-changing target");
    let grpc_intermediate_record = grpc_after_preflight
        .find("record_grpc_backend_dispatch_outcome(")
        .expect("direct gRPC retry accounting must remain present");
    let grpc_backoff = grpc_after_preflight
        .find("let delay = retry::retry_delay(retry_config, grpc_attempt);")
        .expect("direct gRPC retry backoff must remain present");
    assert!(
        grpc_mismatch < grpc_intermediate_record
            && grpc_mismatch < grpc_backoff
            && grpc_after_preflight[grpc_mismatch..grpc_intermediate_record].contains("break;"),
        "direct gRPC path mismatch must abort before intermediate accounting and retry backoff"
    );

    let generic_retry = source
        .find("// Resolve and validate the next retry target before charging this")
        .expect("generic H1/H2 retries must preflight the next target");
    let generic_after_preflight = &source[generic_retry..];
    let generic_mismatch = generic_after_preflight
        .find("Aborting retry because the candidate would change")
        .expect("generic H1/H2 retries must reject a path-changing target");
    let generic_intermediate_record = generic_after_preflight
        .find("permits.record_backend_outcome(BackendAdmissionOutcome {")
        .expect("generic H1/H2 retry accounting must remain present");
    let generic_backoff = generic_after_preflight
        .find("let delay = retry::retry_delay(retry_config, attempt);")
        .expect("generic H1/H2 retry backoff must remain present");
    assert!(
        generic_mismatch < generic_intermediate_record
            && generic_mismatch < generic_backoff
            && generic_after_preflight[generic_mismatch..generic_intermediate_record]
                .contains("break;"),
        "generic H1/H2 path mismatch must abort before intermediate accounting and retry backoff"
    );
}

#[test]
fn test_deferred_hooks_cannot_spoof_backend_gateway_assertions() {
    let source = include_str!("../../../src/proxy/mod.rs");
    let routing_hook = source
        .rfind("BackendPathBeforeProxyPass::RoutingHeaderDeferred")
        .expect("deferred routing-header hook must remain present");
    let after_routing_hook = &source[routing_hook..];
    let refresh = after_routing_hook
        .find("refresh_effective_backend_gateway_assertion_headers(")
        .expect("gateway assertions must be refreshed after deferred routing hooks");
    let baggage_strip = after_routing_hook
        .find("hbone_proxy::strip_egress_baggage_in_proxy_headers(")
        .expect("egress baggage policy must run after deferred routing hooks");
    let remaining_hook = after_routing_hook
        .find("BackendPathBeforeProxyPass::RemainingDeferred")
        .expect("remaining deferred hook pass must remain present");
    assert!(
        refresh < baggage_strip && baggage_strip < remaining_hook,
        "gateway assertions and baggage policy must be restored before final enforcement"
    );
    assert!(
        !after_routing_hook[..remaining_hook].contains("select_upstream_target("),
        "deferred headers must not steer the request to a different target"
    );

    let remaining_hook = routing_hook + remaining_hook;
    assert!(
        source[remaining_hook..].contains("refresh_effective_backend_gateway_assertion_headers("),
        "gateway assertions must be restored after every deferred hook pass"
    );
    assert!(
        source[remaining_hook..].contains("hbone_proxy::strip_egress_baggage_in_proxy_headers("),
        "egress baggage policy must be restored after every deferred hook pass"
    );
    assert!(
        source.contains("name.eq_ignore_ascii_case(\"x-consumer-username\")")
            && source.contains("name.eq_ignore_ascii_case(\"x-consumer-custom-id\")")
            && source.contains("name.eq_ignore_ascii_case(\"x-geo-country\")"),
        "the shared scrub must reject case variants of every reserved assertion header"
    );
    assert!(
        source.contains("if let Some(country) = ctx.backend_geo_country()")
            && source.contains("\"x-geo-country\","),
        "the H1/H2 WebSocket boundary must restore the private GeoIP assertion"
    );
}

#[test]
fn test_longest_prefix_match() {
    let config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![
            Proxy {
                listen_path: Some("/api".to_string()),
                id: "short".into(),
                namespace: ferrum_edge::config::types::default_namespace(),
                ..test_proxy()
            },
            Proxy {
                listen_path: Some("/api/v1".to_string()),
                id: "long".into(),
                namespace: ferrum_edge::config::types::default_namespace(),
                ..test_proxy()
            },
        ],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    };
    let router = RouterCache::new(&config, 10000);
    let matched = router.find_proxy(None, "/api/v1/users");
    assert!(matched.is_some());
    assert_eq!(matched.unwrap().proxy.id, "long");
}

#[test]
fn test_no_match() {
    let config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![Proxy {
            listen_path: Some("/api".to_string()),
            ..test_proxy()
        }],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    };
    let router = RouterCache::new(&config, 10000);
    let matched = router.find_proxy(None, "/other/path");
    assert!(matched.is_none());
}

// ── Internal proxy/mod.rs function tests (moved from inline) ─────────────────

use async_trait::async_trait;
use ferrum_edge::_test_support::{
    apply_request_body_plugins, can_dispatch_direct_http2_pool, can_use_direct_http2_pool,
    extract_grpc_reject_message, finalize_plugin_rejection_parts_for_test,
    finalized_upload_deadline_response_for_test, insert_grpc_error_metadata,
    map_http_reject_status_to_grpc_status, normalize_reject_response, request_may_have_body,
    set_grpc_deadline_budget_for_test,
};
use ferrum_edge::config::types::Consumer;
use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::plugins::{
    Plugin, PluginResult, RequestContext, basic_auth::BasicAuth, jwt_auth::JwtAuth,
    key_auth::KeyAuth,
};
use ferrum_edge::proxy::grpc_proxy::grpc_status;
use ferrum_edge::proxy::run_authentication_phase;
use hyper::StatusCode;
use serde_json::json;
use std::sync::Arc;

struct ExternalIdentityAuth;

const BASIC_AUTH_TEST_SECRET: &str = "test-hmac-secret-for-basic-auth-unit-tests";

fn basic_auth_dispatch_consumer() -> Consumer {
    use hmac::{KeyInit, Mac};

    type HmacSha256 = hmac::Hmac<sha2::Sha256>;
    let mut mac = HmacSha256::new_from_slice(BASIC_AUTH_TEST_SECRET.as_bytes()).unwrap();
    mac.update(b"password");
    let password_hash = format!("hmac_sha256:{}", hex::encode(mac.finalize().into_bytes()));

    Consumer {
        id: "basic-dispatch-consumer".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "alice".to_string(),
        custom_id: None,
        credentials: HashMap::from([(
            "basicauth".to_string(),
            json!([{"password_hash": password_hash}]),
        )]),
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[async_trait]
impl Plugin for ExternalIdentityAuth {
    fn name(&self) -> &str {
        "external_identity_auth"
    }
    fn is_auth_plugin(&self) -> bool {
        true
    }
    async fn authenticate(
        &self,
        ctx: &mut RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        ctx.authenticated_identity = Some("external-user".to_string());
        ctx.authenticated_identity_header = Some("external@example.com".to_string());
        PluginResult::Continue
    }
}

struct RejectingAuth {
    body: &'static str,
}

struct StagedCookieRejectingAuth;

struct MixedCaseCookieRejectingAuth;

struct ScopedCookieStagingAuth {
    cookies: &'static str,
}

struct ScopedCookieSelectedAuth {
    cookies: &'static str,
}

#[async_trait]
impl Plugin for RejectingAuth {
    fn name(&self) -> &str {
        "rejecting_auth"
    }
    fn is_auth_plugin(&self) -> bool {
        true
    }
    async fn authenticate(
        &self,
        _ctx: &mut RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        PluginResult::Reject {
            status_code: 401,
            body: self.body.to_string(),
            headers: HashMap::new(),
        }
    }
}

#[async_trait]
impl Plugin for StagedCookieRejectingAuth {
    fn name(&self) -> &str {
        "staged_cookie_rejecting_auth"
    }

    fn is_auth_plugin(&self) -> bool {
        true
    }

    async fn authenticate(
        &self,
        ctx: &mut RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        ctx.metadata.insert(
            "auth.rejection_set_cookie".to_string(),
            "session=staged; Path=/staged; HttpOnly\nSession=case-sensitive; Path=/case\nstaged_only=1; Path=/staged\ndomain=staged; Domain=example.com; Path=/app\ndomain=staged-other; Domain=api.example.com; Path=/app\nhost_scope=staged; Path=/\nomitted=staged\nduplicate=staged; Path=/effective\nquoted=staged; Path=\"/quoted\"\nmalformed pair=staged; Path=/\nquoted_domain=staged; Domain=\".example.com\"; Path=/\ninvalid_path=staged; Path=\nvalue_space=staged; Path=/\nname_space=staged; Path=/"
                .to_string(),
        );
        PluginResult::Reject {
            status_code: 401,
            body: r#"{"error":"staged rejection"}"#.to_string(),
            headers: HashMap::new(),
        }
    }
}

#[async_trait]
impl Plugin for MixedCaseCookieRejectingAuth {
    fn name(&self) -> &str {
        "mixed_case_cookie_rejecting_auth"
    }

    fn is_auth_plugin(&self) -> bool {
        true
    }

    async fn authenticate(
        &self,
        _ctx: &mut RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        PluginResult::Reject {
            status_code: 403,
            body: r#"{"error":"mixed-case rejection"}"#.to_string(),
            headers: HashMap::from([
                (
                    "Set-Cookie".to_string(),
                    "session=selected-upper; Path=/upper; HttpOnly\nupper_only=1; Path=/upper\nshared=1; Path=/\nscoped=clear-root; Path=/\nscoped=clear-app; Path=/app\ndomain=selected; dOmAiN=.Example.COM; pAtH=/app\nhost_scope=selected; Domain=example.com; Path=/\nomitted=selected; Path=/\nduplicate=selected; Path=/ignored; PATH=/effective\nquoted=selected; Path=\"/quoted\"\nmalformed pair=selected; Path=/\nquoted_domain=selected; Domain=\".example.com\"; Path=/\ninvalid_path=selected; Path=\nvalue_space=selected ; Path=/\n name_space =selected; Path=/"
                        .to_string(),
                ),
                (
                    "set-cookie".to_string(),
                    "shared=1; Path=/\nlower_only=1; Path=/lower\nsession=selected-lower; Path=/lower; Secure; SameSite=Strict"
                        .to_string(),
                ),
                ("X-Rejection".to_string(), "selected".to_string()),
            ]),
        }
    }
}

#[async_trait]
impl Plugin for ScopedCookieStagingAuth {
    fn name(&self) -> &str {
        "scoped_cookie_staging_auth"
    }

    fn is_auth_plugin(&self) -> bool {
        true
    }

    async fn authenticate(
        &self,
        ctx: &mut RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        ctx.metadata.insert(
            "auth.rejection_set_cookie".to_string(),
            self.cookies.to_string(),
        );
        PluginResult::Reject {
            status_code: 401,
            body: r#"{"error":"staged rejection"}"#.to_string(),
            headers: HashMap::new(),
        }
    }
}

#[async_trait]
impl Plugin for ScopedCookieSelectedAuth {
    fn name(&self) -> &str {
        "scoped_cookie_selected_auth"
    }

    fn is_auth_plugin(&self) -> bool {
        true
    }

    async fn authenticate(
        &self,
        _ctx: &mut RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        PluginResult::Reject {
            status_code: 403,
            body: r#"{"error":"selected rejection"}"#.to_string(),
            headers: HashMap::from([("Set-Cookie".to_string(), self.cookies.to_string())]),
        }
    }
}

struct IdentityThenRejectAuth;

#[async_trait]
impl Plugin for IdentityThenRejectAuth {
    fn name(&self) -> &str {
        "identity_then_reject_auth"
    }

    fn is_auth_plugin(&self) -> bool {
        true
    }

    async fn authenticate(
        &self,
        ctx: &mut RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        ctx.authenticated_identity = Some("disabled-user".to_string());
        PluginResult::Reject {
            status_code: 403,
            body: r#"{"error":"account disabled"}"#.to_string(),
            headers: HashMap::new(),
        }
    }
}

struct ServerRejectingAuth;

#[async_trait]
impl Plugin for ServerRejectingAuth {
    fn name(&self) -> &str {
        "server_rejecting_auth"
    }

    fn is_auth_plugin(&self) -> bool {
        true
    }

    async fn authenticate(
        &self,
        _ctx: &mut RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        PluginResult::Reject {
            status_code: 503,
            body: r#"{"error":"Identity provider unavailable"}"#.to_string(),
            headers: HashMap::new(),
        }
    }
}

struct PendingAuth;

#[async_trait]
impl Plugin for PendingAuth {
    fn name(&self) -> &str {
        "pending_auth"
    }

    fn is_auth_plugin(&self) -> bool {
        true
    }

    async fn authenticate(
        &self,
        _ctx: &mut RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        std::future::pending().await
    }
}

struct DeadlineRejectDecorator;

struct PendingDeadlineRejectCleanup {
    started: Arc<std::sync::atomic::AtomicBool>,
    release: Arc<tokio::sync::Notify>,
    completed: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait]
impl Plugin for PendingDeadlineRejectCleanup {
    fn name(&self) -> &str {
        "pending_deadline_reject_cleanup"
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        true
    }

    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        self.started
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.release.notified().await;
        self.completed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        PluginResult::Continue
    }
}

struct DeadlineRejectCleanupFollower {
    calls: Arc<std::sync::atomic::AtomicUsize>,
    completed: Arc<tokio::sync::Notify>,
}

#[async_trait]
impl Plugin for DeadlineRejectCleanupFollower {
    fn name(&self) -> &str {
        "deadline_reject_cleanup_follower"
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        true
    }

    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.completed.notify_one();
        PluginResult::Continue
    }
}

#[async_trait]
impl Plugin for DeadlineRejectDecorator {
    fn name(&self) -> &str {
        "deadline_reject_decorator"
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        true
    }

    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        response_headers.insert("x-deadline-decorated".to_string(), "true".to_string());
        PluginResult::Continue
    }
}

struct DeadlineRejectReplacer;

struct DeadlineCommittedObserver {
    calls: Arc<std::sync::atomic::AtomicUsize>,
    saw_decorator: Arc<std::sync::atomic::AtomicBool>,
}

struct PendingDeadlineCommittedObserver {
    started: Arc<std::sync::atomic::AtomicBool>,
    release: Arc<tokio::sync::Notify>,
    completed: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait]
impl Plugin for PendingDeadlineCommittedObserver {
    fn name(&self) -> &str {
        "pending_deadline_committed_observer"
    }

    fn requires_response_committed_hook(&self) -> bool {
        true
    }

    async fn on_response_committed(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
        _body: &[u8],
    ) {
        self.started
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.release.notified().await;
        self.completed
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

struct DeadlineCommittedFollower {
    calls: Arc<std::sync::atomic::AtomicUsize>,
    completed: Arc<tokio::sync::Notify>,
}

#[async_trait]
impl Plugin for DeadlineCommittedFollower {
    fn name(&self) -> &str {
        "deadline_committed_follower"
    }

    fn requires_response_committed_hook(&self) -> bool {
        true
    }

    async fn on_response_committed(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
        _body: &[u8],
    ) {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.completed.notify_one();
    }
}

#[async_trait]
impl Plugin for DeadlineCommittedObserver {
    fn name(&self) -> &str {
        "deadline_committed_observer"
    }

    fn requires_response_committed_hook(&self) -> bool {
        true
    }

    async fn on_response_committed(
        &self,
        _ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
        _body: &[u8],
    ) {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if response_status == 200
            && response_headers
                .get("x-deadline-decorated")
                .is_some_and(|value| value == "true")
        {
            self.saw_decorator
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

#[async_trait]
impl Plugin for DeadlineRejectReplacer {
    fn name(&self) -> &str {
        "deadline_reject_replacer"
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        true
    }

    fn may_replace_rejection_response(&self) -> bool {
        true
    }

    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        PluginResult::Reject {
            status_code: 503,
            body: "must not replace terminal deadline".to_string(),
            headers: HashMap::from([("x-replaced".to_string(), "true".to_string())]),
        }
    }
}

struct PermissiveMissingMeshAuth;

#[async_trait]
impl Plugin for PermissiveMissingMeshAuth {
    fn name(&self) -> &str {
        "permissive_missing_mesh_auth"
    }

    fn is_auth_plugin(&self) -> bool {
        true
    }

    async fn authenticate(
        &self,
        ctx: &mut RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        ctx.metadata.insert(
            "mesh_request_auth.permissive_missing_token".to_string(),
            "true".to_string(),
        );
        PluginResult::Continue
    }
}

struct BodySuffixPlugin {
    suffix: &'static str,
}

struct MissingCredentialContinueAuth;

struct SkippedQueryCredentialAuth;

#[async_trait]
impl Plugin for SkippedQueryCredentialAuth {
    fn name(&self) -> &str {
        "skipped_query_credential_auth"
    }

    fn is_auth_plugin(&self) -> bool {
        true
    }

    fn mark_query_credentials_for_redaction(&self, ctx: &mut RequestContext) {
        if ctx.query_params.contains_key("custom_token") {
            ctx.metadata.insert(
                "auth.query_credential_param.custom_token".to_string(),
                "true".to_string(),
            );
        }
    }

    async fn authenticate(
        &self,
        _ctx: &mut RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        panic!("multi-auth should stop before the later query mechanism")
    }
}

#[async_trait]
impl Plugin for MissingCredentialContinueAuth {
    fn name(&self) -> &str {
        "missing_credential_continue_auth"
    }

    fn is_auth_plugin(&self) -> bool {
        true
    }

    async fn authenticate(
        &self,
        _ctx: &mut RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        PluginResult::Continue
    }
}

#[async_trait]
impl Plugin for BodySuffixPlugin {
    fn name(&self) -> &str {
        "body_suffix"
    }
    fn modifies_request_body(&self) -> bool {
        true
    }
    async fn transform_request_body(
        &self,
        body: &[u8],
        _content_type: Option<&str>,
        _request_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        let mut out = body.to_vec();
        out.extend_from_slice(self.suffix.as_bytes());
        Some(out)
    }
}

#[tokio::test]
async fn test_multi_auth_accepts_external_identity_without_consumer() {
    let external: Arc<dyn Plugin> = Arc::new(ExternalIdentityAuth);
    let rejecting: Arc<dyn Plugin> = Arc::new(RejectingAuth {
        body: r#"{"error":"Missing credentials"}"#,
    });
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![external, rejecting];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/jwks".to_string(),
    );

    let result =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index).await;

    assert!(result.is_none());
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("external-user"));
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_multi_auth_marks_query_credentials_before_first_success_short_circuits() {
    let external: Arc<dyn Plugin> = Arc::new(ExternalIdentityAuth);
    let skipped_query: Arc<dyn Plugin> = Arc::new(SkippedQueryCredentialAuth);
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![external, skipped_query];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/multi-auth".to_string(),
    );
    ctx.query_params
        .insert("custom_token".to_string(), "must-not-reach-opa".to_string());

    let result =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index).await;

    assert!(result.is_none());
    assert_eq!(
        ctx.metadata
            .get("auth.query_credential_param.custom_token")
            .map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn test_multi_auth_strips_skipped_key_auth_credentials_before_backend() {
    let external: Arc<dyn Plugin> = Arc::new(ExternalIdentityAuth);
    let header_key_auth: Arc<dyn Plugin> =
        Arc::new(KeyAuth::new(&json!({"key_location": "header:X-API-Key"})).unwrap());
    let query_key_auth: Arc<dyn Plugin> =
        Arc::new(KeyAuth::new(&json!({"key_location": "query:api_key"})).unwrap());
    let plugins = vec![external, header_key_auth, query_key_auth];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/multi-auth".to_string(),
    );
    ctx.headers.insert(
        "x-api-key".to_string(),
        "must-not-reach-backend".to_string(),
    );
    ctx.query_params
        .insert("api_key".to_string(), "must-not-reach-backend".to_string());

    let result =
        run_authentication_phase(AuthMode::Multi, &plugins, &mut ctx, &consumer_index).await;
    assert!(result.is_none(), "the earlier external auth should win");

    let mut backend_headers = ctx.headers.clone();
    for plugin in &plugins {
        assert!(matches!(
            plugin.before_proxy(&mut ctx, &mut backend_headers).await,
            PluginResult::Continue
        ));
    }

    assert!(!backend_headers.contains_key("x-api-key"));
    assert!(!ctx.query_params.contains_key("api_key"));
    assert_eq!(
        ctx.metadata
            .get("auth.strip_query_param.api_key")
            .map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn test_single_auth_missing_credentials_rejects_before_backend() {
    let key_auth: Arc<dyn Plugin> = Arc::new(KeyAuth::new(&json!({})).unwrap());
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![key_auth];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/key-auth".to_string(),
    );

    let result =
        run_authentication_phase(AuthMode::Single, &auth_plugins, &mut ctx, &consumer_index).await;

    let (status_code, body, headers) = result.expect("missing credentials should reject");
    assert_eq!(status_code, 401);
    assert_eq!(body, br#"{"error":"Authentication required"}"#);
    assert_eq!(
        headers.get("WWW-Authenticate").map(String::as_str),
        Some("ferrum-edge")
    );
    assert!(ctx.identified_consumer.is_none());
    assert!(ctx.authenticated_identity.is_none());
}

#[tokio::test]
async fn test_single_basic_auth_missing_credentials_uses_basic_challenge() {
    unsafe {
        std::env::set_var("FERRUM_BASIC_AUTH_HMAC_SECRET", BASIC_AUTH_TEST_SECRET);
    }
    let basic_auth: Arc<dyn Plugin> = Arc::new(BasicAuth::new(&json!({})).unwrap());
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/basic-auth".to_string(),
    );

    let result = run_authentication_phase(
        AuthMode::Single,
        &[basic_auth],
        &mut ctx,
        &ConsumerIndex::new(&[]),
    )
    .await;

    let (status, _body, headers) = result.expect("missing Basic credentials must reject");
    assert_eq!(status, 401);
    assert_eq!(
        headers.get("WWW-Authenticate").map(String::as_str),
        Some(r#"Basic realm="ferrum-edge", charset="UTF-8""#)
    );
}

#[tokio::test]
async fn test_multi_auth_missing_credentials_uses_first_available_challenge() {
    unsafe {
        std::env::set_var("FERRUM_BASIC_AUTH_HMAC_SECRET", BASIC_AUTH_TEST_SECRET);
    }
    let jwt: Arc<dyn Plugin> = Arc::new(JwtAuth::new(&json!({})).unwrap());
    let basic: Arc<dyn Plugin> = Arc::new(BasicAuth::new(&json!({})).unwrap());
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/mixed-auth".to_string(),
    );

    let result = run_authentication_phase(
        AuthMode::Multi,
        &[jwt, basic],
        &mut ctx,
        &ConsumerIndex::new(&[]),
    )
    .await;

    let (status, _body, headers) = result.expect("all-missing auth chain must reject");
    assert_eq!(status, 401);
    assert_eq!(
        headers.get("WWW-Authenticate").map(String::as_str),
        Some(r#"Basic realm="ferrum-edge", charset="UTF-8""#)
    );
}

#[tokio::test]
async fn test_single_auth_valid_basic_skips_earlier_jwt_scheme() {
    use base64::Engine;

    unsafe {
        std::env::set_var("FERRUM_BASIC_AUTH_HMAC_SECRET", BASIC_AUTH_TEST_SECRET);
    }
    let jwt: Arc<dyn Plugin> = Arc::new(JwtAuth::new(&json!({})).unwrap());
    let basic: Arc<dyn Plugin> = Arc::new(BasicAuth::new(&json!({})).unwrap());
    let auth_plugins = vec![jwt, basic];
    let consumer_index = ConsumerIndex::new(&[basic_auth_dispatch_consumer()]);
    let encoded = base64::engine::general_purpose::STANDARD.encode("alice:password");
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/mixed-auth".to_string(),
    );
    ctx.headers
        .insert("authorization".to_string(), format!("Basic {encoded}"));

    let result =
        run_authentication_phase(AuthMode::Single, &auth_plugins, &mut ctx, &consumer_index).await;

    assert!(result.is_none());
    assert_eq!(
        ctx.identified_consumer
            .as_ref()
            .map(|consumer| consumer.username.as_str()),
        Some("alice")
    );
}

#[tokio::test]
async fn test_single_auth_stops_before_later_reject_after_success() {
    let external: Arc<dyn Plugin> = Arc::new(ExternalIdentityAuth);
    let rejecting: Arc<dyn Plugin> = Arc::new(RejectingAuth {
        body: r#"{"error":"must not override success"}"#,
    });
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/mixed-auth".to_string(),
    );

    let result = run_authentication_phase(
        AuthMode::Single,
        &[external, rejecting],
        &mut ctx,
        &ConsumerIndex::new(&[]),
    )
    .await;

    assert!(result.is_none());
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("external-user"));
}

#[tokio::test]
async fn test_single_auth_preserves_reject_from_plugin_that_sets_identity() {
    let plugin: Arc<dyn Plugin> = Arc::new(IdentityThenRejectAuth);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/mixed-auth".to_string(),
    );

    let result = run_authentication_phase(
        AuthMode::Single,
        &[plugin],
        &mut ctx,
        &ConsumerIndex::new(&[]),
    )
    .await;

    let (status, body, _headers) = result.expect("same-plugin rejection must remain terminal");
    assert_eq!(status, 403);
    assert_eq!(body, br#"{"error":"account disabled"}"#);
}

#[tokio::test]
async fn test_multi_auth_all_missing_credentials_rejects_before_backend() {
    let key_auth: Arc<dyn Plugin> = Arc::new(KeyAuth::new(&json!({})).unwrap());
    let rejecting: Arc<dyn Plugin> = Arc::new(
        KeyAuth::new(&json!({
            "key_location": "query:api_key"
        }))
        .unwrap(),
    );
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![key_auth, rejecting];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/key-auth".to_string(),
    );

    let result =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index).await;

    let (status_code, body, headers) = result.expect("all-missing multi-auth should reject");
    assert_eq!(status_code, 401);
    assert_eq!(body, br#"{"error":"Authentication required"}"#);
    assert_eq!(
        headers.get("WWW-Authenticate").map(String::as_str),
        Some("ferrum-edge")
    );
    assert!(ctx.identified_consumer.is_none());
    assert!(ctx.authenticated_identity.is_none());
}

#[tokio::test]
async fn test_multi_auth_preserves_specific_reject_when_surrounded_by_missing() {
    let missing_header: Arc<dyn Plugin> = Arc::new(KeyAuth::new(&json!({})).unwrap());
    let specific_reject: Arc<dyn Plugin> = Arc::new(RejectingAuth {
        body: r#"{"error":"Specific auth failure"}"#,
    });
    let missing_query: Arc<dyn Plugin> = Arc::new(
        KeyAuth::new(&json!({
            "key_location": "query:api_key"
        }))
        .unwrap(),
    );
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![missing_header, specific_reject, missing_query];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/key-auth".to_string(),
    );

    let result =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index).await;

    let (status_code, body, _headers) =
        result.expect("specific reject should win over generic missing fallback");
    assert_eq!(status_code, 401);
    assert_eq!(body, br#"{"error":"Specific auth failure"}"#);
    assert!(ctx.identified_consumer.is_none());
    assert!(ctx.authenticated_identity.is_none());
}

#[tokio::test]
async fn test_multi_auth_deadline_expiry_overrides_earlier_server_reject() {
    let deadline_plugin =
        ferrum_edge::plugins::create_plugin("grpc_deadline", &json!({"default_deadline_ms": 10}))
            .unwrap()
            .unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/my.Service/Unary".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/grpc".to_string());
    assert!(matches!(
        ferrum_edge::plugins::grpc_deadline::prepare_request_deadline(&[deadline_plugin], &mut ctx,),
        PluginResult::Continue
    ));

    let auth_plugins: Vec<Arc<dyn Plugin>> =
        vec![Arc::new(ServerRejectingAuth), Arc::new(PendingAuth)];
    let rejection = run_authentication_phase(
        AuthMode::Multi,
        &auth_plugins,
        &mut ctx,
        &ConsumerIndex::new(&[]),
    )
    .await
    .expect("expired authentication phase must reject");

    assert_eq!(rejection.0, 200);
    assert!(rejection.1.is_empty());
    assert_eq!(
        rejection.2.get("grpc-status").map(String::as_str),
        Some("4")
    );
    assert_eq!(
        rejection.2.get("grpc-message").map(String::as_str),
        Some("Deadline exceeded at gateway")
    );
}

#[tokio::test]
async fn terminal_deadline_reject_runs_decorators_but_not_replacers() {
    use ferrum_edge::_test_support::mark_gateway_deadline_response_selected_for_test;

    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(DeadlineRejectDecorator),
        Arc::new(DeadlineRejectReplacer),
    ];
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/my.Service/Unary".to_string(),
    );
    set_grpc_deadline_budget_for_test(&mut ctx, Some(0));
    mark_gateway_deadline_response_selected_for_test(&mut ctx);

    let (status, body, headers) = finalize_plugin_rejection_parts_for_test(
        &plugins,
        &mut ctx,
        200,
        Vec::new(),
        HashMap::from([
            ("content-type".to_string(), "application/grpc".to_string()),
            ("grpc-status".to_string(), "4".to_string()),
            (
                "grpc-message".to_string(),
                "Deadline exceeded at gateway".to_string(),
            ),
        ]),
    )
    .await;

    assert_eq!(status, 200);
    assert!(body.is_empty());
    assert_eq!(headers.get("grpc-status").map(String::as_str), Some("4"));
    assert_eq!(
        headers.get("grpc-message").map(String::as_str),
        Some("Deadline exceeded at gateway")
    );
    assert_eq!(
        headers.get("x-deadline-decorated").map(String::as_str),
        Some("true"),
        "header-only rejection decorators must complete after deadline expiry"
    );
    assert!(
        !headers.contains_key("x-replaced"),
        "an expired fail-closed replacer must not override the terminal deadline"
    );
}

#[tokio::test]
async fn rejection_hook_pending_at_deadline_does_not_delay_status_four() {
    let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let release = Arc::new(tokio::sync::Notify::new());
    let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let follower_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let follower_completed = Arc::new(tokio::sync::Notify::new());
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(PendingDeadlineRejectCleanup {
            started: Arc::clone(&started),
            release: Arc::clone(&release),
            completed: Arc::clone(&completed),
        }),
        Arc::new(DeadlineRejectCleanupFollower {
            calls: Arc::clone(&follower_calls),
            completed: Arc::clone(&follower_completed),
        }),
    ];
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/my.Service/Unary".to_string(),
    );
    set_grpc_deadline_budget_for_test(&mut ctx, Some(20));

    let (status, body, headers) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        finalize_plugin_rejection_parts_for_test(
            &plugins,
            &mut ctx,
            503,
            b"backend unavailable".to_vec(),
            HashMap::new(),
        ),
    )
    .await
    .expect("a pending rejection cleanup hook must not retain the client response");

    assert_eq!(status, 200);
    assert!(body.is_empty());
    assert_eq!(headers.get("grpc-status").map(String::as_str), Some("4"));
    assert!(started.load(std::sync::atomic::Ordering::SeqCst));
    assert!(!completed.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        follower_calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "ordered cleanup must wait for the pending hook on detached state"
    );

    release.notify_waiters();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        follower_completed.notified(),
    )
    .await
    .expect("detached rejection cleanup must continue in plugin order");
    assert!(completed.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(follower_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn deadline_text_without_typed_provenance_does_not_claim_gateway_ownership() {
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(DeadlineRejectReplacer)];
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/my.Service/Unary".to_string(),
    );

    let (status, body, headers) = finalize_plugin_rejection_parts_for_test(
        &plugins,
        &mut ctx,
        200,
        Vec::new(),
        HashMap::from([
            ("content-type".to_string(), "application/grpc".to_string()),
            ("grpc-status".to_string(), "4".to_string()),
            (
                "grpc-message".to_string(),
                "Deadline exceeded at gateway".to_string(),
            ),
        ]),
    )
    .await;

    assert_eq!(status, 503);
    assert_eq!(body.as_slice(), b"must not replace terminal deadline");
    assert_eq!(headers.get("x-replaced").map(String::as_str), Some("true"));
}

#[tokio::test]
async fn grpc_web_upload_deadline_finalization_preserves_decorators_and_committed_cleanup() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let saw_decorator = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(DeadlineRejectDecorator),
        Arc::new(DeadlineCommittedObserver {
            calls: Arc::clone(&calls),
            saw_decorator: Arc::clone(&saw_decorator),
        }),
    ];
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/my.Service/Unary".to_string(),
    );
    set_grpc_deadline_budget_for_test(&mut ctx, Some(0));

    let response = finalized_upload_deadline_response_for_test(
        &plugins,
        &mut ctx,
        Some("application/grpc-web+proto"),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-deadline-decorated")
            .and_then(|value| value.to_str().ok()),
        Some("true"),
        "gRPC-Web translation must preserve finalized rejection decorators"
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(
        saw_decorator.load(std::sync::atomic::Ordering::SeqCst),
        "the committed observer must see the translated decorated response exactly once"
    );
}

#[tokio::test]
async fn pending_committed_observer_does_not_retain_terminal_deadline_response() {
    let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let release = Arc::new(tokio::sync::Notify::new());
    let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let follower_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let follower_completed = Arc::new(tokio::sync::Notify::new());
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(PendingDeadlineCommittedObserver {
            started: Arc::clone(&started),
            release: Arc::clone(&release),
            completed: Arc::clone(&completed),
        }),
        Arc::new(DeadlineCommittedFollower {
            calls: Arc::clone(&follower_calls),
            completed: Arc::clone(&follower_completed),
        }),
    ];
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/my.Service/Unary".to_string(),
    );
    set_grpc_deadline_budget_for_test(&mut ctx, Some(0));

    let response = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        finalized_upload_deadline_response_for_test(&plugins, &mut ctx, None),
    )
    .await
    .expect("a pending committed observer must not retain the terminal response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("4")
    );
    assert!(started.load(std::sync::atomic::Ordering::SeqCst));
    assert!(!completed.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(follower_calls.load(std::sync::atomic::Ordering::SeqCst), 0);

    release.notify_waiters();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        follower_completed.notified(),
    )
    .await
    .expect("detached committed observers must continue in plugin order");
    assert!(completed.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(follower_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn upload_deadline_exits_use_finalized_rejection_cleanup_and_logging() {
    let source = include_str!("../../../src/proxy/mod.rs");
    let finalization = source
        .split("async fn build_finalized_upload_deadline_response(")
        .nth(1)
        .expect("shared upload-deadline response finalization")
        .split("async fn finalize_upload_deadline_rejection(")
        .next()
        .expect("bounded upload-deadline response finalization");
    assert!(
        finalization.contains("finalize_reject_response_with_after_proxy_hooks_and_commit_policy(")
    );
    assert!(finalization.contains("build_grpc_web_reject_response("));
    assert_eq!(
        finalization
            .matches("finalize_reject_response_with_after_proxy_hooks_and_commit_policy(")
            .count(),
        1
    );
    assert_eq!(
        finalization
            .matches("build_grpc_web_reject_response(")
            .count(),
        1
    );

    let helper = source
        .split("async fn finalize_upload_deadline_rejection(")
        .nth(1)
        .expect("shared upload-deadline rejection finalizer")
        .split("fn release_circuit_breaker_probe_on_admission_reject")
        .next()
        .expect("bounded upload-deadline finalizer");
    assert!(helper.contains("build_finalized_upload_deadline_response("));
    assert!(helper.contains("log_rejected_request_with_path("));
    assert!(helper.contains("record_request(state,"));
    assert_eq!(
        helper
            .matches("build_finalized_upload_deadline_response(")
            .count(),
        1
    );
    assert_eq!(helper.matches("log_rejected_request_with_path(").count(), 1);
    assert_eq!(helper.matches("record_request(state,").count(), 1);
    let finalize = helper
        .find("build_finalized_upload_deadline_response(")
        .expect("upload deadline finalization");
    let log = helper
        .find("log_rejected_request_with_path(")
        .expect("upload deadline log");
    let metric = helper
        .find("record_request(state,")
        .expect("upload deadline metric");
    assert!(finalize < log && log < metric);

    for phase in [
        "grpc_deadline_upload_before_authenticate",
        "grpc_deadline_upload_before_authorize",
        "grpc_deadline_upload_before_before_proxy",
        "grpc_deadline_terminal_request_body",
        "grpc_deadline_upload_before_dispatch",
        "grpc_deadline_buffered_grpc_upload",
    ] {
        assert!(
            source.contains(phase),
            "missing finalized upload deadline phase {phase}"
        );
    }
    assert_eq!(
        source
            .matches("finalize_upload_deadline_rejection(")
            .count(),
        8,
        "the helper definition plus all seven H1/H2 buffered upload exits must stay routed through cleanup"
    );

    let grpc_collect_deadline_branches: Vec<&str> = source
        .split("Err(grpc_proxy::GrpcRequestBodyCollectError::DeadlineExceeded) => {")
        .skip(1)
        .map(|branch| {
            branch
                .split("Err(grpc_proxy::GrpcRequestBodyCollectError::Proxy")
                .next()
                .expect("bounded buffered gRPC deadline branch")
        })
        .collect();
    assert_eq!(grpc_collect_deadline_branches.len(), 2);
    for branch in grpc_collect_deadline_branches {
        assert!(branch.contains("grpc_probe_guard.disarm()"));
        assert!(branch.contains("release_circuit_breaker_probe_on_admission_reject("));
        assert!(branch.contains("preacquired_backend_admission.take_if_acquired()"));
    }
}

#[test]
fn streaming_deadline_wraps_client_visible_body_after_inspection() {
    let source = include_str!("../../../src/proxy/mod.rs");
    for (arm, next_arm) in [
        (
            "ResponseBody::StreamingH2(resp) => {",
            "ResponseBody::StreamingH3(h3_resp) => {",
        ),
        (
            "ResponseBody::StreamingH3(h3_resp) => {",
            "ResponseBody::Buffered(data) => {",
        ),
    ] {
        let body = source
            .split(arm)
            .nth(1)
            .unwrap_or_else(|| panic!("missing {arm}"))
            .split(next_arm)
            .next()
            .expect("bounded streaming response arm");
        let inspection = body
            .find("run_proxy_body_response_inspection(")
            .unwrap_or_else(|| panic!("missing inspector construction in {arm}"));
        let deadline = body
            .find("with_client_grpc_deadline(")
            .unwrap_or_else(|| panic!("missing client-visible deadline wrapper in {arm}"));
        assert!(
            inspection < deadline,
            "{arm} must base the deadline DATA decision on inspector output"
        );
    }
}

#[test]
fn generic_retry_backoff_uses_request_aware_grpc_deadline_response() {
    let source = include_str!("../../../src/proxy/mod.rs");
    let retry_loop = source
        .find("while retry::should_retry(retry_config, &method, &result, attempt) {")
        .expect("generic HTTP retry loop must remain present");
    let retry_loop = &source[retry_loop..];
    let backoff_end = retry_loop
        .find("attempt += 1;")
        .expect("generic HTTP retry backoff must remain present");
    let backoff = &retry_loop[..backoff_end];

    assert!(
        backoff.contains("client_grpc_deadline_exceeded_response_for_request("),
        "gRPC-Web retry-backoff expiry must use the request-aware deadline shaper"
    );
    assert!(
        !backoff
            .contains("client_grpc_deadline_exceeded_response(result.backend_resolved_ip.clone())"),
        "the generic retry backoff must not regress to native-only gRPC framing"
    );
    assert!(backoff.contains("&ctx,"));
    assert!(backoff.contains("owned_proxy_headers_ref.unwrap_or(&ctx.headers),"));
}

#[test]
fn direct_h2_response_header_wait_uses_earliest_client_or_operator_deadline() {
    use ferrum_edge::_test_support::response_header_deadline_for_test;

    assert_eq!(
        response_header_deadline_for_test(Some(500), 50),
        Some((false, 50))
    );
    assert_eq!(
        response_header_deadline_for_test(Some(50), 500),
        Some((true, 50))
    );
    assert_eq!(
        response_header_deadline_for_test(Some(50), 0),
        Some((true, 50))
    );
    assert_eq!(
        response_header_deadline_for_test(None, 50),
        Some((false, 50))
    );
    assert_eq!(response_header_deadline_for_test(None, 0), None);
}

#[test]
fn streaming_grpc_deadline_removes_backend_content_length_before_headers_commit() {
    use ferrum_edge::_test_support::strip_content_length_for_streaming_grpc_deadline_for_test;

    let mut deadline_headers = HashMap::from([
        ("content-type".to_string(), "application/grpc".to_string()),
        ("content-length".to_string(), "128".to_string()),
    ]);
    strip_content_length_for_streaming_grpc_deadline_for_test(&mut deadline_headers, true);
    assert!(!deadline_headers.contains_key("content-length"));

    let mut unbounded_headers = HashMap::from([("content-length".to_string(), "128".to_string())]);
    strip_content_length_for_streaming_grpc_deadline_for_test(&mut unbounded_headers, false);
    assert_eq!(
        unbounded_headers.get("content-length").map(String::as_str),
        Some("128")
    );
}

#[test]
fn mesh_mtls_arms_operator_read_window_after_sender_readiness() {
    let source = include_str!("../../../src/proxy/mod.rs");
    let function = source
        .split("async fn proxy_to_backend_mesh_mtls")
        .nth(1)
        .expect("mesh mTLS dispatch function")
        .split("async fn proxy_to_backend_http2")
        .next()
        .expect("mesh mTLS dispatch body");
    let readiness = function
        .find("sender.ready()")
        .expect("sender readiness boundary");
    let read_window = function
        .find("let backend_read_deadline")
        .expect("operator read window");

    assert!(
        readiness < read_window,
        "operator response-read timeout must not include pool acquisition/readiness"
    );
}

#[test]
fn grpc_deadline_phase_zero_precedes_request_security_hooks_on_h1_h2_and_h3() {
    let h1_h2 = include_str!("../../../src/proxy/mod.rs")
        .split("async fn handle_proxy_request_inner")
        .nth(1)
        .expect("H1/H2 request handler");
    let h3 = include_str!("../../../src/http3/server.rs")
        .split("let prepared = crate::plugins::grpc_deadline::prepare_request_deadline")
        .nth(1)
        .expect("H3 deadline preflight tail");

    let h1_h2_deadline = h1_h2
        .find("prepare_request_deadline")
        .expect("H1/H2 deadline preflight");
    let h1_h2_request_hooks = h1_h2
        .find("// Execute on_request_received hooks")
        .expect("H1/H2 request hook phase");
    let h1_h2_auth = h1_h2
        .find("run_authentication_phase")
        .expect("H1/H2 authentication phase");
    assert!(h1_h2_deadline < h1_h2_request_hooks);
    assert!(h1_h2_deadline < h1_h2_auth);

    let h3_request_hooks = h3
        .find("// Execute on_request_received hooks")
        .expect("H3 request hook phase");
    let h3_auth = h3
        .find("run_authentication_phase")
        .expect("H3 authentication phase");
    assert!(h3_request_hooks > 0);
    assert!(h3_auth > 0);
}

#[test]
fn grpc_deadline_hot_paths_use_cached_preflight_lists_without_deadline_only_context_clones() {
    for (surface, source) in [
        ("H1/H2", include_str!("../../../src/proxy/mod.rs")),
        ("H3", include_str!("../../../src/http3/server.rs")),
    ] {
        let call = source
            .split("prepare_request_deadline(")
            .nth(1)
            .unwrap_or_else(|| panic!("{surface}: deadline preflight"));
        assert!(
            call.starts_with("\n            plugin_cache_view.grpc_deadline_plugins(),"),
            "{surface}: preflight must use the PluginCache capability list"
        );
        assert!(
            !source.contains("needs_final_request_body_context ||"),
            "{surface}: a deadline alone must not clone final-body RequestContext"
        );
        assert!(
            source.contains("plugin_cache_view.response_committed_plugins(),"),
            "{surface}: committed hooks must use the PluginCache observer list"
        );
    }
}

#[tokio::test]
async fn test_auth_rejection_merges_all_set_cookie_case_variants_deterministically() {
    let staged: Arc<dyn Plugin> = Arc::new(StagedCookieRejectingAuth);
    let selected: Arc<dyn Plugin> = Arc::new(MixedCaseCookieRejectingAuth);
    let auth_plugins = [staged, selected];
    let consumer_index = ConsumerIndex::new(&[]);
    let expected = "session=selected-upper; Path=/upper; HttpOnly\nupper_only=1; Path=/upper\nscoped=clear-root; Path=/\nscoped=clear-app; Path=/app\ndomain=selected; dOmAiN=.Example.COM; pAtH=/app\nhost_scope=selected; Domain=example.com; Path=/\nomitted=selected; Path=/\nduplicate=selected; Path=/ignored; PATH=/effective\nquoted=selected; Path=\"/quoted\"\nmalformed pair=selected; Path=/\nquoted_domain=selected; Domain=\".example.com\"; Path=/\ninvalid_path=selected; Path=\nvalue_space=selected ; Path=/\n name_space =selected; Path=/\nshared=1; Path=/\nlower_only=1; Path=/lower\nsession=selected-lower; Path=/lower; Secure; SameSite=Strict\nsession=staged; Path=/staged; HttpOnly\nSession=case-sensitive; Path=/case\nstaged_only=1; Path=/staged\ndomain=staged-other; Domain=api.example.com; Path=/app\nhost_scope=staged; Path=/\nmalformed pair=staged; Path=/\nquoted_domain=staged; Domain=\".example.com\"; Path=/";

    for _ in 0..32 {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/mixed-cookie-rejection".to_string(),
        );
        let (status_code, body, headers) =
            run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index)
                .await
                .expect("both auth attempts must reject");

        assert_eq!(status_code, 403);
        assert_eq!(body, br#"{"error":"mixed-case rejection"}"#);
        assert_eq!(
            headers.get("X-Rejection").map(String::as_str),
            Some("selected")
        );
        assert_eq!(
            headers.get("set-cookie").map(String::as_str),
            Some(expected)
        );
        assert_eq!(
            headers
                .keys()
                .filter(|name| name.eq_ignore_ascii_case("set-cookie"))
                .count(),
            1
        );
        assert_eq!(
            headers["set-cookie"]
                .split('\n')
                .filter(|cookie| *cookie == "shared=1; Path=/")
                .count(),
            1,
            "identical cookie lines must not multiply"
        );
        assert!(
            !ctx.metadata.contains_key("auth.rejection_set_cookie"),
            "the staged cookies must be consumed exactly once"
        );
    }
}

#[tokio::test]
async fn test_auth_rejection_cookie_storage_key_preserves_extended_scopes() {
    let staged: Arc<dyn Plugin> = Arc::new(ScopedCookieStagingAuth {
        cookies: "non_ldh=staged; Domain=foo_bar.example; Path=/\nip_literal=staged; Domain=[0:0:0:0:0:0:0:1]; Path=/\ninvalid_ip=staged; Domain=[not-an-ip]; Path=/\npartitioned_same=staged; Secure; pArTiTiOnEd; Path=/\npartitioned_split=staged; Secure; Path=/\npartitioned_reverse=staged; Secure; PARTITIONED; Path=/\ndot_scope=staged; Path=/\ntrailing_dot=staged; Path=/\ntrailing_dot_prior=staged; Domain=example.com; Path=/\nempty_domain=staged; Domain=example.com; Path=/\nbare_domain=staged; Domain=example.com; Path=/\nonly_empty=staged; Path=/\nonly_bare=staged; Path=/",
    });
    let selected: Arc<dyn Plugin> = Arc::new(ScopedCookieSelectedAuth {
        cookies: "non_ldh=selected; Domain=foo_bar.example; Path=/\nip_literal=selected; Domain=[::1]; Path=/\ninvalid_ip=selected; Domain=[not-an-ip]; Path=/\npartitioned_same=selected; Secure; Partitioned; Path=/\npartitioned_split=selected; Secure; Partitioned; Path=/\npartitioned_reverse=selected; Secure; Path=/\ndot_scope=selected; Domain=example.com; Path=/\ntrailing_dot=selected; Domain=example.com.; Path=/\ntrailing_dot_prior=selected; Domain=example.com; Domain=other.example.; Path=/\nempty_domain=selected; Domain=example.com; Domain=; Path=/\nbare_domain=selected; Domain=example.com; Domain; Path=/\nonly_empty=selected; Domain=; Path=/\nonly_bare=selected; Domain; Path=/",
    });
    let auth_plugins = [staged, selected];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/cookie-scope".to_string(),
    );
    ctx.request_is_secure = true;
    ctx.request_authority = Some("[::1]".to_string());

    let (_, _, headers) =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index)
            .await
            .expect("both auth attempts must reject");

    assert_eq!(
        headers.get("set-cookie").map(String::as_str),
        Some(
            "non_ldh=selected; Domain=foo_bar.example; Path=/\nip_literal=selected; Domain=[::1]; Path=/\ninvalid_ip=selected; Domain=[not-an-ip]; Path=/\npartitioned_same=selected; Secure; Partitioned; Path=/\npartitioned_split=selected; Secure; Partitioned; Path=/\npartitioned_reverse=selected; Secure; Path=/\ndot_scope=selected; Domain=example.com; Path=/\ntrailing_dot=selected; Domain=example.com.; Path=/\ntrailing_dot_prior=selected; Domain=example.com; Domain=other.example.; Path=/\nempty_domain=selected; Domain=example.com; Domain=; Path=/\nbare_domain=selected; Domain=example.com; Domain; Path=/\nonly_empty=selected; Domain=; Path=/\nonly_bare=selected; Domain; Path=/\ninvalid_ip=staged; Domain=[not-an-ip]; Path=/\npartitioned_split=staged; Secure; Path=/\npartitioned_reverse=staged; Secure; PARTITIONED; Path=/\ndot_scope=staged; Path=/\ntrailing_dot=staged; Path=/\ntrailing_dot_prior=staged; Domain=example.com; Path=/"
        )
    );
}

#[tokio::test]
async fn test_auth_rejection_cookie_storage_key_treats_matching_ip_domain_as_host_only() {
    for (authority, selected_cookie) in [
        ("127.0.0.1", "session=selected; Domain=127.0.0.1; Path=/"),
        (
            "[::1]",
            "session=selected; Domain=[0:0:0:0:0:0:0:1]; Path=/",
        ),
    ] {
        let staged: Arc<dyn Plugin> = Arc::new(ScopedCookieStagingAuth {
            cookies: "session=staged; Path=/",
        });
        let selected: Arc<dyn Plugin> = Arc::new(ScopedCookieSelectedAuth {
            cookies: selected_cookie,
        });
        let auth_plugins = [staged, selected];
        let consumer_index = ConsumerIndex::new(&[]);
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/cookie-scope".to_string(),
        );
        ctx.request_authority = Some(authority.to_string());

        let (_, _, headers) =
            run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index)
                .await
                .expect("both auth attempts must reject");

        assert_eq!(
            headers.get("set-cookie").map(String::as_str),
            Some(selected_cookie),
            "an exact-IP Domain must own the request host's host-only cookie"
        );
    }
}

#[tokio::test]
async fn test_auth_rejection_cookie_storage_key_rejects_nonmatching_ip_domain() {
    let staged: Arc<dyn Plugin> = Arc::new(ScopedCookieStagingAuth {
        cookies: "session=staged; Path=/",
    });
    let selected: Arc<dyn Plugin> = Arc::new(ScopedCookieSelectedAuth {
        cookies: "session=selected; Domain=127.0.0.2; Path=/",
    });
    let auth_plugins = [staged, selected];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/cookie-scope".to_string(),
    );
    ctx.request_authority = Some("127.0.0.1".to_string());

    let (_, _, headers) =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index)
            .await
            .expect("both auth attempts must reject");

    assert_eq!(
        headers.get("set-cookie").map(String::as_str),
        Some("session=selected; Domain=127.0.0.2; Path=/\nsession=staged; Path=/")
    );
}

#[tokio::test]
async fn test_auth_rejection_cookie_storage_key_normalizes_matching_public_suffix_domain() {
    let staged: Arc<dyn Plugin> = Arc::new(ScopedCookieStagingAuth {
        cookies: "session=staged; Path=/",
    });
    let selected: Arc<dyn Plugin> = Arc::new(ScopedCookieSelectedAuth {
        cookies: "session=selected; Domain=github.io; Path=/",
    });
    let auth_plugins = [staged, selected];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/cookie-scope".to_string(),
    );
    ctx.request_authority = Some("github.io".to_string());

    let (_, _, headers) =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index)
            .await
            .expect("both auth attempts must reject");

    assert_eq!(
        headers.get("set-cookie").map(String::as_str),
        Some("session=selected; Domain=github.io; Path=/"),
        "a public-suffix Domain equal to the request host becomes host-only and owns the staged host cookie"
    );
}

#[tokio::test]
async fn test_auth_rejection_cookie_storage_key_rejects_nonmatching_public_suffix_domain() {
    let staged: Arc<dyn Plugin> = Arc::new(ScopedCookieStagingAuth {
        cookies: "session=staged; Path=/",
    });
    let selected: Arc<dyn Plugin> = Arc::new(ScopedCookieSelectedAuth {
        cookies: "session=selected; Domain=github.io; Path=/",
    });
    let auth_plugins = [staged, selected];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/cookie-scope".to_string(),
    );
    ctx.request_authority = Some("app.github.io".to_string());

    let (_, _, headers) =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index)
            .await
            .expect("both auth attempts must reject");

    assert_eq!(
        headers.get("set-cookie").map(String::as_str),
        Some("session=selected; Domain=github.io; Path=/\nsession=staged; Path=/"),
        "a public-suffix Domain that differs from the request host is rejected and cannot suppress a storable staged cookie"
    );
}

#[tokio::test]
async fn test_auth_rejection_cookie_storage_key_preserves_distinct_host_only_and_domain_scopes() {
    for (authority, staged_cookie, selected_cookie) in [
        (
            "example.com",
            "oidc_session=; Max-Age=0; Path=/",
            "oidc_session=selected; Domain=example.com; Path=/",
        ),
        (
            "example.com:8443",
            "rolling_session=rotated; Domain=.EXAMPLE.COM; Path=/",
            "rolling_session=selected; Path=/",
        ),
    ] {
        let staged: Arc<dyn Plugin> = Arc::new(ScopedCookieStagingAuth {
            cookies: staged_cookie,
        });
        let selected: Arc<dyn Plugin> = Arc::new(ScopedCookieSelectedAuth {
            cookies: selected_cookie,
        });
        let auth_plugins = [staged, selected];
        let consumer_index = ConsumerIndex::new(&[]);
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/cookie-scope".to_string(),
        );
        ctx.request_authority = Some(authority.to_string());

        let (_, _, headers) =
            run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index)
                .await
                .expect("both auth attempts must reject");
        let expected = format!("{selected_cookie}\n{staged_cookie}");

        assert_eq!(
            headers.get("set-cookie").map(String::as_str),
            Some(expected.as_str()),
            "a security-relevant staged cookie must coexist with a selected cookie using the opposite host-only/domain scope"
        );
    }
}

#[tokio::test]
async fn test_auth_rejection_cookie_storage_key_rejects_oversized_selected_cookie_pair() {
    let boundary_name = "boundary";
    let boundary_value = "b".repeat(4096 - boundary_name.len());
    let boundary_cookie = format!("{boundary_name}={boundary_value}; Path=/");
    let oversized_name = "oversized";
    let oversized_value = "o".repeat(4097 - oversized_name.len());
    let oversized_cookie = format!("{oversized_name}={oversized_value}; Path=/");
    let selected_cookies: &'static str =
        Box::leak(format!("{oversized_cookie}\n{boundary_cookie}").into_boxed_str());

    let staged: Arc<dyn Plugin> = Arc::new(ScopedCookieStagingAuth {
        cookies: "oversized=; Max-Age=0; Path=/\nboundary=staged; Path=/",
    });
    let selected: Arc<dyn Plugin> = Arc::new(ScopedCookieSelectedAuth {
        cookies: selected_cookies,
    });
    let auth_plugins = [staged, selected];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/cookie-scope".to_string(),
    );
    ctx.request_authority = Some("example.com".to_string());

    let (_, _, headers) =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index)
            .await
            .expect("both auth attempts must reject");
    let emitted = headers["set-cookie"].split('\n').collect::<Vec<_>>();

    assert_eq!(emitted.len(), 3);
    assert_eq!(emitted[0], oversized_cookie);
    assert_eq!(emitted[1], boundary_cookie);
    assert_eq!(emitted[2], "oversized=; Max-Age=0; Path=/");
    assert!(
        !emitted.contains(&"boundary=staged; Path=/"),
        "a 4096-octet selected name/value pair remains comparable"
    );
}

#[tokio::test]
async fn test_auth_rejection_cookie_storage_key_applies_secure_prefixes_case_insensitively() {
    let staged: Arc<dyn Plugin> = Arc::new(ScopedCookieStagingAuth {
        cookies: "partitioned=staged; Secure; Partitioned; Path=/\nsame_site=staged; Secure; SameSite=None; Path=/\n__Secure-token=staged; Secure; Path=/\n__sEcUrE-case=staged; Secure; Path=/\n__hOsT-token=staged; Secure; Path=/\n__Host-path=staged; Secure; Path=/\n__Host-domain=staged; Secure; Path=/\nsame_site_last=staged; Path=/",
    });
    let selected: Arc<dyn Plugin> = Arc::new(ScopedCookieSelectedAuth {
        cookies: "partitioned=selected; Partitioned; Path=/\nsame_site=selected; SameSite=None; Path=/\n__Secure-token=selected; Path=/\n__sEcUrE-case=selected; Path=/\n__hOsT-token=selected; Path=/\n__Host-path=selected; Secure\n__Host-domain=selected; Secure; Domain=example.com; Path=/\nsame_site_last=selected; SameSite=None; SameSite=Lax; Path=/",
    });
    let auth_plugins = [staged, selected];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/cookie-scope".to_string(),
    );
    ctx.request_is_secure = true;

    let (_, _, headers) =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index)
            .await
            .expect("both auth attempts must reject");

    assert_eq!(
        headers.get("set-cookie").map(String::as_str),
        Some(
            "partitioned=selected; Partitioned; Path=/\nsame_site=selected; SameSite=None; Path=/\n__Secure-token=selected; Path=/\n__sEcUrE-case=selected; Path=/\n__hOsT-token=selected; Path=/\n__Host-path=selected; Secure\n__Host-domain=selected; Secure; Domain=example.com; Path=/\nsame_site_last=selected; SameSite=None; SameSite=Lax; Path=/\npartitioned=staged; Secure; Partitioned; Path=/\nsame_site=staged; Secure; SameSite=None; Path=/\n__Secure-token=staged; Secure; Path=/\n__sEcUrE-case=staged; Secure; Path=/\n__hOsT-token=staged; Secure; Path=/\n__Host-path=staged; Secure; Path=/\n__Host-domain=staged; Secure; Path=/"
        )
    );
}

#[tokio::test]
async fn test_auth_rejection_cookie_storage_key_applies_http_prefixes_case_insensitively() {
    let staged: Arc<dyn Plugin> = Arc::new(ScopedCookieStagingAuth {
        cookies: "__Http-session=staged; Secure; HttpOnly; Path=/\n__hOsT-hTtP-session=staged; Secure; HttpOnly; Path=/\n__hTtP-case=staged; Secure; HttpOnly; Path=/\n__Http-valid=staged; Secure; HttpOnly; Path=/",
    });
    let selected: Arc<dyn Plugin> = Arc::new(ScopedCookieSelectedAuth {
        cookies: "__Http-session=selected; Secure; Path=/\n__hOsT-hTtP-session=selected; Secure; Path=/\n__hTtP-case=selected; Secure; Path=/\n__Http-valid=selected; Secure; HttpOnly; Path=/",
    });
    let auth_plugins = [staged, selected];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/cookie-scope".to_string(),
    );
    ctx.request_is_secure = true;

    let (_, _, headers) =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index)
            .await
            .expect("both auth attempts must reject");

    assert_eq!(
        headers.get("set-cookie").map(String::as_str),
        Some(
            "__Http-session=selected; Secure; Path=/\n__hOsT-hTtP-session=selected; Secure; Path=/\n__hTtP-case=selected; Secure; Path=/\n__Http-valid=selected; Secure; HttpOnly; Path=/\n__Http-session=staged; Secure; HttpOnly; Path=/\n__hOsT-hTtP-session=staged; Secure; HttpOnly; Path=/\n__hTtP-case=staged; Secure; HttpOnly; Path=/"
        )
    );
}

#[tokio::test]
async fn test_auth_rejection_cookie_storage_key_excludes_insecure_transport_secure_cookie() {
    let staged: Arc<dyn Plugin> = Arc::new(ScopedCookieStagingAuth {
        cookies: "transport=staged; Path=/\nplain=staged; Path=/",
    });
    let selected: Arc<dyn Plugin> = Arc::new(ScopedCookieSelectedAuth {
        cookies: "transport=selected; Secure; Path=/\nplain=selected; Path=/",
    });
    let auth_plugins = [staged, selected];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/cookie-scope".to_string(),
    );

    let (_, _, headers) =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index)
            .await
            .expect("both auth attempts must reject");

    assert_eq!(
        headers.get("set-cookie").map(String::as_str),
        Some(
            "transport=selected; Secure; Path=/\nplain=selected; Path=/\ntransport=staged; Path=/"
        )
    );
}

#[tokio::test]
async fn test_auth_rejection_cookie_storage_key_allows_secure_cookie_on_trustworthy_http_origin() {
    let staged: Arc<dyn Plugin> = Arc::new(ScopedCookieStagingAuth {
        cookies: "transport=staged; Path=/",
    });
    let selected: Arc<dyn Plugin> = Arc::new(ScopedCookieSelectedAuth {
        cookies: "transport=selected; Secure; Path=/",
    });
    let auth_plugins = [staged, selected];
    let consumer_index = ConsumerIndex::new(&[]);

    for authority in [
        "localhost",
        "LOCALHOST.:8080",
        "app.localhost:8080",
        "127.0.0.1:8080",
        "127.255.255.254",
        "[::1]:8080",
    ] {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/cookie-scope".to_string(),
        );
        ctx.request_authority = Some(authority.to_string());

        let (_, _, headers) =
            run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index)
                .await
                .expect("both auth attempts must reject");

        assert_eq!(
            headers.get("set-cookie").map(String::as_str),
            Some("transport=selected; Secure; Path=/"),
            "trustworthy HTTP authority {authority} must retain selected ownership"
        );
    }

    for authority in ["localhost.example", "128.0.0.1", "[::2]"] {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/cookie-scope".to_string(),
        );
        ctx.request_authority = Some(authority.to_string());

        let (_, _, headers) =
            run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index)
                .await
                .expect("both auth attempts must reject");

        assert_eq!(
            headers.get("set-cookie").map(String::as_str),
            Some("transport=selected; Secure; Path=/\ntransport=staged; Path=/"),
            "untrustworthy HTTP authority {authority} must preserve the storable staged cookie"
        );
    }
}

#[tokio::test]
async fn test_auth_rejection_cookie_storage_key_allows_trusted_tls_termination() {
    let staged: Arc<dyn Plugin> = Arc::new(ScopedCookieStagingAuth {
        cookies: "transport=staged; Path=/",
    });
    let selected: Arc<dyn Plugin> = Arc::new(ScopedCookieSelectedAuth {
        cookies: "transport=selected; Secure; Path=/",
    });
    let auth_plugins = [staged, selected];
    let consumer_index = ConsumerIndex::new(&[]);
    let trusted = TrustedProxies::parse("10.0.0.0/8");
    let socket_peer: std::net::IpAddr = "10.0.0.8".parse().expect("valid trusted proxy IP");
    let mut ctx = RequestContext::new(
        socket_peer.to_string(),
        "GET".to_string(),
        "/cookie-scope".to_string(),
    );
    ctx.metadata
        .insert("ferrum.frontend_scheme".to_string(), "http".to_string());
    let mut raw_headers = http::HeaderMap::new();
    raw_headers.append(
        "x-forwarded-for",
        http::HeaderValue::from_static("203.0.113.10, 10.0.0.7"),
    );
    raw_headers.append("x-forwarded-proto", http::HeaderValue::from_static("https"));
    raw_headers.append("x-forwarded-proto", http::HeaderValue::from_static("http"));
    ctx.set_raw_headers(raw_headers);

    let forwarded_scheme = apply_trusted_forwarded_request_scheme(&mut ctx, &socket_peer, &trusted);
    assert_eq!(forwarded_scheme, Some("https"));
    assert!(ctx.request_is_secure);
    assert_eq!(
        ctx.metadata
            .get("ferrum.frontend_scheme")
            .map(String::as_str),
        Some("https")
    );
    assert_eq!(
        normalize_request_authority_for_signing("EXAMPLE.COM:443", forwarded_scheme),
        Some("example.com".to_string())
    );

    let (_, _, headers) =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index)
            .await
            .expect("both auth attempts must reject");

    assert_eq!(
        headers.get("set-cookie").map(String::as_str),
        Some("transport=selected; Secure; Path=/")
    );
}

#[tokio::test]
async fn test_trusted_forwarded_http_overrides_tls_cookie_and_authority_scope() {
    let staged: Arc<dyn Plugin> = Arc::new(ScopedCookieStagingAuth {
        cookies: "transport=staged; Path=/",
    });
    let selected: Arc<dyn Plugin> = Arc::new(ScopedCookieSelectedAuth {
        cookies: "transport=selected; Secure; Path=/",
    });
    let auth_plugins = [staged, selected];
    let consumer_index = ConsumerIndex::new(&[]);
    let trusted = TrustedProxies::parse("10.0.0.0/8");
    let socket_peer: std::net::IpAddr = "10.0.0.8".parse().expect("valid trusted proxy IP");
    let mut ctx = RequestContext::new(
        socket_peer.to_string(),
        "GET".to_string(),
        "/cookie-scope".to_string(),
    );
    ctx.request_is_secure = true;
    ctx.metadata
        .insert("ferrum.frontend_scheme".to_string(), "https".to_string());
    let mut raw_headers = http::HeaderMap::new();
    raw_headers.append(
        "x-forwarded-for",
        http::HeaderValue::from_static("203.0.113.10, 10.0.0.7"),
    );
    raw_headers.append(
        "x-forwarded-proto",
        http::HeaderValue::from_static("http, https"),
    );
    ctx.set_raw_headers(raw_headers);

    let forwarded_scheme = apply_trusted_forwarded_request_scheme(&mut ctx, &socket_peer, &trusted);
    assert_eq!(forwarded_scheme, Some("http"));
    assert!(!ctx.request_is_secure);
    assert_eq!(
        ctx.metadata
            .get("ferrum.frontend_scheme")
            .map(String::as_str),
        Some("http")
    );
    assert_eq!(
        normalize_request_authority_for_signing("EXAMPLE.COM:80", forwarded_scheme),
        Some("example.com".to_string())
    );
    let mut backend_headers = HashMap::from([("host".to_string(), "example.com".to_string())]);
    apply_effective_backend_scheme_headers_for_test(
        &mut backend_headers,
        "203.0.113.10",
        ctx.request_is_secure,
        true,
    );
    assert_eq!(
        backend_headers.get("x-forwarded-proto").map(String::as_str),
        Some("http")
    );
    assert_eq!(
        backend_headers.get("forwarded").map(String::as_str),
        Some("for=203.0.113.10;proto=http;host=example.com")
    );

    let (_, _, headers) =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index)
            .await
            .expect("both auth attempts must reject");

    assert_eq!(
        headers.get("set-cookie").map(String::as_str),
        Some("transport=selected; Secure; Path=/\ntransport=staged; Path=/")
    );
}

#[test]
fn test_trusted_tls_termination_fails_closed_on_invalid_final_proto_field() {
    let trusted = TrustedProxies::parse("10.0.0.0/8");
    let socket_peer: std::net::IpAddr = "10.0.0.8".parse().expect("valid trusted proxy IP");
    let mut ctx = RequestContext::new(
        socket_peer.to_string(),
        "GET".to_string(),
        "/cookie-scope".to_string(),
    );
    ctx.metadata
        .insert("ferrum.frontend_scheme".to_string(), "http".to_string());
    let mut raw_headers = http::HeaderMap::new();
    raw_headers.append("x-forwarded-proto", http::HeaderValue::from_static("https"));
    raw_headers.append(
        "x-forwarded-proto",
        http::HeaderValue::from_bytes(&[0x80]).expect("obs-text header value"),
    );
    ctx.set_raw_headers(raw_headers);

    assert_eq!(
        apply_trusted_forwarded_request_scheme(&mut ctx, &socket_peer, &trusted),
        None
    );
    assert!(!ctx.request_is_secure);
    assert_eq!(
        ctx.metadata
            .get("ferrum.frontend_scheme")
            .map(String::as_str),
        Some("http")
    );

    // An invalid forwarded value does not downgrade an actually secure hop.
    // Only a recognized value from the trusted peer overrides the transport.
    ctx.request_is_secure = true;
    ctx.metadata
        .insert("ferrum.frontend_scheme".to_string(), "https".to_string());
    assert_eq!(
        apply_trusted_forwarded_request_scheme(&mut ctx, &socket_peer, &trusted),
        None
    );
    assert!(ctx.request_is_secure);
    assert_eq!(
        ctx.metadata
            .get("ferrum.frontend_scheme")
            .map(String::as_str),
        Some("https")
    );
}

#[test]
fn test_effective_scheme_headers_remove_case_variants_for_websocket_and_grpc_collectors() {
    let mut proxy_headers = HashMap::from([
        ("host".to_string(), "api.example".to_string()),
        ("X-Forwarded-Proto".to_string(), "plugin".to_string()),
        ("x-FoRwArDeD-pRoTo".to_string(), "stale".to_string()),
        ("Forwarded".to_string(), "for=plugin".to_string()),
        ("fOrWaRdEd".to_string(), "for=stale".to_string()),
    ]);
    apply_effective_backend_scheme_headers_for_test(&mut proxy_headers, "203.0.113.8", true, true);

    assert_eq!(
        proxy_headers
            .keys()
            .filter(|name| name.eq_ignore_ascii_case("x-forwarded-proto"))
            .count(),
        1
    );
    assert_eq!(
        proxy_headers
            .keys()
            .filter(|name| name.eq_ignore_ascii_case("forwarded"))
            .count(),
        1
    );
    assert_eq!(
        proxy_headers.get("x-forwarded-proto").map(String::as_str),
        Some("https")
    );
    assert_eq!(
        proxy_headers.get("forwarded").map(String::as_str),
        Some("for=203.0.113.8;proto=https;host=api.example")
    );

    let mut raw_headers = http::HeaderMap::new();
    raw_headers.insert(
        "x-forwarded-proto",
        http::HeaderValue::from_static("raw-stale"),
    );
    raw_headers.insert("forwarded", http::HeaderValue::from_static("for=raw-stale"));

    let websocket_headers =
        collect_forwardable_websocket_headers_for_test(&raw_headers, &proxy_headers);
    for (name, expected) in [
        ("x-forwarded-proto", "https"),
        ("forwarded", "for=203.0.113.8;proto=https;host=api.example"),
    ] {
        let matching: Vec<&str> = websocket_headers
            .iter()
            .filter(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .collect();
        assert_eq!(matching, vec![expected], "WebSocket collector {name}");
    }

    let mut grpc_headers = raw_headers;
    merge_proxy_headers_and_strip_for_grpc(&mut grpc_headers, &proxy_headers);
    assert_eq!(
        grpc_headers
            .get_all("x-forwarded-proto")
            .iter()
            .map(|value| value.to_str().expect("valid generated gRPC XFP"))
            .collect::<Vec<_>>(),
        vec!["https"]
    );
    assert_eq!(
        grpc_headers
            .get_all("forwarded")
            .iter()
            .map(|value| value.to_str().expect("valid generated gRPC Forwarded"))
            .collect::<Vec<_>>(),
        vec!["for=203.0.113.8;proto=https;host=api.example"]
    );
}

#[tokio::test]
async fn test_auth_rejection_cookie_storage_key_matches_user_agent_value_parsing() {
    let staged: Arc<dyn Plugin> = Arc::new(ScopedCookieStagingAuth {
        cookies: "space=staged value; Path=/\ncomma=staged,value; Path=/\nquote=staged\"value; Path=/\nbackslash=staged\\value; Path=/\nunbalanced=staged; Path=/\ncontrol=staged; Path=/\ncarriage=staged; Path=/\ntab=staged; Path=/\ndel=staged; Path=/\npath_control=staged; Path=/",
    });
    let selected: Arc<dyn Plugin> = Arc::new(ScopedCookieSelectedAuth {
        cookies: "space=selected value; Path=/\ncomma=selected,value; Path=/\nquote=selected\"value; Path=/\nbackslash=selected\\value; Path=/\nunbalanced=\"selected; Path=/\ncontrol=selected\u{001f}value; Path=/\ncarriage=selected\rvalue; Path=/\ntab=selected\tvalue; Path=/\ndel=selected\u{007f}value; Path=/\npath_control=selected; Path=/app\rignored",
    });
    let auth_plugins = [staged, selected];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/cookie-scope".to_string(),
    );

    let (_, _, headers) =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index)
            .await
            .expect("both auth attempts must reject");

    assert_eq!(
        headers.get("set-cookie").map(String::as_str),
        Some(
            "space=selected value; Path=/\ncomma=selected,value; Path=/\nquote=selected\"value; Path=/\nbackslash=selected\\value; Path=/\nunbalanced=\"selected; Path=/\ncontrol=selected\u{001f}value; Path=/\ncarriage=selected\rvalue; Path=/\ntab=selected\tvalue; Path=/\ndel=selected\u{007f}value; Path=/\npath_control=selected; Path=/app\rignored\ncontrol=staged; Path=/\ncarriage=staged; Path=/\ntab=staged; Path=/\ndel=staged; Path=/\npath_control=staged; Path=/"
        )
    );
}

#[tokio::test]
async fn test_auth_rejection_cookie_storage_key_uses_non_root_default_path_and_cookie_ows() {
    let staged: Arc<dyn Plugin> = Arc::new(ScopedCookieStagingAuth {
        cookies: "same=staged; Path=/app\nroot=staged; Path=/\nslash=staged; Path=/app/\nnbsp=staged; Path=/app\nbare=staged; Path=/app",
    });
    let selected: Arc<dyn Plugin> = Arc::new(ScopedCookieSelectedAuth {
        cookies: "same=selected\nroot=selected\nslash=selected\nnbsp=selected; Path=\u{00a0}/ignored\nbare=selected; Path=/other; Path",
    });
    let auth_plugins = [staged, selected];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/app/login".to_string(),
    );

    let (_, _, headers) =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index)
            .await
            .expect("both auth attempts must reject");

    assert_eq!(
        headers.get("set-cookie").map(String::as_str),
        Some(
            "same=selected\nroot=selected\nslash=selected\nnbsp=selected; Path=\u{00a0}/ignored\nbare=selected; Path=/other; Path\nroot=staged; Path=/\nslash=staged; Path=/app/"
        )
    );
}

#[test]
fn test_request_context_effective_identity_prefers_consumer_then_external_identity() {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/jwks".to_string(),
    );
    assert_eq!(ctx.effective_identity(), None);

    ctx.authenticated_identity = Some("external-user".to_string());
    assert_eq!(ctx.effective_identity(), Some("external-user"));

    ctx.authenticated_identity = Some("   \t".to_string());
    assert_eq!(ctx.effective_identity(), None);

    ctx.authenticated_identity = Some("external-user".to_string());

    ctx.identified_consumer = Some(Arc::new(Consumer {
        id: "consumer-1".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "mapped-consumer".to_string(),
        custom_id: None,
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }));
    assert_eq!(ctx.effective_identity(), Some("mapped-consumer"));
}

#[test]
fn test_request_context_backend_consumer_username_prefers_consumer_then_header_then_identity() {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/jwks".to_string(),
    );
    assert_eq!(ctx.backend_consumer_username(), None);

    ctx.authenticated_identity = Some("external-user".to_string());
    assert_eq!(ctx.backend_consumer_username(), Some("external-user"));

    ctx.authenticated_identity_header = Some("user@example.com".to_string());
    assert_eq!(ctx.backend_consumer_username(), Some("user@example.com"));

    ctx.authenticated_identity_header = Some("   ".to_string());
    assert_eq!(ctx.backend_consumer_username(), Some("external-user"));

    ctx.identified_consumer = Some(Arc::new(Consumer {
        id: "consumer-1".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "mapped-consumer".to_string(),
        custom_id: Some("custom-123".to_string()),
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }));
    assert_eq!(ctx.backend_consumer_username(), Some("mapped-consumer"));
    assert_eq!(ctx.backend_consumer_custom_id(), Some("custom-123"));
}

#[test]
fn test_map_http_reject_status_to_grpc_status_uses_semantic_codes() {
    assert_eq!(
        map_http_reject_status_to_grpc_status(StatusCode::UNAUTHORIZED),
        grpc_status::UNAUTHENTICATED
    );
    assert_eq!(
        map_http_reject_status_to_grpc_status(StatusCode::FORBIDDEN),
        grpc_status::PERMISSION_DENIED
    );
    assert_eq!(
        map_http_reject_status_to_grpc_status(StatusCode::TOO_MANY_REQUESTS),
        grpc_status::RESOURCE_EXHAUSTED
    );
    assert_eq!(
        map_http_reject_status_to_grpc_status(StatusCode::BAD_GATEWAY),
        grpc_status::UNAVAILABLE
    );
}

#[test]
fn test_extract_grpc_reject_message_prefers_json_error_fields() {
    let body = br#"{"error":"Rate limit exceeded","details":"retry later"}"#;
    assert_eq!(
        extract_grpc_reject_message(body).as_deref(),
        Some("Rate limit exceeded")
    );
}

#[test]
fn test_normalize_reject_response_converts_grpc_requests_to_trailers_only_errors() {
    let mut headers = HashMap::new();
    headers.insert("x-ratelimit-limit".to_string(), "5".to_string());

    let normalized = normalize_reject_response(
        StatusCode::TOO_MANY_REQUESTS,
        br#"{"error":"Rate limit exceeded"}"#,
        &headers,
        true,
    );

    assert_eq!(normalized.http_status, StatusCode::OK);
    assert!(normalized.body.is_empty());
    assert_eq!(
        normalized.grpc_status,
        Some(grpc_status::RESOURCE_EXHAUSTED)
    );
    assert_eq!(
        normalized.grpc_message.as_deref(),
        Some("Rate limit exceeded")
    );
    assert_eq!(
        normalized.headers.get("content-type").map(|s| s.as_str()),
        Some("application/grpc")
    );
    assert_eq!(
        normalized.headers.get("grpc-status").map(|s| s.as_str()),
        Some("8")
    );
    assert_eq!(
        normalized
            .headers
            .get("x-ratelimit-limit")
            .map(|s| s.as_str()),
        Some("5")
    );
}

#[test]
fn test_insert_grpc_error_metadata_sanitizes_message() {
    let mut metadata = HashMap::new();
    insert_grpc_error_metadata(
        &mut metadata,
        grpc_status::UNAVAILABLE,
        "backend unavailable\nretry later",
    );
    assert_eq!(metadata.get("grpc_status").map(|s| s.as_str()), Some("14"));
    assert_eq!(
        metadata.get("grpc_message").map(|s| s.as_str()),
        Some("backend unavailable retry later")
    );
}

#[test]
fn test_direct_http2_pool_requires_http2_without_retries_or_request_buffering() {
    assert!(can_use_direct_http2_pool(true, false, false));
    assert!(!can_use_direct_http2_pool(false, false, false));
    assert!(!can_use_direct_http2_pool(true, true, false));
    assert!(!can_use_direct_http2_pool(true, false, true));
}

#[test]
fn test_direct_http2_pool_dispatch_disabled_by_body_limits() {
    assert!(can_dispatch_direct_http2_pool(true, false, false, 0, 0));
    assert!(!can_dispatch_direct_http2_pool(true, false, false, 1, 0));
    assert!(!can_dispatch_direct_http2_pool(true, false, false, 0, 1));
    assert!(!can_dispatch_direct_http2_pool(true, true, false, 0, 0));
}

#[test]
fn test_request_may_have_body_uses_method_and_body_headers() {
    let no_headers = HashMap::new();
    for method in ["GET", "HEAD", "OPTIONS"] {
        assert!(!request_may_have_body(method, &no_headers));
    }
    for method in ["DELETE", "PATCH", "POST", "PUT"] {
        assert!(request_may_have_body(method, &no_headers));
    }

    let content_length_zero = HashMap::from([("content-length".to_string(), "0".to_string())]);
    let chunked = HashMap::from([("transfer-encoding".to_string(), "chunked".to_string())]);
    for method in ["GET", "HEAD", "OPTIONS"] {
        assert!(request_may_have_body(method, &content_length_zero));
        assert!(request_may_have_body(method, &chunked));
    }
}

#[tokio::test]
async fn test_apply_request_body_plugins_preserves_plugin_order() {
    let first: Arc<dyn Plugin> = Arc::new(BodySuffixPlugin { suffix: "-first" });
    let second: Arc<dyn Plugin> = Arc::new(BodySuffixPlugin { suffix: "-second" });
    let headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let transformed =
        apply_request_body_plugins(&[first, second], &headers, b"body".to_vec()).await;
    assert_eq!(transformed, b"body-first-second");
}

#[tokio::test]
async fn test_single_auth_allows_mesh_request_auth_permissive_missing_token() {
    let mesh_request_auth: Arc<dyn Plugin> = Arc::new(PermissiveMissingMeshAuth);
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![mesh_request_auth];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/mesh".to_string(),
    );

    let result =
        run_authentication_phase(AuthMode::Single, &auth_plugins, &mut ctx, &consumer_index).await;

    assert!(result.is_none());
    assert!(ctx.identified_consumer.is_none());
    assert!(ctx.authenticated_identity.is_none());
}

#[tokio::test]
async fn test_multi_auth_clears_reject_when_later_plugin_authenticates() {
    // Multi-auth first-success-wins: when a later plugin succeeds, the earlier
    // reject is cleared and the request is allowed through.
    let specific_reject: Arc<dyn Plugin> = Arc::new(RejectingAuth {
        body: r#"{"error":"Invalid JWT"}"#,
    });
    let external: Arc<dyn Plugin> = Arc::new(ExternalIdentityAuth);
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![specific_reject, external];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/jwks".to_string(),
    );

    let result =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index).await;

    assert!(
        result.is_none(),
        "multi-auth first-success-wins: later plugin authenticated so request should pass"
    );
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("external-user"));
}

#[tokio::test]
async fn test_multi_auth_allows_mesh_permissive_missing_token() {
    let mesh_request_auth: Arc<dyn Plugin> = Arc::new(PermissiveMissingMeshAuth);
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![mesh_request_auth];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/mesh".to_string(),
    );

    let result =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index).await;

    assert!(
        result.is_none(),
        "mesh permissive missing token should pass in multi mode when no other plugin rejects"
    );
    assert!(ctx.identified_consumer.is_none());
    assert!(ctx.authenticated_identity.is_none());
}

#[tokio::test]
async fn test_multi_auth_rejects_when_mandatory_plugin_rejects_despite_mesh_permissive_marker() {
    let rejecting_auth: Arc<dyn Plugin> = Arc::new(RejectingAuth {
        body: r#"{"error":"API key required"}"#,
    });
    let mesh_request_auth: Arc<dyn Plugin> = Arc::new(PermissiveMissingMeshAuth);
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![rejecting_auth, mesh_request_auth];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/mesh".to_string(),
    );

    let result =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index).await;

    assert!(
        result.is_some(),
        "mesh permissive marker must not bypass another plugin's rejection in Multi mode"
    );
    let (status, body, _headers) = result.unwrap();
    assert_eq!(status, 401);
    assert_eq!(
        String::from_utf8_lossy(&body),
        r#"{"error":"API key required"}"#
    );
}

#[tokio::test]
async fn test_single_auth_rejects_when_mesh_marker_present_with_other_missing_auth() {
    let mesh_request_auth: Arc<dyn Plugin> = Arc::new(PermissiveMissingMeshAuth);
    let missing_auth: Arc<dyn Plugin> = Arc::new(MissingCredentialContinueAuth);
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![mesh_request_auth, missing_auth];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/mesh".to_string(),
    );

    let result =
        run_authentication_phase(AuthMode::Single, &auth_plugins, &mut ctx, &consumer_index).await;

    assert!(result.is_some());
    let (status, body, _headers) = result.unwrap();
    assert_eq!(status, 401);
    assert_eq!(
        String::from_utf8_lossy(&body),
        r#"{"error":"Authentication required"}"#
    );
}

#[tokio::test]
async fn test_multi_auth_rejects_when_mesh_marker_present_with_other_missing_auth() {
    let mesh_request_auth: Arc<dyn Plugin> = Arc::new(PermissiveMissingMeshAuth);
    let missing_auth: Arc<dyn Plugin> = Arc::new(MissingCredentialContinueAuth);
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![mesh_request_auth, missing_auth];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/mesh".to_string(),
    );

    let result =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index).await;

    assert!(result.is_some());
    let (status, body, _headers) = result.unwrap();
    assert_eq!(status, 401);
    assert_eq!(
        String::from_utf8_lossy(&body),
        r#"{"error":"Authentication required"}"#
    );
}

#[tokio::test]
async fn test_single_auth_rejects_when_mandatory_plugin_rejects_despite_mesh_permissive_marker() {
    let rejecting_auth: Arc<dyn Plugin> = Arc::new(RejectingAuth {
        body: r#"{"error":"API key required"}"#,
    });
    let mesh_request_auth: Arc<dyn Plugin> = Arc::new(PermissiveMissingMeshAuth);
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![rejecting_auth, mesh_request_auth];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/mesh".to_string(),
    );

    let result =
        run_authentication_phase(AuthMode::Single, &auth_plugins, &mut ctx, &consumer_index).await;

    assert!(
        result.is_some(),
        "mesh permissive marker must not bypass another plugin's rejection in Single mode"
    );
    let (status, body, _headers) = result.unwrap();
    assert_eq!(status, 401);
    assert_eq!(
        String::from_utf8_lossy(&body),
        r#"{"error":"API key required"}"#
    );
}

#[test]
fn deadline_bound_grpc_web_pass_through_never_selects_native_backend_h3() {
    let source = include_str!("../../../src/proxy/mod.rs");
    let dispatch = source
        .split("let deadline_bound_grpc_web_pass_through =")
        .nth(1)
        .expect("deadline-bound untranslated gRPC-Web classifier")
        .split("let bytes_sent_observed =")
        .next()
        .expect("initial backend H3 selection block");
    assert!(dispatch.contains("grpc_web_request && !grpc_request_is_web_translated"));
    assert!(dispatch.contains("&& ctx.grpc_deadline_at().is_some();"));
    assert!(
        dispatch.contains("let mut current_dispatch_h3 = !deadline_bound_grpc_web_pass_through")
    );

    let retry_rotation = source
        .split("if target_changed {")
        .nth(1)
        .expect("retry target capability refresh")
        .split("// Re-evaluate the live PeerAuthentication snapshot")
        .next()
        .expect("bounded retry target capability refresh");
    assert!(retry_rotation.contains("current_dispatch_h3 = !deadline_bound_grpc_web_pass_through"));
}

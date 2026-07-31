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
        .find("finalize_reject_response_with_after_proxy_hooks_and_commit_policy(")
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
        include_str!("../../../src/plugins/response_mock.rs"),
        include_str!("../../../src/plugins/load_testing.rs"),
    ] {
        assert!(
            plugin_source
                .contains("fn defer_before_proxy_until_backend_path_resolved(&self) -> bool")
        );
    }

    // Irreversible built-in egress has no `before_proxy` hook and dispatches in
    // the finalized-request-egress phase, which is strictly later than the
    // backend-path policy gate and the complete final-body policy pass
    // (GHSA-4vr5-4wm3-x5xv).
    for plugin_source in [
        include_str!("../../../src/plugins/request_mirror.rs"),
        include_str!("../../../src/plugins/serverless_function.rs"),
        include_str!("../../../src/plugins/ai_federation.rs"),
    ] {
        assert!(plugin_source.contains("fn dispatches_finalized_request_egress(&self) -> bool"));
        assert!(plugin_source.contains("async fn dispatch_finalized_request_egress("));
        assert!(!plugin_source.contains("    async fn before_proxy("));
        assert!(
            !plugin_source
                .contains("fn defer_before_proxy_until_backend_path_resolved(&self) -> bool")
        );
    }
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

    const RETENTION_CALL: &str = "crate::plugins::grpc_web::retain_negotiated_response_content_type(&mut ctx, content_type);";

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
    assert_eq!(&body[..], br#"{"error":"Authentication required"}"#);
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
    assert_eq!(&body[..], br#"{"error":"account disabled"}"#);
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
    assert_eq!(&body[..], br#"{"error":"Authentication required"}"#);
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
    assert_eq!(&body[..], br#"{"error":"Specific auth failure"}"#);
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
    assert_eq!(&body[..], b"must not replace terminal deadline");
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

    // Mixed-case must also drop: Streaming sanitization would otherwise
    // canonicalize a surviving variant onto the wire.
    let mut mixed_case = HashMap::from([("Content-Length".to_string(), "128".to_string())]);
    strip_content_length_for_streaming_grpc_deadline_for_test(&mut mixed_case, true);
    assert!(
        !mixed_case
            .keys()
            .any(|name| name.eq_ignore_ascii_case("content-length"))
    );

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
        assert_eq!(&body[..], br#"{"error":"mixed-case rejection"}"#);
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
    let trusted =
        TrustedProxies::parse_strict("10.0.0.0/8", "test").expect("valid trusted proxy list");
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
    let trusted =
        TrustedProxies::parse_strict("10.0.0.0/8", "test").expect("valid trusted proxy list");
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
    let trusted =
        TrustedProxies::parse_strict("10.0.0.0/8", "test").expect("valid trusted proxy list");
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
    assert!(!normalized.failed_websocket_handshake);
}

/// A failed WebSocket handshake is an ordinary HTTP response (RFC 6455 §4.2.2):
/// transport-owned negotiation metadata must not survive, but the response keeps
/// an authoritative gateway-derived `Content-Length`. Using an invalid HTTP
/// version or an unframed body instead makes RFC 6455 clients fail the reject
/// before they can observe its status.
#[test]
fn test_normalized_reject_builder_keeps_authoritative_length_and_drops_negotiation_fields() {
    use ferrum_edge::_test_support::build_normalized_reject_wire_parts_for_test;

    let body = br#"{"error":"forbidden"}"#;
    let headers = HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("upgrade".to_string(), "websocket".to_string()),
        ("connection".to_string(), "Upgrade".to_string()),
        (
            "sec-websocket-accept".to_string(),
            "policy-must-not-escape".to_string(),
        ),
        // Hostile / stale plugin-authored length: must be replaced, not trusted.
        ("content-length".to_string(), "999999".to_string()),
    ]);

    let expected_content_length = body.len().to_string();
    for failed_websocket_handshake in [false, true] {
        let parts = build_normalized_reject_wire_parts_for_test(
            StatusCode::FORBIDDEN,
            body,
            headers.clone(),
            failed_websocket_handshake,
        );
        assert_eq!(parts.status, StatusCode::FORBIDDEN);
        assert!(
            parts.version >= http::Version::HTTP_11,
            "reject must stay HTTP/1.1 or newer, got {:?} \
             (failed_websocket_handshake={failed_websocket_handshake})",
            parts.version
        );
        let wire = parts.headers;
        assert_eq!(
            wire.get(http::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()),
            Some(expected_content_length.as_str()),
            "ExactBody repair must publish the real body length \
             (failed_websocket_handshake={failed_websocket_handshake})"
        );
        assert!(wire.get(http::header::TRANSFER_ENCODING).is_none());
        assert!(wire.get(http::header::UPGRADE).is_none());
        assert!(wire.get(http::header::CONNECTION).is_none());
        assert_eq!(
            wire.get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
            "ordinary representation metadata must survive the boundary"
        );
    }

    // `Sec-WebSocket-*` is transport-owned only on the typed WebSocket boundary;
    // the ordinary HTTP reject path has no reason to special-case it.
    let failed_ws =
        build_normalized_reject_wire_parts_for_test(StatusCode::FORBIDDEN, body, headers, true)
            .headers;
    assert!(
        failed_ws.get("sec-websocket-accept").is_none(),
        "failed WebSocket rejects must not leak a policy-authored Sec-WebSocket-Accept"
    );
}

/// The typed body-omission signal is derived from the request method + status
/// only, and the framing selector never lets a claimed omission override real
/// body bytes.
#[test]
fn test_reject_body_disposition_is_method_and_status_derived() {
    use ferrum_edge::proxy::headers::{ClientResponseFraming, RejectBodyDisposition};

    for method in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"] {
        assert_eq!(
            RejectBodyDisposition::for_request(method, 403),
            RejectBodyDisposition::WireBody,
            "{method} 403 carries a wire body"
        );
    }
    for method in ["HEAD", "head", "HeAd"] {
        assert_eq!(
            RejectBodyDisposition::for_request(method, 200),
            RejectBodyDisposition::OmittedByProtocol,
            "{method} omits body bytes"
        );
    }
    for status in [100u16, 199, 204, 205, 304] {
        assert_eq!(
            RejectBodyDisposition::for_request("GET", status),
            RejectBodyDisposition::OmittedByProtocol,
            "status {status} forbids a body"
        );
    }

    // Empty ordinary reject -> authoritative zero.
    assert!(matches!(
        ClientResponseFraming::for_final_reject(403, 0, RejectBodyDisposition::WireBody),
        ClientResponseFraming::ExactBody { len: 0, .. }
    ));
    // Empty omitted-by-protocol reject -> preserve the representation length.
    // `Head` is the ONLY framing that may keep one; ordinary `Streaming` now
    // removes Content-Length outright, so selecting it here would silently drop
    // a HEAD reject's representation length instead of preserving it.
    assert!(matches!(
        ClientResponseFraming::for_final_reject(200, 0, RejectBodyDisposition::OmittedByProtocol),
        ClientResponseFraming::Head { .. }
    ));
    // Bytes about to be written always win over a claimed omission.
    assert!(matches!(
        ClientResponseFraming::for_final_reject(200, 21, RejectBodyDisposition::OmittedByProtocol),
        ClientResponseFraming::ExactBody { len: 21, .. }
    ));
}

/// ExactBody / Streaming wire sanitizer must not remove+reinsert an already
/// canonical `content-length` on the common path (hot-path allocation invariant),
/// while still repairing malformed / noncanonical spellings fail-closed.
#[test]
fn test_sanitize_client_response_preserves_canonical_content_length_storage() {
    use ferrum_edge::proxy::headers::{
        ClientResponseFraming, sanitize_client_response_headers_for_wire,
    };
    use std::collections::HashMap;

    // ExactBody: single lowercase matching decimal — no mutation of the value.
    let mut exact = HashMap::from([
        ("content-length".to_string(), "42".to_string()),
        ("x-ok".to_string(), "1".to_string()),
    ]);
    let exact_cl_ptr = exact.get("content-length").unwrap().as_ptr();
    sanitize_client_response_headers_for_wire(
        &mut exact,
        ClientResponseFraming::ExactBody {
            status: 200,
            len: 42,
        },
    );
    assert_eq!(exact.get("content-length").map(String::as_str), Some("42"));
    assert_eq!(
        exact.get("content-length").unwrap().as_ptr(),
        exact_cl_ptr,
        "ExactBody must preserve already-canonical Content-Length storage"
    );

    // ExactBody repair branches: mismatch, leading zeroes, whitespace, mixed-case.
    for (key, value, expected) in [
        ("content-length", "999", "4"),
        ("content-length", "042", "42"),
        ("content-length", "42 ", "42"),
        ("Content-Length", "42", "42"),
    ] {
        let mut headers = HashMap::from([(key.to_string(), value.to_string())]);
        let framing = ClientResponseFraming::ExactBody {
            status: 200,
            len: expected.parse().unwrap(),
        };
        sanitize_client_response_headers_for_wire(&mut headers, framing);
        assert_eq!(
            headers.get("content-length").map(String::as_str),
            Some(expected),
            "ExactBody must repair {key}: {value:?}"
        );
        assert!(
            !headers
                .keys()
                .any(|name| name.eq_ignore_ascii_case("content-length") && name != "content-length"),
            "ExactBody repair must leave only lowercase content-length"
        );
    }

    // Head: single lowercase untrimmed parseable value — no mutation.
    let mut head = HashMap::from([("content-length".to_string(), "42".to_string())]);
    let head_cl_ptr = head.get("content-length").unwrap().as_ptr();
    sanitize_client_response_headers_for_wire(
        &mut head,
        ClientResponseFraming::Head { status: 200 },
    );
    assert_eq!(head.get("content-length").map(String::as_str), Some("42"));
    assert_eq!(
        head.get("content-length").unwrap().as_ptr(),
        head_cl_ptr,
        "Head must preserve already-safe Content-Length storage"
    );

    // Head acceptance preserves leading zeroes (parseable) without rewrite.
    let mut leading_zero = HashMap::from([("content-length".to_string(), "042".to_string())]);
    let leading_ptr = leading_zero.get("content-length").unwrap().as_ptr();
    sanitize_client_response_headers_for_wire(
        &mut leading_zero,
        ClientResponseFraming::Head { status: 200 },
    );
    assert_eq!(
        leading_zero.get("content-length").map(String::as_str),
        Some("042"),
        "Head must not invent a stricter leading-zero policy"
    );
    assert_eq!(
        leading_zero.get("content-length").unwrap().as_ptr(),
        leading_ptr
    );

    // Head repair: invalid, whitespace-padded, mixed-case, duplicates.
    let mut invalid = HashMap::from([("content-length".to_string(), "not-a-number".to_string())]);
    sanitize_client_response_headers_for_wire(
        &mut invalid,
        ClientResponseFraming::Head { status: 200 },
    );
    assert!(!invalid.contains_key("content-length"));

    let mut padded = HashMap::from([("content-length".to_string(), " 42 ".to_string())]);
    sanitize_client_response_headers_for_wire(
        &mut padded,
        ClientResponseFraming::Head { status: 200 },
    );
    assert_eq!(padded.get("content-length").map(String::as_str), Some("42"));

    let mut mixed = HashMap::from([("Content-Length".to_string(), "42".to_string())]);
    sanitize_client_response_headers_for_wire(
        &mut mixed,
        ClientResponseFraming::Head { status: 200 },
    );
    assert_eq!(mixed.get("content-length").map(String::as_str), Some("42"));
    assert!(!mixed.contains_key("Content-Length"));

    let mut duplicates = HashMap::from([
        ("content-length".to_string(), "42".to_string()),
        ("Content-Length".to_string(), "42".to_string()),
    ]);
    sanitize_client_response_headers_for_wire(
        &mut duplicates,
        ClientResponseFraming::Head { status: 200 },
    );
    assert!(
        !duplicates
            .keys()
            .any(|name| name.eq_ignore_ascii_case("content-length")),
        "duplicate Content-Length case variants must be stripped"
    );
}

/// An *empty* ordinary reject is the residual the emptiness heuristic missed:
/// zero is an authoritative length, so a plugin-authored `Content-Length: 999`
/// must be replaced by canonical `0` rather than preserved as a streaming
/// representation length. Covers the plain HTTP reject and the failed WebSocket
/// handshake, which is also an ordinary HTTP error.
#[test]
fn test_normalized_reject_builder_replaces_hostile_length_on_empty_body() {
    use ferrum_edge::_test_support::build_normalized_reject_wire_parts_with_method_for_test;

    let headers = HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("content-length".to_string(), "999".to_string()),
    ]);

    for failed_websocket_handshake in [false, true] {
        for method in ["GET", "POST", "DELETE"] {
            let wire = build_normalized_reject_wire_parts_with_method_for_test(
                method,
                StatusCode::FORBIDDEN,
                b"",
                headers.clone(),
                failed_websocket_handshake,
            )
            .headers;
            assert_eq!(
                wire.get(http::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok()),
                Some("0"),
                "empty {method} reject must publish canonical 0 \
                 (failed_websocket_handshake={failed_websocket_handshake})"
            );
            assert!(wire.get(http::header::TRANSFER_ENCODING).is_none());
        }
    }
}

/// `HEAD` is the case the empty-body heuristic was protecting: the trusted
/// synthetic-response preparation contract empties the body but keeps the
/// representation length a `GET` would have returned. That length — and only
/// that length — must survive; a plugin-authored value is overwritten by the
/// contract's own representation size beforehand.
#[test]
fn test_head_reject_preserves_representation_length_from_preparation_contract() {
    use ferrum_edge::_test_support::prepare_and_build_normalized_reject_wire_parts_for_test;

    let body = br#"{"error":"forbidden"}"#;
    let representation_len = body.len().to_string();

    let wire = prepare_and_build_normalized_reject_wire_parts_for_test(
        "HEAD",
        StatusCode::FORBIDDEN,
        body,
        HashMap::from([("content-type".to_string(), "application/json".to_string())]),
    )
    .headers;
    assert_eq!(
        wire.get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()),
        Some(representation_len.as_str()),
        "HEAD must keep the representation length a GET would have returned"
    );

    // The same trusted request, but a GET, publishes the real wire length.
    let get_wire = prepare_and_build_normalized_reject_wire_parts_for_test(
        "GET",
        StatusCode::FORBIDDEN,
        body,
        HashMap::from([("content-type".to_string(), "application/json".to_string())]),
    )
    .headers;
    assert_eq!(
        get_wire
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()),
        Some(representation_len.as_str())
    );
}

/// Statuses that forbid a message body strip `Content-Length` outright, on both
/// the preparation contract and the final builder, no matter what a response
/// hook wrote.
#[test]
fn test_no_body_status_rejects_strip_plugin_authored_length() {
    use ferrum_edge::_test_support::prepare_and_build_normalized_reject_wire_parts_for_test;

    for status in [
        StatusCode::CONTINUE,
        StatusCode::NO_CONTENT,
        StatusCode::RESET_CONTENT,
        StatusCode::NOT_MODIFIED,
    ] {
        for method in ["GET", "HEAD"] {
            let wire = prepare_and_build_normalized_reject_wire_parts_for_test(
                method,
                status,
                b"",
                HashMap::from([("content-length".to_string(), "999".to_string())]),
            )
            .headers;
            assert!(
                wire.get(http::header::CONTENT_LENGTH).is_none(),
                "{method} {status} must not advertise a body length"
            );
        }
    }
}

/// A native gRPC reject normalizes to a trailers-only response: HTTP 200 with
/// terminal metadata in the header block and no body. It must keep streaming /
/// trailer semantics — inventing `Content-Length: 0` there would break clients
/// that expect a trailers-only frame sequence.
#[test]
fn test_native_grpc_trailers_only_reject_does_not_invent_zero_length() {
    use ferrum_edge::_test_support::build_grpc_trailers_only_reject_wire_parts_for_test;

    let headers = HashMap::from([
        ("content-length".to_string(), "999".to_string()),
        ("x-ratelimit-limit".to_string(), "5".to_string()),
    ]);
    let parts = build_grpc_trailers_only_reject_wire_parts_for_test(
        StatusCode::FORBIDDEN,
        br#"{"error":"forbidden"}"#,
        &headers,
    );

    assert_eq!(parts.status, StatusCode::OK);
    let wire = parts.headers;
    assert!(
        wire.get(http::header::CONTENT_LENGTH).is_none(),
        "trailers-only gRPC must neither keep the hostile length nor invent 0"
    );
    assert!(wire.get(http::header::TRANSFER_ENCODING).is_none());
    assert_eq!(
        wire.get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/grpc")
    );
    assert_eq!(
        wire.get("grpc-status").and_then(|v| v.to_str().ok()),
        Some("7")
    );
    assert_eq!(
        wire.get("x-ratelimit-limit").and_then(|v| v.to_str().ok()),
        Some("5"),
        "plugin metadata unrelated to framing must survive"
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
fn test_direct_http2_sni_uses_body_compat_gate_not_body_limit_gate() {
    // Issue #2954: SNI cannot fall back to reqwest, so nonzero body limits
    // must not disqualify direct-H2 when retries/buffering are absent.
    // Callers use can_use_direct_http2_pool for the SNI path.
    assert!(can_use_direct_http2_pool(true, false, false));
    assert!(!can_use_direct_http2_pool(true, true, false));
    assert!(!can_use_direct_http2_pool(true, false, true));
    // Ordinary preference still requires both body limits at 0.
    assert!(!can_dispatch_direct_http2_pool(
        true, false, false, 10_485_760, 10_485_760
    ));
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

#[test]
fn streaming_grpc_web_adapters_honor_preserved_response_statuses() {
    let source = include_str!("../../../src/proxy/mod.rs");

    let direct = source
        .split("let grpc_web_streaming_content_type = grpc_web_response_content_type")
        .nth(1)
        .expect("direct streaming gRPC-Web translation gate")
        .split("// Build the response with the live Incoming body")
        .next()
        .expect("bounded direct streaming response preparation");
    let direct_gate = direct
        .find("response_body_rewrite_allowed(grpc_streaming.status)")
        .expect("direct streaming adapter must honor preserved statuses");
    let direct_terminal_take = direct
        .find("take_streaming_initial_terminal_metadata(")
        .expect("direct streaming terminal metadata extraction");
    assert!(
        direct_gate < direct_terminal_take,
        "preserved statuses must bypass metadata extraction and representation rewriting"
    );
    assert!(direct.contains("if grpc_web_streaming_content_type.is_some()"));

    let generic = source
        .split("let grpc_web_streaming_adapter = if body_will_stream")
        .nth(1)
        .expect("generic streaming gRPC-Web translation gate")
        .split("// Build final response")
        .next()
        .expect("bounded generic streaming response preparation");
    let generic_gate = generic
        .find("response_body_rewrite_allowed(response_status)")
        .expect("generic streaming adapter must honor preserved statuses");
    let generic_terminal_take = generic
        .find("take_streaming_initial_terminal_metadata(")
        .expect("generic streaming terminal metadata extraction");
    assert!(
        generic_gate < generic_terminal_take,
        "generic preserved statuses must retain native headers and body framing"
    );
}
/// GHSA-4vr5-4wm3-x5xv: irreversible outbound request egress must be its own
/// phase, reachable only after request-body finalization.
///
/// Structural because the property is an ordering across two 10k+ line dispatch
/// ladders that no single unit-level call can witness: at every site that runs
/// `run_final_request_body_hooks`, the egress phase must run *after* it and only
/// on `Continue`, and the no-buffering fallback must be gated so it cannot fire
/// ahead of a finalization that is still to come.
#[test]
fn test_finalized_request_egress_runs_after_final_body_hooks_and_before_dispatch() {
    let src = include_str!("../../../src/proxy/mod.rs");

    // The dispatcher is exactly-once and refuses to run without a declared
    // egress plugin, so an ordinary chain pays nothing.
    let dispatcher = src
        .split("pub(crate) async fn run_finalized_request_egress_hooks(")
        .nth(1)
        .expect("finalized-request-egress dispatcher must remain present")
        .split("async fn run_finalized_request_egress_hooks_inner(")
        .next()
        .expect("dispatcher must remain bounded");
    assert!(dispatcher.contains("if ctx.finalized_request_egress_dispatched {"));
    assert!(dispatcher.contains("ctx.finalized_request_egress_dispatched = true;"));
    assert!(dispatcher.contains("plugin.dispatches_finalized_request_egress()"));

    let handler = src
        .find("async fn handle_proxy_request_inner(")
        .map(|start| &src[start..])
        .expect("H1/H2 request handler must remain present");

    // Every egress call site in the handler must be preceded by the final
    // request-body hook pass, or be the explicitly gated no-buffering fallback.
    let egress_sites: Vec<usize> = handler
        .match_indices("run_finalized_request_egress_hooks(")
        .map(|(index, _)| index)
        .collect();
    assert!(
        egress_sites.len() >= 4,
        "H1/H2 must reach the egress boundary from the terminal, ordinary, gRPC, \
         and no-buffering sites; found {}",
        egress_sites.len()
    );
    let first_final_hook = handler
        .find("run_final_request_body_hooks(")
        .expect("final request-body hooks must remain present");
    assert!(
        egress_sites[0] > first_final_hook,
        "no egress site may precede the first final request-body hook pass"
    );
    assert!(
        handler
            .matches("finalized_request_rejection_phase(rejected_by_egress)")
            .count()
            >= 3,
        "ordinary, terminal, and native-gRPC egress rejections must retain the \
         finalized_request_egress transaction phase"
    );

    // The fallback site is the only one not preceded by a final-body hook pass.
    // It must be exactly-once gated rather than gated on "this chain never
    // buffers": a request that carries no body at all is left streaming by
    // `buffer_request_body_for_before_proxy`, so the terminal preparation runs
    // neither transforms nor final-body hooks for it and reaches no boundary of
    // its own. Gating the fallback on `!requires_request_body_buffering` made the
    // whole phase unreachable for a bodyless request on any buffering chain —
    // e.g. a `GET` on a `request_mirror` proxy, whose `mirror_request_body`
    // default requires buffering.
    let fallback = handler
        .find("&& !ctx.finalized_request_egress_dispatched")
        .expect("the fallback egress site must remain exactly-once gated");
    assert!(
        handler[..fallback]
            .rfind("DISPATCHES_FINALIZED_REQUEST_EGRESS")
            .is_some_and(|capability| fallback - capability < 200),
        "the fallback egress site must stay capability-gated"
    );
    assert!(
        handler[fallback..]
            .find("!(grpc_uses_native_dispatch && requires_request_body_buffering)")
            .is_some_and(|offset| offset < 300),
        "only a buffering request that will enter the native-gRPC branch may defer to \
         that branch's own egress boundary; mesh fall-through requests must still be \
         dispatched here when they carry no body (GHSA-4vr5-4wm3-x5xv)"
    );

    let mesh_fall_through = handler
        .find("let grpc_mesh_fall_through")
        .expect("mesh gRPC fall-through must be classified before terminal preparation");
    let terminal = handler
        .find("if final_body_before_backend_dispatch")
        .expect("terminal body preparation must remain present");
    assert!(
        mesh_fall_through < terminal
            && handler[mesh_fall_through..terminal].contains(
                "grpc_uses_generic_dispatch\n            && requires_request_body_buffering",
            ),
        "every buffering gRPC request that will use generic dispatch must be pulled through \
         transforms, final policy, and finalized-request egress before dispatch"
    );

    // A buffered request on an egress chain finalizes before backend dispatch
    // rather than inside `proxy_to_backend`.
    let helper = src
        .split("pub(crate) fn final_request_body_requirements(")
        .nth(1)
        .expect("shared final-body applicability helper must remain present")
        .split("pub(crate) fn request_body_requirements_before_authenticate(")
        .next()
        .expect("shared final-body applicability helper must remain bounded");
    assert!(
        helper.contains("terminal_dispatch |= has_finalized_request_egress && requires_buffering;")
    );

    // HTTP/3 reaches the same boundary after its own terminal finalization.
    let h3 = include_str!("../../../src/http3/server.rs");
    let h3_final_hook = h3
        .find("let final_body_result = crate::proxy::run_final_request_body_hooks(")
        .expect("H3 terminal final-body hooks must remain present");
    let h3_egress = h3
        .find("crate::proxy::run_finalized_request_egress_hooks(")
        .expect("H3 must reach the finalized-request-egress boundary");
    assert!(
        h3_final_hook < h3_egress,
        "H3 egress must run after the terminal final request-body hooks"
    );

    // Composition admission still fails closed for anything egressing earlier.
    let cache = include_str!("../../../src/plugin_cache.rs");
    assert!(cache.contains("plugin.enforces_finalized_request_policy()"));
    assert!(cache.contains("plugin.dispatches_finalized_request_egress()"));

    // Every built-in final request hook that can reject the backend-visible
    // representation must advertise the composition marker. Otherwise a
    // registered custom plugin could egress earlier and bypass that policy.
    for policy_source in [
        include_str!("../../../src/plugins/ai_prompt_compressor.rs"),
        include_str!("../../../src/plugins/ai_prompt_shield.rs"),
        include_str!("../../../src/plugins/ai_request_guard.rs"),
        include_str!("../../../src/plugins/ai_semantic_firewall.rs"),
        include_str!("../../../src/plugins/ai_stream_router.rs"),
        include_str!("../../../src/plugins/ai_tool_governor.rs"),
        include_str!("../../../src/plugins/ai_transcript_audit.rs"),
        include_str!("../../../src/plugins/body_validator.rs"),
        include_str!("../../../src/plugins/grpc_web.rs"),
        include_str!("../../../src/plugins/openapi_validator.rs"),
        include_str!("../../../src/plugins/request_size_limiting.rs"),
        include_str!("../../../src/plugins/soap_ws_security.rs"),
        include_str!("../../../src/plugins/waf/mod.rs"),
    ] {
        assert!(policy_source.contains("fn enforces_finalized_request_policy(&self) -> bool"));
    }
}

/// `Content-Length` acceptance at the final wire boundary must be RFC 9110
/// §8.6 `1*DIGIT`, not "whatever `u64::from_str` tolerates".
///
/// Rust's integer `FromStr` accepts a leading `+`, so a `Content-Length: +42`
/// left on a streaming response map parses successfully and was therefore
/// treated as an already-safe value: `needs_client_response_wire_sanitization`
/// reported no work, the sanitizer preserved it verbatim, and the malformed
/// field reached the client. On an H1 chain, one intermediary may read `+42` as
/// `42`, another as `0`, and another may reject the message — the exact framing
/// disagreement this boundary exists to remove.
#[test]
fn test_head_sanitizer_rejects_non_digit_content_length_spellings() {
    use ferrum_edge::proxy::headers::{
        ClientResponseFraming, needs_client_response_wire_sanitization,
        sanitize_client_response_headers_for_wire,
    };
    use std::collections::HashMap;

    // `Head` is the only framing that preserves a value at all, so it is the
    // only one whose acceptance policy can be wrong in the "preserved a
    // malformed spelling" direction.
    let framing = ClientResponseFraming::Head { status: 200 };

    // Signed, non-numeric, and overflowing spellings are all refused. A
    // streaming body is framed by the protocol's own end-of-body signal, so
    // dropping an unverifiable length is the safe repair.
    for value in [
        "+42",
        "+0",
        "-1",
        "4 2",
        "42abc",
        "0x2a",
        "",
        // One past u64::MAX: all digits, but not representable, comparable, or
        // repairable by the gateway.
        "18446744073709551616",
    ] {
        let mut headers = HashMap::from([
            ("content-length".to_string(), value.to_string()),
            ("x-ok".to_string(), "1".to_string()),
        ]);
        assert!(
            needs_client_response_wire_sanitization(&headers, framing),
            "{value:?} must be reported as needing repair, or the H3 hot path \
             skips sanitization entirely and publishes it verbatim"
        );
        sanitize_client_response_headers_for_wire(&mut headers, framing);
        assert!(
            !headers
                .keys()
                .any(|name| name.eq_ignore_ascii_case("content-length")),
            "{value:?} is not a valid Content-Length and must not reach the wire"
        );
        assert_eq!(
            headers.get("x-ok").map(String::as_str),
            Some("1"),
            "unrelated headers must survive the repair"
        );
    }

    // Bare 1*DIGIT (including leading zeroes, which the grammar permits) stays
    // untouched — the stricter check must not start rewriting valid backends.
    for value in ["0", "42", "042", "18446744073709551615"] {
        let mut headers = HashMap::from([("content-length".to_string(), value.to_string())]);
        assert!(
            !needs_client_response_wire_sanitization(&headers, framing),
            "{value:?} is a valid Content-Length and must stay on the hot path"
        );
        sanitize_client_response_headers_for_wire(&mut headers, framing);
        assert_eq!(
            headers.get("content-length").map(String::as_str),
            Some(value)
        );
    }

    // A signed value under a mixed-case key must not be "repaired" into a
    // canonical lowercase field carrying the same malformed number.
    let mut mixed = HashMap::from([("Content-Length".to_string(), "+42".to_string())]);
    sanitize_client_response_headers_for_wire(&mut mixed, framing);
    assert!(
        !mixed
            .keys()
            .any(|name| name.eq_ignore_ascii_case("content-length")),
        "case-repair must not rehome a non-1*DIGIT value onto the canonical key"
    );
}

/// `ExactBody` must not accept a signed spelling as "already canonical" and
/// skip the rewrite that publishes the authoritative length.
#[test]
fn test_exact_body_sanitizer_rewrites_signed_content_length() {
    use ferrum_edge::proxy::headers::{
        ClientResponseFraming, needs_client_response_wire_sanitization,
        sanitize_client_response_headers_for_wire,
    };
    use std::collections::HashMap;

    let framing = ClientResponseFraming::ExactBody {
        status: 200,
        len: 42,
    };
    let mut headers = HashMap::from([("content-length".to_string(), "+42".to_string())]);
    assert!(needs_client_response_wire_sanitization(&headers, framing));
    sanitize_client_response_headers_for_wire(&mut headers, framing);
    assert_eq!(
        headers.get("content-length").map(String::as_str),
        Some("42"),
        "ExactBody must publish the canonical decimal length it was given"
    );
}

/// Buffered writers share one framing rule across H1/H2, native H3, and the H3
/// cross-protocol bridge: the wire body is in hand, so its length is
/// authoritative. `HEAD` is the sole exception — the representation length a
/// `GET` would have returned must survive the empty wire body.
#[test]
fn test_buffered_response_framing_is_body_derived_except_head() {
    use ferrum_edge::proxy::headers::ClientResponseFraming;

    for method in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"] {
        assert!(
            matches!(
                ClientResponseFraming::for_buffered_response(method, 200, 21),
                ClientResponseFraming::ExactBody { len: 21, .. }
            ),
            "{method} buffered response must publish its exact body length"
        );
        assert!(
            matches!(
                ClientResponseFraming::for_buffered_response(method, 403, 0),
                ClientResponseFraming::ExactBody { len: 0, .. }
            ),
            "{method} empty buffered response must publish an authoritative zero"
        );
    }
    for method in ["HEAD", "head", "HeAd"] {
        assert!(
            matches!(
                ClientResponseFraming::for_buffered_response(method, 200, 0),
                ClientResponseFraming::Head { .. }
            ),
            "{method} must preserve the backend representation length"
        );
    }
}

/// GHSA-xvr4 residual: an ordinary streamed non-HEAD response must not publish
/// ANY `Content-Length` that survived the mutable response hooks — including a
/// syntactically valid, lowercase, canonically spelled one.
///
/// This is the arm the earlier repair left open. Hop-by-hop stripping and the
/// `ExactBody` overwrite covered the buffered writers, but the streaming arm
/// preserved one valid value, and `security_headers.set` / `opa.deny_headers`
/// could author exactly that. On a streamed body the gateway has not written the
/// bytes yet, so it cannot verify the claim; publishing it lets one recipient on
/// an HTTP/1.1 chain frame by the declared length while another frames by the
/// protocol's own end-of-body signal.
#[test]
fn test_ordinary_streaming_framing_strips_every_content_length_spelling() {
    use ferrum_edge::proxy::headers::{
        ClientResponseFraming, needs_client_response_wire_sanitization,
        sanitize_client_response_headers_for_wire,
    };
    use std::collections::HashMap;

    let framing = ClientResponseFraming::Streaming;

    // Every one of these is a *valid* wire spelling that the previous Streaming
    // arm preserved verbatim.
    for (key, value) in [
        ("content-length", "0"),
        ("content-length", "42"),
        ("content-length", "042"),
        ("content-length", "18446744073709551615"),
        ("Content-Length", "42"),
        ("CONTENT-LENGTH", "42"),
    ] {
        let mut headers = HashMap::from([
            (key.to_string(), value.to_string()),
            ("x-ok".to_string(), "1".to_string()),
        ]);
        assert!(
            needs_client_response_wire_sanitization(&headers, framing),
            "{key}: {value:?} must be reported as needing repair, or the H3 hot \
             path skips sanitization and publishes it verbatim"
        );
        sanitize_client_response_headers_for_wire(&mut headers, framing);
        assert!(
            !headers
                .keys()
                .any(|name| name.eq_ignore_ascii_case("content-length")),
            "ordinary streaming must not publish {key}: {value:?} — the gateway \
             cannot verify it against bytes it has not written"
        );
        assert_eq!(
            headers.get("x-ok").map(String::as_str),
            Some("1"),
            "unrelated headers must survive the strip"
        );
    }

    // A clean map still needs no work, so the allocation-free hot path stays.
    let clean = HashMap::from([("x-ok".to_string(), "1".to_string())]);
    assert!(!needs_client_response_wire_sanitization(&clean, framing));

    // Hop-by-hop stripping is unchanged and composes with the length strip.
    let mut both = HashMap::from([
        (
            "connection".to_string(),
            "keep-alive, x-internal".to_string(),
        ),
        ("x-internal".to_string(), "leak".to_string()),
        ("transfer-encoding".to_string(), "chunked".to_string()),
        ("content-length".to_string(), "42".to_string()),
        ("x-ok".to_string(), "1".to_string()),
    ]);
    sanitize_client_response_headers_for_wire(&mut both, framing);
    assert_eq!(both.len(), 1, "only the ordinary header may survive");
    assert_eq!(both.get("x-ok").map(String::as_str), Some("1"));
}

#[test]
fn websocket_transport_boundary_strips_connection_nominated_extensions() {
    use ferrum_edge::_test_support::strip_websocket_transport_managed_response_headers;

    let mut headers = HashMap::from([
        (
            "Connection".to_string(),
            "Upgrade, X-Handshake-Hop".to_string(),
        ),
        ("X-Handshake-Hop".to_string(), "must-not-leak".to_string()),
        (
            "Sec-WebSocket-Protocol".to_string(),
            "fabricated".to_string(),
        ),
        ("Content-Length".to_string(), "999".to_string()),
        ("x-end-to-end".to_string(), "preserved".to_string()),
    ]);

    strip_websocket_transport_managed_response_headers(&mut headers);

    for removed in [
        "connection",
        "upgrade",
        "x-handshake-hop",
        "sec-websocket-protocol",
        "content-length",
    ] {
        assert!(
            !headers
                .keys()
                .any(|name| name.eq_ignore_ascii_case(removed)),
            "{removed} crossed the WebSocket handshake boundary"
        );
    }
    assert_eq!(
        headers.get("x-end-to-end").map(String::as_str),
        Some("preserved")
    );
}

/// `HEAD` is the one exemption, and it is narrow: exactly one valid
/// representation length survives, while invalid values, duplicate case
/// variants, and no-body statuses are still stripped.
#[test]
fn test_head_framing_preserves_only_one_valid_representation_length() {
    use ferrum_edge::proxy::headers::{
        ClientResponseFraming, sanitize_client_response_headers_for_wire,
    };
    use std::collections::HashMap;

    // Preserved: one valid value, canonicalized onto the lowercase key.
    for (key, value, expected) in [
        ("content-length", "1024", "1024"),
        ("Content-Length", "1024", "1024"),
        ("CONTENT-LENGTH", " 1024 ", "1024"),
        ("content-length", "01024", "01024"),
    ] {
        let mut headers = HashMap::from([(key.to_string(), value.to_string())]);
        sanitize_client_response_headers_for_wire(
            &mut headers,
            ClientResponseFraming::Head { status: 200 },
        );
        assert_eq!(
            headers.get("content-length").map(String::as_str),
            Some(expected),
            "HEAD must keep the representation length from {key}: {value:?}"
        );
        assert!(
            !headers
                .keys()
                .any(|name| name.eq_ignore_ascii_case("content-length") && name != "content-length"),
            "HEAD repair must leave only the canonical lowercase key"
        );
    }

    // Dropped: ambiguous duplicates across case variants.
    let mut duplicates = HashMap::from([
        ("content-length".to_string(), "1024".to_string()),
        ("Content-Length".to_string(), "1024".to_string()),
    ]);
    sanitize_client_response_headers_for_wire(
        &mut duplicates,
        ClientResponseFraming::Head { status: 200 },
    );
    assert!(
        !duplicates
            .keys()
            .any(|name| name.eq_ignore_ascii_case("content-length")),
        "duplicate HEAD lengths are a HeaderMap duplicate field — fail closed"
    );

    // Dropped: spellings outside `1*DIGIT`.
    for value in [
        "+1024",
        "-1",
        "10 24",
        "1024abc",
        "",
        "18446744073709551616",
    ] {
        let mut headers = HashMap::from([("content-length".to_string(), value.to_string())]);
        sanitize_client_response_headers_for_wire(
            &mut headers,
            ClientResponseFraming::Head { status: 200 },
        );
        assert!(
            !headers.contains_key("content-length"),
            "HEAD must drop the malformed spelling {value:?}"
        );
    }

    // Dropped: statuses that forbid a body, even under HEAD framing.
    for status in [100u16, 199, 204, 205, 304] {
        let mut headers = HashMap::from([
            ("content-length".to_string(), "1024".to_string()),
            ("Content-Length".to_string(), "7".to_string()),
        ]);
        sanitize_client_response_headers_for_wire(
            &mut headers,
            ClientResponseFraming::Head { status },
        );
        assert!(
            !headers
                .keys()
                .any(|name| name.eq_ignore_ascii_case("content-length")),
            "status {status} forbids a body, so no length may survive"
        );
    }
}

/// The ordinary-vs-HEAD distinction is a typed framing decision derived from the
/// trusted request method — not a caller-supplied boolean, and never inferred
/// from a response header a plugin or backend controls.
#[test]
fn test_streaming_response_framing_constructor_is_method_derived() {
    use ferrum_edge::proxy::headers::ClientResponseFraming;

    for method in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"] {
        assert!(
            matches!(
                ClientResponseFraming::for_streaming_response(method, 200),
                ClientResponseFraming::Streaming
            ),
            "{method} streaming responses must strip Content-Length"
        );
    }
    for method in ["HEAD", "head", "HeAd"] {
        assert!(
            matches!(
                ClientResponseFraming::for_streaming_response(method, 200),
                ClientResponseFraming::Head { status: 200 }
            ),
            "{method} must select Head framing regardless of case"
        );
    }
}

/// The gateway's own accounting capture must reproduce exactly what the wire
/// boundary would have accepted, so removing the field from the wire cannot
/// silently change H3 graceful-close classification or the direct-H2
/// large-response coalescer bypass.
#[test]
fn test_preserved_response_content_length_matches_boundary_acceptance() {
    use ferrum_edge::proxy::headers::preserved_response_content_length;
    use std::collections::HashMap;

    for (key, value, expected) in [
        ("content-length", "0", Some(0u64)),
        ("content-length", "42", Some(42)),
        ("content-length", "042", Some(42)),
        ("Content-Length", "42", Some(42)),
        ("content-length", " 42 ", Some(42)),
        ("content-length", "+42", None),
        ("content-length", "-1", None),
        ("content-length", "4 2", None),
        ("content-length", "", None),
        ("content-length", "18446744073709551616", None),
    ] {
        let headers = HashMap::from([(key.to_string(), value.to_string())]);
        assert_eq!(
            preserved_response_content_length(&headers, 200),
            expected,
            "{key}: {value:?}"
        );
    }

    // Conflicting duplicates are a HeaderMap duplicate field — fail closed
    // rather than picking whichever variant iteration reached first.
    let duplicates = HashMap::from([
        ("content-length".to_string(), "42".to_string()),
        ("Content-Length".to_string(), "43".to_string()),
    ]);
    assert_eq!(preserved_response_content_length(&duplicates, 200), None);

    // No-body statuses have no declared length to account for.
    let headers = HashMap::from([("content-length".to_string(), "42".to_string())]);
    for status in [100u16, 204, 205, 304] {
        assert_eq!(
            preserved_response_content_length(&headers, status),
            None,
            "status {status} forbids a body"
        );
    }

    assert_eq!(
        preserved_response_content_length(&HashMap::new(), 200),
        None
    );
}

/// A buffered gRPC response with no DATA frames is trailers-only regardless of
/// which hook produced it, so `Content-Length` is removed rather than invented
/// as `0` or preserved from a plugin-authored map.
#[test]
fn test_buffered_grpc_framing_is_trailers_only_on_empty_body() {
    use ferrum_edge::proxy::headers::ClientResponseFraming;

    assert!(matches!(
        ClientResponseFraming::for_buffered_grpc(200, 0),
        ClientResponseFraming::TrailersOnly
    ));
    assert!(matches!(
        ClientResponseFraming::for_buffered_grpc(200, 17),
        ClientResponseFraming::ExactBody { len: 17, .. }
    ));
}

/// Regression: a plugin reject on the buffered gRPC path must not publish a
/// plugin-authored `Content-Length` on a response that sends zero DATA frames.
///
/// `normalize_reject_response(.., is_grpc_request = true)` strips every case
/// variant of protocol-managed `content-length`, empties the body for
/// trailers-only framing, and leaves only the authoritative gRPC terminal
/// metadata. Framing is derived from the final body, so every reject arm
/// selects trailers-only for an empty body rather than streaming framing that
/// would publish a surviving plugin length.
#[test]
fn test_buffered_grpc_plugin_reject_drops_plugin_authored_content_length() {
    use ferrum_edge::_test_support::normalize_reject_response;
    use ferrum_edge::proxy::headers::{
        ClientResponseFraming, sanitize_client_response_headers_for_wire,
    };
    use std::collections::HashMap;

    let plugin_reject_headers = HashMap::from([
        ("content-length".to_string(), "999".to_string()),
        ("Content-Length".to_string(), "31337".to_string()),
        ("x-plugin".to_string(), "1".to_string()),
    ]);
    let normalized = normalize_reject_response(
        StatusCode::FORBIDDEN,
        br#"{"error":"denied"}"#,
        &plugin_reject_headers,
        true,
    );

    assert!(
        normalized.body.is_empty(),
        "a native gRPC reject normalizes to trailers-only with no DATA frames"
    );
    assert!(
        !normalized
            .headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("content-length")),
        "normalization must strip every plugin-authored Content-Length case variant"
    );
    assert_eq!(
        normalized.headers.get("grpc-status").map(String::as_str),
        Some("7")
    );
    assert_eq!(
        normalized.headers.get("x-plugin").map(String::as_str),
        Some("1")
    );

    let framing = ClientResponseFraming::for_buffered_grpc(
        normalized.http_status.as_u16(),
        normalized.body.len(),
    );
    assert!(
        matches!(framing, ClientResponseFraming::TrailersOnly),
        "an empty buffered gRPC body must select trailers-only framing"
    );

    // Feed explicit case variants directly so the wire sanitizer is exercised
    // independently of reject normalization.
    let mut raw_length_variants = HashMap::from([
        ("content-length".to_string(), "999".to_string()),
        ("Content-Length".to_string(), "31337".to_string()),
        ("x-plugin".to_string(), "1".to_string()),
    ]);
    sanitize_client_response_headers_for_wire(&mut raw_length_variants, framing);
    assert!(
        !raw_length_variants
            .keys()
            .any(|name| name.eq_ignore_ascii_case("content-length")),
        "no Content-Length may reach a trailers-only gRPC response"
    );
    assert_eq!(
        raw_length_variants.get("x-plugin").map(String::as_str),
        Some("1")
    );

    // `Head` framing is the separate contract: it is the only arm that
    // preserves one valid length, and buffered gRPC rejects must not select it
    // for an empty body. Ordinary `Streaming` no longer preserves anything, so
    // it is not a distinguishing counterexample here.
    let mut head_headers = HashMap::from([("content-length".to_string(), "999".to_string())]);
    sanitize_client_response_headers_for_wire(
        &mut head_headers,
        ClientResponseFraming::Head { status: 200 },
    );
    assert_eq!(
        head_headers.get("content-length").map(String::as_str),
        Some("999"),
        "Head framing preserves the representation length, which buffered gRPC \
         rejects must not select for an empty body"
    );
}

/// GHSA-xvr4 header sealing and GHSA-5fp3 shared-`Bytes` delivery meet on the
/// same rejection: a retained cached payload must be handed onward as one
/// allocation while the gateway still publishes its own authoritative
/// `Content-Length`. Pinning them together stops a later change from buying
/// sharing back with a plugin-authored length, or fail-closed framing back with
/// a per-hit copy of the cached body.
#[test]
fn test_shared_reject_bytes_keep_allocation_and_gateway_derived_content_length() {
    use ferrum_edge::_test_support::build_reject_wire_parts_from_shared_bytes_for_test;
    use http::StatusCode;

    // Far past any inline-capacity threshold, so a copy shows up as an
    // unmistakable pointer change rather than an allocator coincidence.
    let cached = bytes::Bytes::from(vec![0x5cu8; 256 * 1024]);
    let cached_ptr = cached.as_ptr() as usize;
    // A plugin-authored length that disagrees with the payload actually sent.
    let headers = HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("content-length".to_string(), "9".to_string()),
    ]);

    let (parts, observed_ptr) = build_reject_wire_parts_from_shared_bytes_for_test(
        "GET",
        StatusCode::FORBIDDEN,
        cached.clone(),
        &headers,
    );

    assert_eq!(
        observed_ptr, cached_ptr,
        "the final reject header boundary must not copy the shared cached body"
    );
    let expected = cached.len().to_string();
    assert_eq!(
        parts
            .headers
            .get("content-length")
            .and_then(|value| value.to_str().ok()),
        Some(expected.as_str()),
        "the gateway must overwrite the plugin-authored length with the real one"
    );

    // HEAD: the synthetic-response contract has already emptied the wire body,
    // so the declared representation length survives instead of collapsing to a
    // misleading `0`.
    let (head_parts, _) = build_reject_wire_parts_from_shared_bytes_for_test(
        "HEAD",
        StatusCode::OK,
        bytes::Bytes::new(),
        &HashMap::from([("content-length".to_string(), "4096".to_string())]),
    );
    assert_eq!(
        head_parts
            .headers
            .get("content-length")
            .and_then(|value| value.to_str().ok()),
        Some("4096"),
        "HEAD must keep the representation length the synthetic contract established"
    );
}

#[test]
fn reqwest_dispatch_fails_closed_when_proxy_ttl_dns_preflight_fails() {
    let source = include_str!("../../../src/proxy/mod.rs");
    assert!(
        source.contains("let policy_rejected = crate::dns::is_egress_policy_denial(error);"),
        "DNS preflight failures must use the canonical egress-policy classifier"
    );
    for (label, start_marker, resume_marker, rejection) in [
        (
            "retry",
            "pub(crate) async fn proxy_to_backend_retry(",
            "let client_result = crate::plugins::await_grpc_deadline(",
            "return backend_dns_resolution_failed_response(effective_host, &error);",
        ),
        (
            "initial dispatch",
            "async fn proxy_to_backend(",
            "if dispatch_hbone {",
            "return backend_dns_resolution_failed_dispatch_result(effective_host, &error);",
        ),
    ] {
        let function_start = source
            .find(start_marker)
            .unwrap_or_else(|| panic!("{label}: missing start marker"));
        let preflight_start = source[function_start..]
            .find(if label == "retry" {
                "let resolved_ip = match resolved_ip_result {"
            } else {
                "let resolved_ip = if dispatch_hbone"
            })
            .map(|offset| function_start + offset)
            .unwrap_or_else(|| panic!("{label}: missing DNS preflight result handling"));
        let resume = source[preflight_start..]
            .find(resume_marker)
            .map(|offset| preflight_start + offset)
            .unwrap_or_else(|| panic!("{label}: missing post-preflight dispatch marker"));
        let preflight = &source[preflight_start..resume];

        assert!(
            preflight.contains(rejection),
            "{label} must not continue to reqwest after the proxy-specific DNS lookup fails"
        );
        assert!(
            !preflight.contains("resolved_ip_result.ok()"),
            "{label} must not discard the proxy-specific DNS error"
        );
    }
}

#[test]
fn cross_cluster_hbone_identity_bypasses_only_the_reqwest_dns_preflight() {
    let source = include_str!("../../../src/proxy/mod.rs");
    let helper = source
        .split("fn is_synthetic_cross_cluster_hbone_dispatch_target(")
        .nth(1)
        .expect("synthetic cross-cluster HBONE shape helper")
        .split("/// Whether a target dispatches over the Sidecar")
        .next()
        .expect("bounded synthetic cross-cluster HBONE shape helper");
    for required in [
        "HBONE_CROSS_CLUSTER_SYNTHETIC_HOST_PREFIX",
        "target_hbone_enabled(target)",
        "target_hbone_cross_cluster(target)",
        "HBONE_DIAL_HOST_TAG",
        "HBONE_AUTHORITY_HOST_TAG",
        "MESH_EASTWEST_SNI_TAG",
        "MESH_TRUST_DOMAIN_TAG",
    ] {
        assert!(
            helper.contains(required),
            "synthetic-host exemption must require {required}"
        );
    }

    let initial = source
        .split("async fn proxy_to_backend(")
        .nth(1)
        .expect("initial backend dispatch")
        .split("if dispatch_hbone {")
        .next()
        .expect("bounded pre-HBONE dispatch section");
    let synthetic_gate = initial
        .find("is_synthetic_cross_cluster_hbone_dispatch_target")
        .expect("cross-cluster HBONE synthetic-host gate");
    let dns_preflight = initial[synthetic_gate..]
        .find("state.dns_cache.resolve(")
        .map(|offset| synthetic_gate + offset)
        .expect("ordinary-host DNS preflight");
    let hard_failure = initial[dns_preflight..]
        .find("return backend_dns_resolution_failed_dispatch_result(effective_host, &error);")
        .map(|offset| dns_preflight + offset)
        .expect("ordinary-host fail-closed result");

    assert!(
        synthetic_gate < dns_preflight && dns_preflight < hard_failure,
        "only the scoped HBONE identity may skip the reqwest-oriented DNS preflight"
    );
    assert!(
        initial[synthetic_gate..dns_preflight].contains("None"),
        "the synthetic identity must carry no fabricated resolved IP into HBONE dispatch"
    );
}

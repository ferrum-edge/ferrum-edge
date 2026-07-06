#[test]
fn h3_frontend_caps_retry_before_retry_dependent_decisions() {
    let source = include_str!("../../../src/http3/server.rs");
    let selection = source
        .find("let selection = crate::proxy::backend_dispatch::select_upstream_target(")
        .expect("H3 selected-target lookup must remain present");
    let after_selection = &source[selection..];

    let cap = after_selection
        .find("let selected_base_proxy =")
        .expect("H3 frontend must cap retry policy by selected target");
    let effective = after_selection
        .find("let effective_proxy = crate::proxy::resolve_effective_proxy_for_target(")
        .expect("H3 frontend must resolve selected-target effective proxy");
    assert!(
        after_selection[effective..].contains("&selected_base_proxy"),
        "H3 effective proxy resolution must use the retry-capped selected base proxy"
    );
    let has_retry = after_selection
        .find("let has_retry = match http_flavor")
        .expect("retry-dependent buffering decision must remain present");
    let native_h3_decision = after_selection
        .find("let backend_supports_native_h3 =")
        .expect("native-H3 dispatch decision must remain present");
    let circuit_breaker = after_selection
        .find("check_circuit_breaker(")
        .expect("H3 circuit-breaker check must remain present");

    assert!(
        cap < has_retry,
        "retry cap must run before retry-dependent buffering/native-H3 gates"
    );
    assert!(
        effective < native_h3_decision,
        "effective proxy must be resolved before native-H3 capability decisions"
    );
    assert!(
        effective < circuit_breaker,
        "effective proxy must be resolved before circuit-breaker/admission dispatch"
    );
}

#[test]
fn h3_plain_and_grpc_bridges_keep_unresolved_base_proxy_for_retries() {
    let source = include_str!("../../../src/http3/server.rs");
    let bridge_call = source
        .find(
            "crate::http3::cross_protocol::run(crate::http3::cross_protocol::CrossProtocolRequest",
        )
        .expect("H3 cross-protocol bridge call must remain present");
    let bridge = &source[bridge_call..];
    let proxy_field = bridge
        .find("proxy: if matches!(http_flavor, HttpFlavor::Plain | HttpFlavor::Grpc)")
        .expect("H3 plain/gRPC bridge must choose an unresolved base proxy");
    let base_branch = bridge[proxy_field..]
        .find("selected_base_proxy.as_ref()")
        .expect("H3 plain/gRPC bridge must pass the capped unresolved base proxy");
    let effective_branch = bridge[proxy_field..]
        .find("proxy.as_ref()")
        .expect("remaining H3 bridge paths must still use the effective proxy");

    assert!(
        base_branch < effective_branch,
        "plain/gRPC bridge must prefer selected_base_proxy so retry targets are resolved per attempt"
    );
}

#[test]
fn h3_websocket_bridge_keeps_unresolved_base_proxy_for_retries() {
    let source = include_str!("../../../src/http3/server.rs");
    let websocket_call = source
        .find("crate::http3::websocket::handle_h3_websocket(")
        .expect("H3 WebSocket bridge call must remain present");
    let websocket_args = &source[websocket_call..];
    let proxy_arg = websocket_args
        .find("Arc::clone(&selected_base_proxy)")
        .expect("H3 WebSocket bridge must receive the capped unresolved base proxy");
    let effective_proxy_arg = websocket_args
        .find("\n            proxy,")
        .unwrap_or(usize::MAX);

    assert!(
        proxy_arg < effective_proxy_arg,
        "H3 WebSocket bridge must not inherit the first target's effective proxy"
    );
}

#[test]
fn h3_grpc_streaming_bridge_keeps_unresolved_base_proxy_for_selected_target() {
    let source = include_str!("../../../src/http3/server.rs");
    let streaming_call = source
        .find("crate::http3::cross_protocol::dispatch_grpc_streaming(")
        .expect("H3 streaming gRPC bridge call must remain present");
    let streaming_args = &source[streaming_call..];
    let base_proxy_arg = streaming_args
        .find("&selected_base_proxy")
        .expect("H3 streaming gRPC bridge must receive the capped unresolved base proxy");
    let effective_proxy_arg = streaming_args
        .find("\n                &proxy,")
        .unwrap_or(usize::MAX);

    assert!(
        base_proxy_arg < effective_proxy_arg,
        "H3 streaming gRPC bridge must not inherit the first target's effective proxy"
    );
}

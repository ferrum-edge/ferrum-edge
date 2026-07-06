fn assert_websocket_retry_rechecks_circuit_breaker(
    src: &str,
    retry_log_marker: &str,
    path_label: &str,
) {
    let retry_start = src
        .find("let mut retry_backend_url = current_backend_url.clone();")
        .unwrap_or_else(|| panic!("{path_label}: retry target staging block not found"));
    let retry_tail = &src[retry_start..];
    let retry_log = retry_tail
        .find(retry_log_marker)
        .unwrap_or_else(|| panic!("{path_label}: retry log marker not found"));
    let retry_block = &retry_tail[..retry_log];

    let gate = retry_block
        .find("state.circuit_breaker_cache.can_execute(")
        .unwrap_or_else(|| panic!("{path_label}: retry block does not recheck circuit breaker"));
    let url_assignment = retry_block
        .find("current_backend_url = retry_backend_url")
        .unwrap_or_else(|| panic!("{path_label}: retry URL assignment not found"));
    let key_assignment = retry_block
        .find("current_cb_target_key = retry_cb_target_key")
        .unwrap_or_else(|| panic!("{path_label}: retry circuit-breaker key assignment not found"));

    assert!(
        gate < url_assignment,
        "{path_label}: retry URL is assigned before circuit-breaker admission"
    );
    assert!(
        gate < key_assignment,
        "{path_label}: retry circuit-breaker key is assigned before admission"
    );
}

fn assert_websocket_success_records_against_current_key(src: &str, path_label: &str) {
    let success_start = src
        .find("Backend handshake succeeded")
        .unwrap_or_else(|| panic!("{path_label}: success accounting block not found"));
    let success_tail = &src[success_start..];
    let record_success = success_tail
        .find("cb.record_success(ws_cb_probe_slot_available)")
        .unwrap_or_else(|| panic!("{path_label}: record_success call not found"));
    let success_block = &success_tail[..record_success];

    assert!(
        success_block.contains("current_cb_target_key.as_deref()"),
        "{path_label}: success accounting must use the retry-admitted circuit-breaker key"
    );
}

#[test]
fn h1_h2_websocket_retry_is_circuit_breaker_gated_before_dispatch() {
    let src = include_str!("../../../src/proxy/mod.rs");
    assert_websocket_retry_rechecks_circuit_breaker(
        src,
        "\"Retrying WebSocket backend connection\"",
        "h1_h2_websocket",
    );
    assert_websocket_success_records_against_current_key(src, "h1_h2_websocket");
}

#[test]
fn h3_websocket_retry_is_circuit_breaker_gated_before_dispatch() {
    let src = include_str!("../../../src/http3/websocket.rs");
    assert_websocket_retry_rechecks_circuit_breaker(
        src,
        "\"Retrying H3 WebSocket backend connection\"",
        "h3_websocket",
    );
    assert_websocket_success_records_against_current_key(src, "h3_websocket");
}

// The H3 WebSocket bridge has no mesh WS transport fork, so its connect loop
// must screen the selected target with `direct_http_mesh_transport_refusal`
// BEFORE the plain `connect_websocket_backend` dial. The screen sits at the
// loop top so both the initial target and every retry-rotated target
// re-entering the loop are covered (issue #2007).
#[test]
fn h3_websocket_connect_loop_screens_mesh_transport_refusal_before_dial() {
    let src = include_str!("../../../src/http3/websocket.rs");
    let loop_start = src
        .find("let backend_handshake = loop {")
        .expect("h3_websocket: backend connect loop not found");
    let loop_tail = &src[loop_start..];
    let refusal = loop_tail
        .find("direct_http_mesh_transport_refusal(")
        .expect("h3_websocket: connect loop does not screen mesh transport refusal");
    let dial = loop_tail
        .find("connect_websocket_backend(")
        .expect("h3_websocket: backend dial not found");
    assert!(
        refusal < dial,
        "h3_websocket: the mesh-transport refusal screen must run before the plain \
         backend dial so a mesh-tagged target (initial or retry-rotated) is never \
         dialed directly"
    );
}

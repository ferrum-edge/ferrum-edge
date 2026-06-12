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

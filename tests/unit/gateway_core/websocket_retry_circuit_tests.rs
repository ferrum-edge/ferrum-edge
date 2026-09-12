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
        .find("cb.record_success(cb_probe.take_slot())")
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

// After issue #3620 the H3 WebSocket bridge shares the H1/H2 mesh WS egress
// fork. Unix-socket targets still fail closed via `h3_bridge_transport_refusal`
// BEFORE any dial; mesh-tagged targets ride `connect_mesh_websocket_backend`.
// The Unix screen sits at the loop top so both the initial target and every
// retry-rotated target re-entering the loop are covered.
#[test]
fn h3_websocket_connect_loop_screens_unix_and_forks_mesh_before_dial() {
    let src = include_str!("../../../src/http3/websocket.rs");
    let loop_start = src
        .find("let backend_handshake = loop {")
        .expect("h3_websocket: backend connect loop not found");
    let loop_tail = &src[loop_start..];
    let refusal = loop_tail
        .find("h3_bridge_transport_refusal(")
        .expect("h3_websocket: connect loop must screen Unix-only bridge refusal");
    let mesh = loop_tail
        .find("connect_mesh_websocket_backend(")
        .expect("h3_websocket: mesh egress dial must be present");
    let dial = loop_tail
        .find("connect_websocket_backend(")
        .expect("h3_websocket: direct backend dial not found");
    assert!(
        refusal < mesh && mesh < dial,
        "h3_websocket: Unix refusal, then mesh fork, then direct dial — a mesh-tagged \
         target must never fall through to the plaintext dial"
    );
    assert!(
        loop_tail.contains("websocket_mesh_egress"),
        "h3_websocket must reuse the shared websocket_mesh_egress classifier"
    );
    assert!(
        loop_tail.contains("select_next_h3_eligible_retry_target("),
        "h3_websocket retry rotation must skip H3-ineligible (Unix) candidates via the shared helper"
    );
}

/// After main landed Unix WebSocket backend handshakes (#3732), the H3 bridge
/// relay must stay exhaustive on Unix without enabling Unix dispatch: the connect
/// loop still refuses Unix targets before dial, and any impossible Unix variant
/// reaching the relay match must fail closed without `run_websocket_proxy`.
#[test]
fn h3_websocket_relay_rejects_impossible_unix_handshake_without_dispatch() {
    let src = include_str!("../../../src/http3/websocket.rs");
    let relay_start = src
        .find("let relay_result = match backend_handshake {")
        .expect("h3_websocket: backend relay dispatch match not found");
    let relay_tail = &src[relay_start..];
    let relay_end = relay_tail
        .find("\n    };\n\n    if let Err(e) = relay_result")
        .expect("h3_websocket: relay match terminator not found");
    let relay_block = &relay_tail[..relay_end];

    assert!(
        relay_block.contains("WsBackendHandshake::Direct(")
            && relay_block.contains("WsBackendHandshake::Mesh(")
            && relay_block.contains("WsBackendHandshake::Unix("),
        "h3_websocket relay must dispatch Direct, Mesh, and Unix variants"
    );
    let unix_arm = relay_block
        .find("WsBackendHandshake::Unix(")
        .expect("h3_websocket relay must include Unix arm for exhaustiveness");
    let unix_slice = &relay_block[unix_arm..];
    assert!(
        unix_slice.contains("let _handshake = *handshake"),
        "impossible Unix relay arm must own the handshake so its private lease drops at arm end"
    );
    assert!(
        !unix_slice.contains("conn_lease"),
        "H3 Unix relay must not access UnixBackendWsHandshake's private conn_lease field"
    );
    assert!(
        !unix_slice.contains("run_websocket_proxy("),
        "H3 must never frame-relay a Unix backend (no H3 Unix dialer)"
    );
    assert!(
        unix_slice.contains("Unix socket dispatch required for this backend target"),
        "impossible Unix relay arm must reuse the bridge refusal contract"
    );

    let loop_start = src
        .find("let backend_handshake = loop {")
        .expect("h3_websocket: backend connect loop not found");
    let connect_tail = &src[loop_start..];
    assert!(
        connect_tail.contains("h3_bridge_transport_refusal("),
        "h3_websocket connect loop must still refuse Unix before dial"
    );
    let connect_only = connect_tail
        .split("let relay_result = match backend_handshake {")
        .next()
        .expect("h3_websocket connect loop must precede relay dispatch");
    assert!(
        !connect_only.contains("WsBackendHandshake::Unix("),
        "h3_websocket connect loop must not construct Unix handshakes"
    );
}

/// Helper `None` means "no OTHER eligible candidate" (the ordinary single-target
/// upstream), NOT "this transport is undispatchable" — the current target was
/// already screened by `h3_bridge_transport_refusal` at the connect-loop top.
/// So `None` must fall through and retry that screened target, exactly as the
/// H1/H2 WebSocket loop, the native-H3 loop, and the H3 plain bridge do.
/// Aborting there would silently disable connect-failure retry for every
/// single-target upstream.
#[test]
fn h3_websocket_retry_maps_helper_none_to_current_target_fallthrough() {
    let src = include_str!("../../../src/http3/websocket.rs");
    let retry_start = src
        .find("let mut retry_backend_url = current_backend_url.clone();")
        .expect("h3_websocket: retry staging block not found");
    let retry_tail = &src[retry_start..];
    let retry_log = retry_tail
        .find("\"Retrying H3 WebSocket backend connection\"")
        .expect("h3_websocket: retry log marker not found");
    let retry_block = &retry_tail[..retry_log];

    let helper = retry_block
        .find("select_next_h3_eligible_retry_target(")
        .expect("h3_websocket: shared H3-eligible helper call not found");

    // The staged retry identity defaults to the current attempt's, so a helper
    // `None` retries the already-screened target instead of aborting.
    let staging = &retry_block[..helper];
    assert!(
        staging.contains("let mut retry_target = current_target.clone();")
            && staging.contains("let mut retry_cb_target_key = current_cb_target_key.clone();")
            && staging.contains("let mut retry_path_mismatch = false;"),
        "h3_websocket: retry identity must default to the current attempt's target"
    );

    let none_arm = retry_block[helper..]
        .find("None =>")
        .expect("h3_websocket: helper None arm must be explicit (not if-let Some)");
    let none_slice = &retry_block[helper + none_arm..];
    assert!(
        !none_slice.contains("retry_path_mismatch = true"),
        "h3_websocket: helper None must not abort the retry — the current target is \
         already H3-eligible and every sibling retry loop retries it"
    );

    // `Some(next)` still keeps path + DestinationRule budget gates before dial.
    let some_arm = retry_block[helper..]
        .find("Some(next)")
        .expect("h3_websocket: helper Some(next) arm must remain");
    assert!(
        some_arm < none_arm,
        "h3_websocket: Some(next) path/budget checks must precede the None arm"
    );
    let some_slice = &retry_block[helper + some_arm..helper + none_arm];
    assert!(
        some_slice.contains("retry_target_preserves_backend_path(")
            && some_slice.contains("retry_attempt_allowed_for_target("),
        "h3_websocket: Some(next) must still enforce path + retry-budget checks"
    );
    assert_eq!(
        some_slice.matches("retry_path_mismatch = true").count(),
        2,
        "h3_websocket: only the path-change and retry-budget rejections may abort a rotation"
    );

    // Abort gate must still prevent sleeping / incrementing / continue-retry.
    assert!(
        retry_block.contains("if !retry_path_mismatch")
            && retry_block.contains("if retry_admitted_by_cb && !retry_path_mismatch"),
        "h3_websocket: retry_path_mismatch must still gate sleep, CB admission, and continue"
    );
}

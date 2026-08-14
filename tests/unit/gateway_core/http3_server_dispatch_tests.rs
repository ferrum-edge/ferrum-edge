#[test]
fn h3_native_forces_mesh_onto_bridge_and_refuses_unix_before_dispatch() {
    let src = include_str!("../../../src/http3/server.rs");
    assert!(
        src.contains("target_requires_http_mesh_egress")
            && src.contains("&& !mesh_egress_required"),
        "native H3 pool selection must force mesh-tagged targets onto the bridge (issue #3620)"
    );
    let native_gate = src
        .find("let native_h3_direct_dispatch = use_native_h3_pool || use_native_h3_grpc;")
        .expect("native H3 direct-dispatch gate must remain explicit");
    let after_gate = &src[native_gate..];
    let refusal = after_gate
        .find("h3_bridge_transport_refusal(")
        .expect("native H3 dispatch must screen Unix-only bridge refusal");
    let native_grpc = after_gate
        .find("if use_native_h3_grpc")
        .expect("native H3 gRPC dispatch branch must remain present");
    let native_plain_bridge_bypass = after_gate
        .find("if !use_native_h3_pool")
        .expect("native plain H3 bridge-bypass branch must remain present");

    assert!(
        refusal < native_grpc,
        "Unix-transport-tagged gRPC targets must fail closed before native H3 gRPC dispatch can dial the QUIC pool"
    );
    assert!(
        refusal < native_plain_bridge_bypass,
        "Unix-transport-tagged plain targets must fail closed before native H3 plain dispatch can bypass the bridge"
    );

    let dispatch_src = include_str!("../../../src/proxy/backend_dispatch.rs");
    assert!(
        dispatch_src.contains("pub(crate) fn h3_bridge_transport_refusal(")
            && dispatch_src.contains("pub(crate) fn h3_dispatch_target_eligible("),
        "issue #3620 helpers for H3 bridge Unix refusal and retry eligibility must remain present"
    );
}

#[test]
fn h3_plain_bridge_dispatches_mesh_through_shared_pools() {
    let source = include_str!("../../../src/http3/cross_protocol.rs");
    let plain = source
        .split("async fn dispatch_plain<S>(")
        .nth(1)
        .expect("H3→HTTP plain dispatcher must remain present")
        .split("async fn dispatch_grpc<S>(")
        .next()
        .expect("H3→HTTP plain dispatcher must remain bounded");
    assert!(
        plain.contains("run_plain_attempt_local_policy_or_reject("),
        "every plain attempt must pass through the local transport-policy gate"
    );
    assert!(
        source.contains("async fn run_plain_attempt_local_policy_or_reject")
            && source.contains("h3_bridge_transport_refusal(current_target)"),
        "the shared per-attempt policy gate must refuse Unix targets, not all mesh tags"
    );
    assert!(
        plain.contains("boxed_proxy_h3_plain_http_mesh_buffered("),
        "mesh-tagged plain attempts must dial through the boxed shared mesh helper"
    );
    assert!(
        !plain.contains("crate::proxy::proxy_h3_plain_http_mesh_buffered("),
        "H3 plain mesh dispatch must not materialize the helper in the bridge poll frame"
    );
    assert!(
        plain.contains("select_next_cross_protocol_retry_target("),
        "mixed-upstream retry rotation must go through the shared cross-protocol selector"
    );
    let retry_selector = source
        .split("fn select_next_cross_protocol_retry_target(")
        .nth(1)
        .expect("cross-protocol retry selector must remain present")
        .split("async fn resolve_cross_protocol_backend_ip(")
        .next()
        .expect("bounded cross-protocol retry selector");
    assert!(
        retry_selector.contains("select_next_h3_eligible_retry_target("),
        "mixed-upstream retry rotation must filter H3-ineligible candidates via the shared helper"
    );
    assert!(
        plain.contains("target_requires_http_mesh_egress"),
        "streaming mesh uploads must force-buffer for replayable mesh dispatch"
    );
    assert!(
        plain.contains("run_after_proxy_hooks("),
        "mesh terminal writes must still run after_proxy (issue #3620)"
    );
}

#[test]
fn h3_plain_mesh_upload_collection_releases_half_open_probe_before_terminal_write() {
    let source = include_str!("../../../src/http3/cross_protocol.rs");
    let plain = source
        .split("async fn dispatch_plain<S>(")
        .nth(1)
        .expect("H3→HTTP plain dispatcher must remain present")
        .split("async fn dispatch_grpc<S>(")
        .next()
        .expect("H3→HTTP plain dispatcher must remain bounded");
    let mesh_block_start = plain
        .find("target_requires_http_mesh_egress")
        .expect("mesh force-buffer gate must remain present");
    let mesh_block = &plain[mesh_block_start..];
    let mesh_block_end = mesh_block
        .find("let (response, bytes_sent, mut backend_admission_permits")
        .expect("mesh force-buffer block must remain bounded");
    let mesh_collection = &mesh_block[..mesh_block_end];

    assert!(
        mesh_collection.contains("collect_h3_request_body_under_authorization("),
        "mesh uploads must force-collect via collect_h3_request_body_under_authorization"
    );
    assert!(
        mesh_collection.contains("plain_write_bound"),
        "mesh force-buffer must drain under the composed authorization bound"
    );
    assert!(
        !mesh_collection.contains("grpc_web_deadline_at"),
        "mesh force-buffer must not drain under the client RPC deadline wrapper"
    );
    assert_eq!(
        mesh_collection
            .matches("release_cross_protocol_circuit_breaker_probe_on_admission_reject(")
            .count(),
        3,
        "mesh upload collection must release the HALF_OPEN probe on each terminal reject branch"
    );

    let oversize = mesh_collection
        .split("Ok(None)")
        .nth(1)
        .expect("missing mesh collection branch: Ok(None)")
        .split("H3RequestBodyReadError::DeadlineExceeded")
        .next()
        .expect("bounded mesh collection Ok(None) branch");
    let oversize_release = oversize
        .find("release_cross_protocol_circuit_breaker_probe_on_admission_reject(")
        .expect("Ok(None) must release HALF_OPEN probe");
    let oversize_write = oversize
        .find("write_plain_gateway_error(")
        .expect("Ok(None) must write plain gateway error");
    assert!(
        oversize_release < oversize_write,
        "Ok(None) must release probe before terminal write"
    );

    // Bind the exact force-buffer DeadlineExceeded arm, including the typed
    // capture, then compare ordering in one whitespace-normalized slice so a
    // rustfmt wrap cannot point the test at a comment or a nested-arm offset.
    let deadline_start = mesh_collection
        .find("H3RequestBodyReadError::DeadlineExceeded")
        .expect("missing mesh collection branch: DeadlineExceeded");
    let deadline = mesh_collection[deadline_start..]
        .split("H3RequestBodyReadError::TimedOut")
        .next()
        .expect("bounded mesh collection DeadlineExceeded branch");
    let deadline_compact: String = deadline.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(
        deadline_compact.contains("DeadlineExceeded(authorization_expiry)")
            || deadline_compact.contains("DeadlineExceeded(authorization_expiry,)"),
        "the mesh force-buffer must bind the captured winner rather than a unit variant"
    );
    let deadline_release = deadline_compact
        .find("release_cross_protocol_circuit_breaker_probe_on_admission_reject(")
        .expect("DeadlineExceeded must release HALF_OPEN probe");
    let auth_record = deadline_compact
        .find("record_authorization_termination_once(")
        .expect("Some(termination) must record the bounded class");
    let auth_write = deadline_compact
        .find("write_plain_authorization_expired_terminal(")
        .expect("Some(termination) must write the grace-bounded 401");
    assert!(
        deadline_compact.contains("StreamAuthProtocolFamily::Http"),
        "mesh force-buffer authorization expiry is the HTTP family"
    );
    assert!(
        !deadline_compact.contains("write_plain_gateway_error("),
        "mesh force-buffer authorization expiry must not use the unbounded reject writer"
    );
    let deadline_write = deadline_compact
        .find("write_plain_grpc_web_client_deadline(")
        .expect("DeadlineExceeded(None) must keep the gRPC-Web/client deadline response");
    assert!(
        deadline_release < auth_record,
        "DeadlineExceeded must release the probe before recording authorization expiry"
    );
    assert!(
        auth_record < auth_write,
        "fixed-cardinality authorization termination must be recorded before the 401 write"
    );
    assert!(
        deadline_release < deadline_write,
        "DeadlineExceeded(None) must release the probe before the client-deadline terminal"
    );

    let timeout = mesh_collection
        .split("H3RequestBodyReadError::TimedOut")
        .nth(1)
        .expect("missing mesh collection branch: TimedOut/Read")
        .split("} else {")
        .next()
        .expect("bounded mesh collection TimedOut/Read branch");
    let timeout_release = timeout
        .find("release_cross_protocol_circuit_breaker_probe_on_admission_reject(")
        .expect("TimedOut/Read must release HALF_OPEN probe");
    let timeout_write = timeout
        .find("write_plain_gateway_error(")
        .expect("TimedOut/Read must write plain gateway error");
    assert!(
        timeout_release < timeout_write,
        "TimedOut/Read must release probe before terminal write"
    );
}

#[test]
fn h3_reject_writer_skips_empty_data_frames() {
    let src = include_str!("../../../src/http3/server.rs");
    let helper = src
        .find("async fn send_h3_finalized_reject_response(")
        .expect("H3 finalized reject writer must remain present");
    let body = &src[helper..];
    assert!(
        body.contains("if !body.is_empty()") && body.contains("stream.send_data("),
        "H3 reject writer must skip DATA when the shared no-body preparation emptied the body"
    );
    let proxy_src = include_str!("../../../src/proxy/mod.rs");
    assert!(
        proxy_src.contains("prepare_synthetic_response_wire("),
        "shared reject finalizer must centralize HEAD/204/205/304 wire preparation"
    );
    let shared_finalizer_start = proxy_src
        .find("pub(crate) async fn apply_reject_after_proxy_and_synthetic_body_hooks(")
        .expect("shared reject finalizer must remain present");
    let shared_finalizer = &proxy_src[shared_finalizer_start..];
    let shared_finalizer_end = shared_finalizer
        .find("pub(crate) struct AfterProxyReject")
        .expect("shared reject finalizer boundary must remain present");
    assert!(
        shared_finalizer[..shared_finalizer_end].contains("*body = Bytes::new();"),
        "shared no-body finalization must drop retained body allocation rather than clear-in-place"
    );
    assert!(
        !shared_finalizer[..shared_finalizer_end].contains("body.clear();"),
        "shared no-body finalization must not retain large synthetic body capacity"
    );
    let streaming_start = src
        .find("async fn run_h3_streaming_after_proxy_hooks(")
        .expect("H3 streaming after_proxy helper must remain present");
    let streaming_tail = &src[streaming_start..];
    let streaming_end = streaming_tail
        .find("\n#[allow(clippy::too_many_arguments)]\nasync fn proxy_to_backend_h3_refined_response(")
        .expect("H3 streaming after_proxy helper boundary must remain present");
    assert!(
        streaming_tail[..streaming_end].contains("prepare_synthetic_response_wire("),
        "streaming after_proxy rejections must also apply shared HEAD/no-body wire preparation"
    );
    assert!(
        streaming_tail[..streaming_end].contains("reject.body = Bytes::new();"),
        "H3 streaming no-body finalization must drop retained body allocation rather than clear-in-place"
    );
    assert!(
        !streaming_tail[..streaming_end].contains("reject.body.clear();"),
        "H3 streaming no-body finalization must not retain large reject body capacity"
    );
}

#[test]
fn h3_final_body_rejects_use_complete_synthetic_response_pipeline() {
    let src = include_str!("../../../src/http3/server.rs");
    let request_scoped_gate = src
        .find("let has_terminal_body_dispatch = capabilities")
        .expect("H3 terminal dispatch must retain a request-scoped applicability gate");
    let dispatch_marker = src
        .find("// Terminal final-body hooks may perform provider egress.")
        .expect("H3 terminal final-body dispatch boundary must remain present");
    let early_dispatch = src[dispatch_marker..]
        .find("if final_body_before_backend_dispatch {")
        .map(|offset| dispatch_marker + offset)
        .expect("H3 terminal final-body dispatch gate must remain present");
    let applicability = &src[request_scoped_gate..early_dispatch];
    assert!(applicability.contains("if let Some(transformed_headers)"));
    assert!(applicability.contains("std::mem::swap(&mut ctx.headers, transformed_headers)"));
    assert!(applicability.contains("crate::proxy::final_request_body_requirements("));

    let early_start = src
        .find("let raw_request_body_bytes = body_data.len() as u64;")
        .expect("H3 early request-body finalization must remain present");
    let early_end = src[early_start..]
        .find("let backend_admission_plugins = plugin_cache_view.backend_admission_plugins();")
        .map(|offset| early_start + offset)
        .expect("H3 early finalization boundary must remain present");
    let early = &src[early_start..early_end];
    assert!(early.contains("apply_reject_after_proxy_and_synthetic_body_hooks("));
    assert!(!early.contains("apply_replaceable_after_proxy_hooks_to_rejection("));
    assert!(early.contains("matches!(http_flavor, HttpFlavor::Grpc)"));
    let terminal_reject = early
        .split("let rejection_hook_start = std::time::Instant::now();")
        .nth(1)
        .expect("H3 terminal rejection latency timer must remain present");
    let commit = terminal_reject
        .find("run_h3_reject_response_committed_hooks(")
        .expect("H3 terminal rejection commit hook");
    let account = terminal_reject
        .find("plugin_execution_ns += rejection_hook_start.elapsed().as_nanos() as u64;")
        .expect("H3 terminal rejection hook latency accounting");
    let log = terminal_reject
        .find("log_rejected_request_with_path(")
        .expect("H3 terminal rejection log");
    assert!(commit < account && account < log);

    let late_start = src
        .find("// Skip the per-plugin context-aware dispatch")
        .expect("H3 late request-body finalization must remain present");
    let late_end = src[late_start..]
        .find("backend_admission_start = std::time::Instant::now();")
        .map(|offset| late_start + offset)
        .expect("H3 backend-admission boundary must remain present");
    let late = &src[late_start..late_end];
    assert!(late.contains("apply_reject_after_proxy_and_synthetic_body_hooks("));
    assert!(!late.contains("apply_replaceable_after_proxy_hooks_to_rejection("));
    assert!(late.contains("matches!(http_flavor, HttpFlavor::Grpc)"));
}

#[test]
fn h3_terminal_body_read_failures_commit_dedup_cleanup_once() {
    let src = include_str!("../../../src/http3/server.rs");
    let finalizer = src
        .split("async fn finalize_h3_terminal_body_read_rejection(")
        .nth(1)
        .expect("H3 terminal-body rejection finalizer must remain present")
        .split("/// Optional HTTP/3 listener settings")
        .next()
        .expect("H3 terminal-body rejection finalizer must remain bounded");
    assert!(finalizer.contains("RELEASE_INFLIGHT_ON_COMMIT_METADATA_KEY"));
    assert_eq!(
        finalizer
            .matches("apply_reject_after_proxy_and_synthetic_body_hooks(")
            .count(),
        1
    );
    assert!(finalizer.contains("matches!(http_flavor, HttpFlavor::Grpc),\n        false,"));
    assert_eq!(
        finalizer
            .matches("run_h3_reject_response_committed_hooks(")
            .count(),
        1
    );
    assert_eq!(
        finalizer.matches("log_rejected_request_with_path(").count(),
        1
    );
    assert_eq!(finalizer.matches("record_request(state,").count(), 1);
    let decorate = finalizer
        .find("apply_reject_after_proxy_and_synthetic_body_hooks(")
        .expect("terminal rejection decorators");
    let commit = finalizer
        .find("run_h3_reject_response_committed_hooks(")
        .expect("terminal rejection commit");
    let account = finalizer
        .find("*plugin_execution_ns += rejection_hook_start.elapsed().as_nanos() as u64;")
        .expect("terminal rejection hook latency accounting");
    let log = finalizer
        .find("log_rejected_request_with_path(")
        .expect("terminal rejection log");
    let metric = finalizer
        .find("record_request(state,")
        .expect("terminal rejection metric");
    assert!(decorate < commit && commit < account && account < log && log < metric);
    assert!(finalizer.contains("FinalizedH3TerminalBodyRejection {"));
    assert!(finalizer.contains("http_status,\n        headers,\n        body,"));

    let content_length_fast_path = src
        .split("// Enforce request body size limit via Content-Length fast path.")
        .nth(1)
        .expect("H3 Content-Length fast path must remain present")
        .split("// Finalize a body that can affect response streaming")
        .next()
        .expect("H3 Content-Length fast path must remain bounded");
    assert!(content_length_fast_path.contains("if final_body_before_backend_dispatch"));
    let content_length_finalize = content_length_fast_path
        .find("finalize_h3_terminal_body_read_rejection(")
        .expect("Content-Length rejection finalizer");
    let content_length_send = content_length_fast_path
        .find("send_h3_plugin_reject_flavor_aware(")
        .expect("Content-Length rejection send");
    assert!(content_length_finalize < content_length_send);
    assert!(content_length_fast_path.contains("rejection.body.clone()"));
    assert!(content_length_fast_path.contains("&rejection.headers"));

    let terminal_dispatch = src
        .split("// Terminal final-body hooks may perform provider egress.")
        .nth(1)
        .expect("H3 terminal provider dispatch must remain present")
        .split("let backend_admission_plugins = plugin_cache_view.backend_admission_plugins();")
        .next()
        .expect("H3 terminal provider dispatch must remain bounded");
    assert!(terminal_dispatch.contains("collect_h3_request_body_under_authorization("));
    assert!(terminal_dispatch.contains("drain_h3_request_body("));
    // Ok(None): idle recv after a completed oversize drain — the flavor-aware
    // writer already halts after HEADERS; do not duplicate STOP_SENDING.
    // Read: client gone — halt, finalize cleanup, no response write.
    // TimedOut: mid-recv_data cancel — write under post-deadline grace with
    // halt_recv=false, then let the wrapper halt through the vendored transport.
    let oversize = terminal_dispatch
        .split("Ok(None)")
        .nth(1)
        .expect("missing terminal upload branch: Ok(None)")
        .split("H3RequestBodyReadError::Read(error)")
        .next()
        .expect("bounded terminal upload branch");
    assert_eq!(
        oversize
            .matches("finalize_h3_terminal_body_read_rejection(")
            .count(),
        1
    );
    let oversize_finalize = oversize
        .find("finalize_h3_terminal_body_read_rejection(")
        .expect("terminal upload rejection finalizer");
    let oversize_send = oversize
        .find("send_h3_plugin_reject_flavor_aware(")
        .expect("terminal upload rejection send");
    assert!(oversize_finalize < oversize_send);
    assert!(
        !oversize.contains("halt_cancelled_h3_upload("),
        "oversize terminal upload must rely on the writer's post-HEADERS halt"
    );
    assert!(oversize.contains("rejection.body.clone()"));
    assert!(oversize.contains("&rejection.headers"));

    let disconnected = terminal_dispatch
        .split("H3RequestBodyReadError::Read(error)")
        .nth(1)
        .expect("missing terminal upload branch: Read")
        .split("H3RequestBodyReadError::TimedOut")
        .next()
        .expect("bounded terminal upload branch");
    let disconnected_halt = disconnected
        .find("halt_cancelled_h3_upload(")
        .expect("disconnected terminal upload must STOP_SENDING");
    let disconnected_finalize = disconnected
        .find("finalize_h3_terminal_body_read_rejection(")
        .expect("disconnected terminal upload rejection finalizer");
    assert!(disconnected_halt < disconnected_finalize);
    assert!(
        !disconnected.contains("send_h3_plugin_reject_flavor_aware("),
        "a disconnected H3 stream must finalize cleanup without attempting a write"
    );

    let timed_out = terminal_dispatch
        .split("H3RequestBodyReadError::TimedOut")
        .nth(1)
        .expect("missing terminal upload branch: TimedOut")
        .split("H3RequestBodyReadError::DeadlineExceeded")
        .next()
        .expect("bounded terminal upload branch");
    assert_eq!(
        timed_out
            .matches("finalize_h3_terminal_body_read_rejection(")
            .count(),
        1
    );
    let timed_out_finalize = timed_out
        .find("finalize_h3_terminal_body_read_rejection(")
        .expect("timed-out terminal upload rejection finalizer");
    let timed_out_send = timed_out
        .find("send_h3_plugin_reject_flavor_aware_with_recv_halt(")
        .expect("timed-out terminal upload must use the recv-halt-aware sender");
    assert!(timed_out_finalize < timed_out_send);
    assert!(timed_out.contains("rejection.body.clone()"));
    assert!(timed_out.contains("&rejection.headers"));
    assert!(
        timed_out.contains("false,\n                    )\n                    .await?;"),
        "timed-out terminal upload must defer the halt until its bounded write settles"
    );
    assert!(
        !timed_out.contains("halt_cancelled_h3_upload("),
        "the timed-out branch must not halt before the response writer runs"
    );

    assert!(terminal_dispatch.contains("H3RequestBodyReadError::DeadlineExceeded"));
    assert!(terminal_dispatch.contains("finalize_h3_upload_deadline_rejection("));
}

#[test]
fn shared_reject_finalizer_records_finalized_synthetic_signal_for_2xx() {
    let proxy_src = include_str!("../../../src/proxy/mod.rs");
    let finalizer = proxy_src
        .split("pub(crate) async fn apply_reject_after_proxy_and_synthetic_body_hooks(")
        .nth(1)
        .expect("shared reject finalizer must remain present")
        .split("pub(crate) struct AfterProxyReject")
        .next()
        .expect("shared reject finalizer must remain bounded");
    assert!(
        finalizer.contains("FINALIZED_SYNTHETIC_RESPONSE_METADATA_KEY"),
        "H1/H2/H3 shared reject finalizer must record the body-independent finalized-synthetic signal"
    );
    assert!(
        finalizer.contains("(200..300).contains(status)"),
        "finalized-synthetic signal must gate on final HTTP 2xx so non-2xx rejects stay TTL-backed"
    );
    assert!(
        proxy_src.contains("pub(crate) const FINALIZED_SYNTHETIC_RESPONSE_METADATA_KEY"),
        "finalized-synthetic lifecycle key must remain a shared proxy constant"
    );

    let dedup_src = include_str!("../../../src/plugins/request_deduplication.rs");
    assert!(
        dedup_src.contains("FINALIZED_SYNTHETIC_RESPONSE_METADATA_KEY"),
        "request_deduplication must release ownership from the finalized-synthetic commit signal"
    );
}

#[test]
fn translated_h3_grpc_web_threads_preacquired_admission_into_grpc_dispatch() {
    let server = include_str!("../../../src/http3/server.rs");
    let bridge = server
        .find(
            "crate::http3::cross_protocol::run(crate::http3::cross_protocol::CrossProtocolRequest",
        )
        .expect("H3 cross-protocol bridge request must remain present");
    let bridge = &server[bridge..];
    assert!(
        bridge.contains("preacquired_backend_admission,"),
        "the H3 frontend must transfer its preacquired admission owner into the bridge"
    );

    let cross_protocol = include_str!("../../../src/http3/cross_protocol.rs");
    let run = cross_protocol
        .find("pub(crate) async fn run<S>(")
        .expect("cross-protocol run entry point must remain present");
    let grpc_arm = cross_protocol[run..]
        .find("HttpFlavor::Grpc => {")
        .map(|offset| run + offset)
        .expect("cross-protocol gRPC dispatch arm must remain present");
    let grpc_call = &cross_protocol[grpc_arm..];
    let call_end = grpc_call
        .find(".await\n        }")
        .expect("cross-protocol gRPC dispatch call must remain present");
    assert!(
        grpc_call[..call_end].contains("preacquired_backend_admission,"),
        "the gRPC arm must pass through the admission owner instead of dropping it"
    );

    let dispatch = cross_protocol
        .find("async fn dispatch_grpc<S>(")
        .expect("buffered cross-protocol gRPC dispatcher must remain present");
    let dispatch_body = &cross_protocol[dispatch..];
    let first_admission = dispatch_body
        .find("let mut backend_admission_permits =")
        .expect("initial gRPC backend admission must remain present");
    let initial = &dispatch_body[first_admission..];
    let consume = initial
        .find("preacquired_backend_admission.take_if_acquired()")
        .expect("initial gRPC dispatch must consume preacquired admission");
    let fallback = initial
        .find("run_cross_protocol_backend_admission_or_reject(")
        .expect("initial gRPC dispatch must retain an admission fallback");
    assert!(
        consume < fallback,
        "preacquired admission must be consumed before a fallback acquisition can run"
    );

    let retry = dispatch_body
        .find("Retrying cross-protocol H3→gRPC backend request")
        .expect("cross-protocol gRPC retry path must remain present");
    let retry_admission = &dispatch_body[retry..];
    let retry_admission_end = retry_admission
        .find("record_cross_protocol_connection_start")
        .expect("retry admission block must remain present");
    assert!(
        retry_admission[..retry_admission_end]
            .contains("run_cross_protocol_backend_admission_or_reject("),
        "a rotated retry target must acquire its own fresh admission"
    );
    assert!(
        !retry_admission[..retry_admission_end].contains("take_if_acquired"),
        "the initial target's preacquired permit must never be reused by a retry"
    );
}

#[test]
fn buffered_h3_deadline_replacements_keep_grpc_web_wire_flavor() {
    let server = include_str!("../../../src/http3/server.rs");
    let committed = server
        .find("// transform_response_body hooks — only for buffered responses.")
        .expect("buffered H3 response-hook pipeline must remain present");
    let committed = &server[committed..];
    let transform = committed
        .find("transform_buffered_response_body_with_deadline(")
        .expect("buffered H3 deadline transforms must remain present");
    let replacement = committed
        .find("run_deadline_bounded_response_committed_hooks(")
        .expect("buffered H3 deadline replacement and decoration must remain present");
    let response_write = committed
        .find("apply_response_headers(Response::builder().status(status), &response_headers)")
        .expect("buffered H3 direct response write must remain present");
    assert!(transform < replacement && replacement < response_write);
    assert!(
        committed[..response_write].contains("grpc_web_response_content_type,"),
        "the direct H3 buffered pipeline must retain the original gRPC-Web flavor before writing"
    );

    let shared = include_str!("../../../src/proxy/mod.rs");
    let committed_hooks = shared
        .split("pub(crate) async fn run_deadline_bounded_response_committed_hooks(")
        .nth(1)
        .expect("shared committed-hook deadline pipeline must remain present")
        .split("pub(crate) async fn")
        .next()
        .expect("shared committed-hook deadline pipeline must remain bounded");
    assert!(committed_hooks.contains("replace_buffered_grpc_response_with_deadline("));

    let cross_protocol = include_str!("../../../src/http3/cross_protocol.rs");
    let transform = cross_protocol
        .find("crate::proxy::transform_buffered_response_body_with_deadline(")
        .expect("cross-protocol buffered response transform must remain present");
    let transform = &cross_protocol[transform..];
    let committed = transform
        .find("run_deadline_bounded_response_committed_hooks(")
        .expect("cross-protocol committed-hook pipeline must remain present");
    assert!(transform[..committed].contains("grpc_web_response_content_type,"));

    let shared_transform = shared
        .split("pub(crate) async fn transform_buffered_response_body_with_deadline(")
        .nth(1)
        .expect("shared buffered transform deadline pipeline must remain present")
        .split("pub(crate) async fn")
        .next()
        .expect("shared buffered transform deadline pipeline must remain bounded");
    assert!(shared_transform.contains("replace_buffered_grpc_response_with_deadline("));
}

// Buffered response-body policy enforcement across encoded, partial, and
// non-parseable representations is covered behaviorally — by driving the real
// shared transform phase with a real `response_transformer` — in
// `gateway_core::response_representation_tests`. Source-text assertions were
// removed: they passed while the runtime still forwarded protected bytes.

#[test]
fn h3_grpc_web_upload_deadlines_use_request_aware_writer() {
    let source = include_str!("../../../src/http3/cross_protocol.rs");
    let dispatch = source
        .find("async fn dispatch_grpc<S>(")
        .expect("buffered H3-to-gRPC dispatcher must remain present");
    let body = &source[dispatch..];
    let body_start = body
        .find("let body = if let Some(buffered)")
        .expect("H3 gRPC upload buffering must remain present");
    let body = &body[body_start..];
    let body_end = body
        .find("// Build the backend-facing header map")
        .expect("H3 gRPC upload buffering must remain bounded");
    let body = &body[..body_end];
    let timed_out = body
        .find("H3RequestBodyReadError::TimedOut")
        .expect("missing timed-out upload branch");
    let timed_out = &body[timed_out..];
    let timed_out_end = timed_out[1..]
        .find("H3RequestBodyReadError::")
        .map_or(timed_out.len(), |offset| offset + 1);
    let timed_out = &timed_out[..timed_out_end];
    assert!(timed_out.contains("write_grpc_error_for_request_with_recv_halt("));
    assert!(timed_out.contains("ctx,"));
    assert!(
        timed_out.contains("false,\n                )"),
        "timed-out bridge upload must defer STOP_SENDING until after the bounded write"
    );
    assert!(timed_out.contains("await_post_deadline_terminal_response_write("));
    assert!(
        timed_out.contains("halt_request_body(stream)"),
        "the full-stream bridge must halt after the bounded terminal write settles"
    );
    let deadline = body
        .find("H3RequestBodyReadError::DeadlineExceeded")
        .expect("missing deadline upload branch");
    let deadline = &body[deadline..];
    let deadline_end = deadline[1..]
        .find("H3RequestBodyReadError::")
        .map_or(deadline.len(), |offset| offset + 1);
    let deadline = &deadline[..deadline_end];
    assert!(deadline.contains("write_final_body_reject("));
    assert!(deadline.contains("grpc_deadline_exceeded_plugin_result()"));
    assert!(deadline.contains("log_rejected_request("));

    let writer = source
        .find("async fn write_grpc_error_for_request_with_recv_halt<S>(")
        .expect("request-aware H3 gRPC error writer must remain present");
    let writer = &source[writer..];
    let writer_end = writer
        .find("async fn write_grpc_error_send<S>(")
        .expect("request-aware H3 gRPC error writer must remain bounded");
    let writer = &writer[..writer_end];
    assert!(writer.contains("translated_error_response("));
    assert!(writer.contains("write_reject_with_headers_and_recv_halt("));
    assert!(writer.contains("write_grpc_error_send_with_policy("));
}

/// Assert that a client-owned termination arm of the native-H3 gRPC relay
/// records ONLY health-neutral error classes.
///
/// The contract is "every classification this arm makes is neutral", not "this
/// arm contains exactly N neutral literals": a stale occurrence count silently
/// passes when a new sub-path is added without a class, and has to be re-tuned
/// whenever a neutral path is added. So this compares the number of
/// `body_error_class` assignments against the number that are
/// `ClientDisconnect` — adding a neutral path is free, adding a non-neutral one
/// fails, and dropping the classification entirely fails the floor below.
fn assert_h3_arm_health_neutral(arm: &str, min_paths: usize, what: &str) {
    let assignments = arm.matches("body_error_class =").count();
    assert!(
        assignments >= min_paths,
        "{what}: every terminating path must classify the outcome \
         (found {assignments} assignments, expected at least {min_paths})"
    );
    let neutral_class = "Some(crate::retry::ErrorClass::ClientDisconnect)";
    let neutral = arm.matches(neutral_class).count();
    assert_eq!(
        neutral, assignments,
        "{what}: a client-owned termination must never be charged to backend \
         health — every classification in this arm must be ClientDisconnect"
    );
    assert!(
        !arm.contains("ErrorClass::ReadWriteTimeout"),
        "{what}: a client-owned termination must not be recorded as a backend \
         read/write timeout"
    );
}

/// Slice one arm out of the native-H3 gRPC relay's response `select!`.
///
/// Bounded by the NEXT arm rather than by an arbitrary later token, so the
/// region stays exactly one arm as the relay grows.
fn native_h3_grpc_select_arm(start: &str, next_arm: &str) -> &'static str {
    let source = include_str!("../../../src/http3/server.rs");
    let Some(begin) = source.find(start) else {
        panic!("native H3 gRPC relay arm must remain present: {start}");
    };
    let remaining = &source[begin..];
    let Some(end) = remaining.find(next_arm) else {
        panic!("native H3 gRPC relay arm must remain bounded by: {next_arm}");
    };
    &remaining[..end]
}

#[test]
fn native_h3_client_deadlines_remain_health_neutral() {
    let source = include_str!("../../../src/http3/server.rs");

    // The absolute client-deadline arm: clean terminal trailer, terminal-trailer
    // send failure, and the post-DATA reset. Bounded by the arm that must follow
    // it — the terminating upload fault, which is asserted below and whose
    // placement (deadline, then fault, then backend DATA) is itself the contract
    // that a fault cannot lose a race to a simultaneously-ready response frame.
    let body_deadline = native_h3_grpc_select_arm(
        "_ = &mut grpc_deadline_sleep, if grpc_deadline_active && !stream_done =>",
        "fault = &mut upload_fault_wait =>",
    );
    assert_h3_arm_health_neutral(body_deadline, 3, "native H3 gRPC body-deadline arm");

    // The terminating request-upload fault arm is client-caused too (client
    // abort, malformed trailing metadata, oversized upload), so it obeys the
    // same rule. Bounded by the backend-DATA arm that follows it.
    let fault_arm = native_h3_grpc_select_arm(
        "fault = &mut upload_fault_wait =>",
        "chunk_result = backend_recv.recv_data(), if !stream_done =>",
    );
    assert_h3_arm_health_neutral(fault_arm, 1, "native H3 gRPC upload-fault arm");
    assert!(
        !fault_arm.contains("grpc_trailer_status ="),
        "a gateway-authored fault status must not be latched as the backend's \
         terminal grpc-status (it would train the adaptive-concurrency limiter)"
    );

    // Trailer-wait timeout is expiry-first `await_deadline_first` → `Err(())`
    // → `expired_authorization()`. Client-owned gRPC deadline completion is
    // the `None if trailer_timeout_is_deadline` arm; the following `None =>`
    // arm is a backend read-timeout and must stay out of this health-neutral
    // region.
    let trailer_deadline = source
        .find("None if trailer_timeout_is_deadline =>")
        .expect("native H3 trailer deadline branch must remain present");
    let trailer_deadline = &source[trailer_deadline..];
    let trailer_end = trailer_deadline
        .find("None =>")
        .expect("native H3 trailer deadline branch must remain bounded");
    let trailer_deadline = &trailer_deadline[..trailer_end];
    assert_h3_arm_health_neutral(trailer_deadline, 3, "native H3 gRPC trailer-deadline arm");
}

#[test]
fn h3_cross_protocol_streaming_grpc_consumes_deadline_and_read_bounds() {
    let source = include_str!("../../../src/http3/cross_protocol.rs");
    let handler = source
        .split("async fn handle_h3_grpc_streaming_response")
        .nth(1)
        .expect("H3 cross-protocol streaming gRPC response handler")
        .split("/// Resolve the gRPC dispatch transport")
        .next()
        .expect("bounded streaming handler body");
    let strip = handler
        .find("strip_content_length_for_streaming_grpc_deadline(")
        .expect("deadline-capable relay must strip Content-Length");
    let header_write = handler
        .find("send_response_headers_with_framing(")
        .expect("streaming response header write");
    assert!(
        strip < header_write,
        "Content-Length must be removed before H3 response headers commit"
    );
    assert!(handler.contains("streaming.response_read_timeout_ms,"));
    assert!(handler.contains("streaming.grpc_deadline_at,"));

    let relay = source
        .split("async fn stream_hyper_incoming")
        .nth(1)
        .expect("H3 cross-protocol hyper body relay")
        .split("fn should_finish_h3_stream_without_trailers")
        .next()
        .expect("bounded relay body");
    assert!(relay.contains("_ = &mut grpc_deadline"));
    assert!(relay.contains("GATEWAY_DEADLINE_EXCEEDED_STATUS_HEADER"));
    assert_eq!(
        relay
            .matches("grpc_deadline_can_send_terminal_status(")
            .count(),
        3,
        "write-bound client expiry plus the authorization and client select arms must all use \
         client-visible DATA"
    );
    assert!(relay.contains("abort_response_stream(stream)"));
    assert!(relay.contains("_ = &mut read_deadline"));
    assert!(relay.contains("await_response_write_before_deadline("));
    assert!(relay.contains("await_downstream_write!(stream.send_data"));
}

#[test]
fn h3_cross_protocol_buffered_grpc_writes_and_fin_are_deadline_bounded() {
    let source = include_str!("../../../src/http3/cross_protocol.rs");
    let buffered = source
        .split("Ok(GrpcResponseKind::Buffered(resp)) => {")
        .nth(1)
        .expect("buffered cross-protocol gRPC response arm")
        .split("Ok(GrpcResponseKind::Streaming(streaming)) => {")
        .next()
        .expect("bounded buffered gRPC response arm");
    assert!(buffered.contains("await_response_write_before_deadline("));
    assert!(buffered.contains("await_terminal_response_write_before_deadline("));
    assert!(buffered.contains("stream.send_data(response_body)"));
    assert!(buffered.contains("stream.send_trailers(trailer_map)"));
    assert!(
        buffered.matches("stream.finish()").count() >= 2,
        "both trailer and no-trailer buffered responses must send a deadline-bounded FIN"
    );
}

#[test]
fn h3_native_buffered_response_writes_are_deadline_bounded() {
    let source = include_str!("../../../src/http3/server.rs");
    let writer = source
        .split("// Build and send buffered response")
        .nth(1)
        .expect("native H3 buffered response writer")
        .split("pub(crate) fn h3_plugin_protocol_for_request")
        .next()
        .expect("bounded native H3 buffered response writer");
    assert!(writer.contains("macro_rules! await_buffered_h3_write"));
    assert!(writer.contains("await_buffered_h3_write!(stream.send_response(resp))"));
    assert!(writer.contains("await_buffered_h3_write!(stream.send_data"));
    assert!(writer.contains("await_response_write_before_deadline("));
    assert!(writer.contains("await_terminal_response_write_before_deadline("));
    assert!(writer.contains("await_buffered_h3_write!(stream.finish())"));
}

#[test]
fn h3_native_buffered_deadline_outcome_is_recorded_before_transaction_logging() {
    let source = include_str!("../../../src/http3/server.rs");
    let writer = source
        .split("// Build and send buffered response")
        .nth(1)
        .expect("native H3 buffered response writer")
        .split("pub(crate) fn h3_plugin_protocol_for_request")
        .next()
        .expect("bounded native H3 buffered response writer");
    let deadline_metadata = writer
        .rfind("insert_grpc_error_metadata(")
        .expect("write deadline must update transaction metadata");
    let summary = writer
        .find("let summary = TransactionSummary {")
        .expect("buffered transaction summary must remain present");
    let log = writer
        .find("log_with_mirror(&plugins, &summary, &ctx)")
        .expect("buffered transaction log call must remain present");
    assert!(deadline_metadata < summary && summary < log);
    assert!(writer[..summary].contains("body_completed = false"));
    assert!(writer[..summary].contains("bytes_received = response_body_bytes"));
    assert!(writer[summary..log].contains("body_completed,"));
    assert!(writer[summary..log].contains("bytes_received,"));
}

#[test]
fn h3_buffered_terminal_write_bias_uses_typed_gateway_provenance() {
    let context = include_str!("../../../src/plugins/mod.rs");
    assert!(context.contains("gateway_deadline_response_selected: bool"));
    assert!(context.contains("fn mark_gateway_deadline_response_selected"));

    let proxy = include_str!("../../../src/proxy/mod.rs");
    let replacement = proxy
        .split("pub(crate) fn replace_buffered_grpc_response_with_deadline(")
        .nth(1)
        .expect("shared buffered deadline replacement")
        .split("pub(crate) async fn transform_buffered_response_body_with_deadline")
        .next()
        .expect("bounded shared buffered deadline replacement");
    assert!(replacement.contains("ctx.mark_gateway_deadline_response_selected()"));

    let cross_protocol = include_str!("../../../src/http3/cross_protocol.rs");
    let buffered = cross_protocol
        .split("Ok(GrpcResponseKind::Buffered(resp)) => {")
        .nth(1)
        .expect("buffered cross-protocol gRPC response arm")
        .split("Ok(GrpcResponseKind::Streaming(streaming)) => {")
        .next()
        .expect("bounded buffered gRPC response arm");
    let writer = buffered
        .split("let grpc_deadline_at = ctx.grpc_deadline_at();")
        .nth(1)
        .expect("buffered cross-protocol writer");
    let header_write = writer
        .find("let header_write =")
        .expect("buffered cross-protocol header write");
    assert!(writer[..header_write].contains("ctx.gateway_deadline_response_selected()"));
    assert!(!writer[..header_write].contains("metadata.get(\"grpc_status\")"));

    let native = include_str!("../../../src/http3/server.rs");
    let native_writer = native
        .split("// Build and send buffered response")
        .nth(1)
        .expect("native H3 buffered response writer")
        .split("macro_rules! await_buffered_h3_write")
        .next()
        .expect("bounded native H3 provenance setup");
    assert!(native_writer.contains("ctx.gateway_deadline_response_selected()"));
    assert!(!native_writer.contains("metadata.get(\"grpc_status\")"));
}

#[test]
fn h3_request_plugin_deadlines_mark_and_bound_terminal_rejections() {
    let plugins = include_str!("../../../src/plugins/mod.rs");
    assert!(plugins.contains("enum RequestPluginDeadlineResult"));
    assert!(plugins.contains("Self::DeadlineExceeded =>"));
    assert!(plugins.contains("ctx.mark_gateway_deadline_response_selected()"));

    let proxy = include_str!("../../../src/proxy/mod.rs");
    let authentication = proxy
        .split("pub async fn run_authentication_phase(")
        .nth(1)
        .expect("shared authentication phase must remain present")
        .split("pub async fn handle_proxy_request(")
        .next()
        .expect("shared authentication phase must remain bounded");
    assert!(authentication.contains("await_request_plugin_deadline_with_provenance("));
    assert!(authentication.contains("ctx.mark_gateway_deadline_response_selected()"));

    let server = include_str!("../../../src/http3/server.rs");
    for (start_marker, end_marker, phase) in [
        (
            "// Execute on_request_received hooks",
            "// Materialize query params before authentication.",
            "on_request_received",
        ),
        (
            "// Authorization phase (pre-computed authorize plugin list",
            "let maybe_needs_request_buffering =",
            "authorize",
        ),
        (
            "async fn run_h3_backend_path_plugins_or_send_reject(",
            "async fn run_h3_backend_admission_or_send_reject(",
            "on_backend_path_resolved",
        ),
    ] {
        let start = server
            .find(start_marker)
            .unwrap_or_else(|| panic!("native H3 {phase} phase must remain present"));
        let end = server[start..]
            .find(end_marker)
            .map(|offset| start + offset)
            .unwrap_or_else(|| panic!("native H3 {phase} phase must remain bounded"));
        let phase_source = &server[start..end];
        assert!(
            phase_source.contains("await_request_plugin_deadline_with_provenance("),
            "native H3 {phase} must retain provenance-aware deadline awaits"
        );
        assert!(
            phase_source.contains(".into_plugin_result("),
            "native H3 {phase} must convert deadline outcomes with the live context"
        );
    }
    assert_eq!(
        server
            .matches("await_request_plugin_deadline_with_provenance(")
            .count(),
        3,
        "only native H3 request-plugin phases retain direct deadline awaits in server.rs"
    );

    let before_proxy_helper = proxy
        .split("pub(crate) async fn run_before_proxy_hooks_for_backend_path_policy(")
        .nth(1)
        .expect("shared before_proxy backend-path policy helper must remain present")
        .split("const MAX_SET_COOKIE_NAME_VALUE_BYTES")
        .next()
        .expect("shared before_proxy backend-path policy helper must remain bounded");
    assert!(before_proxy_helper.contains("await_request_plugin_deadline_with_provenance("));
    assert!(before_proxy_helper.contains("plugin.before_proxy(ctx, headers)"));
    assert!(before_proxy_helper.contains(".into_plugin_result(ctx)"));

    let initial_before_proxy_start = server
        .find("// before_proxy hooks — only clone headers if at least one plugin modifies them.")
        .expect("native H3 initial before_proxy block must remain present");
    let initial_before_proxy_end = server[initial_before_proxy_start..]
        .find("// Keep H3 body-plugin applicability aligned with the H1/H2 path:")
        .map(|offset| initial_before_proxy_start + offset)
        .expect("native H3 initial before_proxy block must remain bounded");
    let initial_before_proxy = &server[initial_before_proxy_start..initial_before_proxy_end];

    let initial_clone_before_proxy = initial_before_proxy
        .split("let mut cloned = ctx.headers.clone();")
        .nth(1)
        .expect("native H3 header-clone before_proxy path must remain present")
        .split("owned_proxy_headers = Some(cloned);")
        .next()
        .expect("native H3 header-clone before_proxy path must remain bounded");
    assert!(
        initial_clone_before_proxy.contains("run_before_proxy_hooks_for_backend_path_policy(")
            && initial_clone_before_proxy.contains("BackendPathBeforeProxyPass::Initial"),
        "native H3 header-clone path must delegate before_proxy to the shared helper"
    );

    let initial_take_before_proxy = initial_before_proxy
        .split("let mut tmp_headers = std::mem::take(&mut ctx.headers);")
        .nth(1)
        .expect("native H3 zero-clone before_proxy path must remain present")
        .split("ctx.headers = tmp_headers;")
        .next()
        .expect("native H3 zero-clone before_proxy path must remain bounded");
    assert!(
        initial_take_before_proxy.contains("run_before_proxy_hooks_for_backend_path_policy(")
            && initial_take_before_proxy.contains("BackendPathBeforeProxyPass::Initial"),
        "native H3 zero-clone path must delegate before_proxy to the shared helper"
    );

    let routing_deferred_before_proxy = server
        .split("if has_deferred_routing_header_hooks {")
        .nth(1)
        .expect("native H3 routing-header deferred block must remain present")
        .split("if backend_path_is_policy_bound {")
        .next()
        .expect("native H3 routing-header deferred block must remain bounded");
    assert!(
        routing_deferred_before_proxy.contains("run_before_proxy_hooks_for_backend_path_policy(")
            && routing_deferred_before_proxy
                .contains("BackendPathBeforeProxyPass::RoutingHeaderDeferred"),
        "native H3 routing-header deferred pass must delegate before_proxy to the shared helper"
    );

    let remaining_deferred_before_proxy = server
        .split("if has_deferred_routing_header_hooks {")
        .nth(1)
        .expect("native H3 remaining deferred block must remain present")
        .split("if backend_path_is_policy_bound {")
        .nth(1)
        .expect("native H3 remaining deferred pass must remain present")
        .split("match deferred_result {")
        .next()
        .expect("native H3 remaining deferred pass must remain bounded");
    assert!(
        remaining_deferred_before_proxy.contains("run_before_proxy_hooks_for_backend_path_policy(")
            && remaining_deferred_before_proxy
                .contains("BackendPathBeforeProxyPass::RemainingDeferred"),
        "native H3 remaining deferred pass must delegate before_proxy to the shared helper"
    );
    assert_eq!(
        server
            .matches("run_before_proxy_hooks_for_backend_path_policy(")
            .count(),
        4,
        "native H3 must delegate both initial header paths and each deferred pass"
    );

    // Bound the region at the CLOSING BRACE of the recv-halt wrapper rather than
    // at whatever item happens to follow it. The counted grace-expiry arms below
    // are a property of these two functions alone, so an unrelated writer added
    // after them (the aggregate MCP SSE pump, for one) must not be swept in.
    let writer_start = server
        .find("async fn send_h3_plugin_reject_flavor_aware(")
        .expect("native H3 plugin rejection writer must remain present");
    let recv_halt_start = server[writer_start..]
        .find("async fn send_h3_plugin_reject_flavor_aware_with_recv_halt(")
        .map(|offset| writer_start + offset)
        .expect("native H3 recv-halt rejection writer must remain present");
    let writer_end = server[recv_halt_start..]
        .find("\n}\n")
        .map(|offset| recv_halt_start + offset)
        .expect("native H3 plugin rejection deadline wrapper must remain bounded");
    let writer = &server[writer_start..writer_end];
    assert!(writer.contains("ctx.gateway_deadline_response_selected()"));
    assert!(writer.contains("replace_buffered_h3_response_with_grpc_deadline("));
    // Already-selected gateway deadline rejections use the shared post-deadline
    // grace (not the expired absolute deadline), then halt the full request
    // stream through the vendored transport even after a mid-recv cancel.
    assert!(writer.contains("await_post_deadline_terminal_response_write("));
    assert!(!writer.contains("await_terminal_response_write_before_deadline("));
    assert_eq!(
        writer
            .matches("H3ResponseWriteError::DeadlineExceeded")
            .count(),
        2,
        "terminal-deadline and halt_recv=false cancel branches must both handle grace expiry"
    );
    assert_eq!(
        writer.matches("abort_response_stream(stream)").count(),
        2,
        "each grace-expiry arm must abort the response send half"
    );
    assert_eq!(
        writer.matches("halt_request_body(stream)").count(),
        2,
        "each bounded full-stream branch must halt the request direction after the write settles"
    );

    // The aggregate MCP SSE lease is adopted from the SAME rejection funnel, so
    // it must be taken (and therefore released) exactly once, and adopted only
    // while the gateway-authored event stream is still the final representation.
    assert_eq!(
        writer.matches("ctx.mcp_aggregate_sse.take()").count(),
        1,
        "the SSE listener lease must be taken exactly once on the H3 reject funnel"
    );
    for conjunct in [
        "matches!(flavor, HttpFlavor::Plain)",
        "grpc_web_response_content_type.is_none()",
        "!terminal_gateway_deadline",
        "http_status == StatusCode::OK",
        "body.is_empty()",
        "crate::proxy::response_headers_select_event_stream(headers)",
    ] {
        assert!(
            writer.contains(conjunct),
            "H3 SSE adoption must keep the `{conjunct}` representation guard"
        );
    }
}

/// The native H3 aggregate MCP SSE writer is a long-lived pump rather than a
/// buffered representation, so its framing decision, its composed
/// listener/authorization bound, its fail-closed terminals, and its
/// listener-slot release order are the properties worth freezing.
#[test]
fn h3_aggregate_sse_writer_streams_under_a_hard_listener_bound() {
    let server = include_str!("../../../src/http3/server.rs");
    let start = server
        .find("async fn send_h3_aggregate_sse_response(")
        .expect("native H3 aggregate SSE writer must remain present");
    let end = server[start..]
        .find("\n}\n")
        .map(|offset| start + offset)
        .expect("native H3 aggregate SSE writer must remain bounded");
    let sse_writer = &server[start..end];

    // Streaming framing: no `Content-Length` may be published for bytes that
    // have not been written yet.
    assert!(
        sse_writer.contains("sanitize_client_response_headers_for_wire("),
        "the H3 SSE response must pass the final wire header boundary"
    );
    assert!(
        sse_writer.contains("ClientResponseFraming::Streaming"),
        "the H3 SSE response must be framed as a streaming body"
    );
    assert!(
        !sse_writer.contains("ClientResponseFraming::ExactBody"),
        "an SSE stream has no exact body length to publish"
    );

    // The listener lifetime is composed with the captured authorization plan;
    // the plan is taken once from the request and never recomputed from activity.
    assert!(
        sse_writer.contains("effective_request_auth_deadline("),
        "the H3 SSE writer must capture the accepted request's authorization plan"
    );
    assert!(
        sse_writer.contains("compose_aggregate_sse_bound(body.deadline(), auth_plan)"),
        "the H3 SSE writer must compose the listener lifetime with that captured plan"
    );
    assert!(
        sse_writer.contains("await_authorized_headers_write("),
        "the H3 SSE HEADERS write must race the composed bound"
    );
    assert!(
        sse_writer.contains("await_response_write_before_deadline("),
        "every flow-control-blocked DATA/FIN write must race the composed bound"
    );
    assert!(
        sse_writer.contains("tokio::time::timeout_at(deadline, pump)"),
        "waiting for the next event must also sit inside the composed bound"
    );

    // Authorization before commitment uses the fixed redacted terminal under
    // grace, otherwise resets. After commitment it resets rather than finishing.
    assert!(
        sse_writer.contains("authorization_expired_pre_commitment_response("),
        "pre-commit authorization expiry must use the fixed redacted terminal"
    );
    assert!(
        sse_writer.contains("await_post_deadline_terminal_response_write("),
        "the pre-commit authorization terminal must be written under the bounded grace"
    );
    assert!(
        sse_writer.contains("record_authorization_termination_once("),
        "post-commit authorization expiry must record through the shared once-only latch"
    );
    assert!(
        sse_writer.contains("StreamAuthProtocolFamily::Http"),
        "aggregate SSE is the HTTP family, not an unbounded label"
    );
    assert!(
        sse_writer.contains("latch_authorization_termination("),
        "the bounded class must be latched into request/transaction metadata"
    );
    let auth_abort = sse_writer
        .find("if let Some(termination) = aggregate_sse_bound.expired_authorization()")
        .expect("post-commit authorization attribution");
    let auth_abort_reset = sse_writer[auth_abort..]
        .find("abort_response_stream(stream)")
        .map(|offset| auth_abort + offset)
        .expect("post-commit authorization expiry must reset");
    let listener_grace = sse_writer[auth_abort..]
        .find("await_post_deadline_terminal_response_write(")
        .map(|offset| auth_abort + offset)
        .expect("listener-lifetime expiry must finish under the bounded terminal grace");
    assert!(
        auth_abort_reset < listener_grace,
        "authorization after commitment must reset before the listener-lifetime finish arm"
    );
    let listener_else = sse_writer[auth_abort..]
        .split("} else {")
        .nth(1)
        .expect("listener-lifetime else arm")
        .split("    } else {")
        .next()
        .expect("listener-lifetime else arm bounded");
    assert!(
        listener_else.contains("await_post_deadline_terminal_response_write("),
        "listener-lifetime expiry must bound the clean-FIN attempt"
    );
    assert!(
        listener_else.contains("abort_response_stream(stream)"),
        "listener-lifetime FIN blocked past grace must reset the response stream"
    );
    assert!(
        !listener_else.contains("record_authorization_termination_once("),
        "listener-lifetime expiry must not increment authorization accounting"
    );
    assert!(
        !listener_else.contains("let _ = stream.finish().await"),
        "listener-lifetime expiry must not await finish unbounded"
    );
    assert_eq!(
        sse_writer
            .matches("await_post_deadline_terminal_response_write(")
            .count(),
        2,
        "pre-commit authorization terminal and listener-lifetime FIN must both use the bounded grace"
    );

    // Dropping the body is what returns the session's single-listener slot, so
    // every exit must release it, and the ordinary path must release it BEFORE
    // the QUIC stream teardown a reconnecting client races.
    assert!(
        sse_writer.matches("drop(body);").count() >= 4,
        "every H3 SSE exit must release the listener slot"
    );
    let release = sse_writer
        .rfind("drop(body);")
        .expect("the pump exit must release the listener slot");
    let finish = sse_writer
        .find("stream.finish()")
        .expect("the H3 SSE writer must finish the response stream");
    assert!(
        release < finish,
        "the listener slot must be released before the QUIC stream teardown"
    );
    assert!(
        sse_writer.contains("halt_request_body(stream)"),
        "every H3 SSE exit must preserve receive-half teardown"
    );

    // Nothing here may collect the stream: a buffered SSE body is unbounded.
    for buffering in ["collect()", "to_bytes(", "Vec::from", "BytesMut"] {
        assert!(
            !sse_writer.contains(buffering),
            "the H3 SSE pump must never buffer the stream (`{buffering}`)"
        );
    }
}

#[test]
fn h1_h2_request_plugin_awaits_and_body_hook_clones_preserve_deadline_provenance() {
    let proxy = include_str!("../../../src/proxy/mod.rs");

    assert!(
        !proxy.contains("await_request_plugin_deadline("),
        "proxy request hooks must retain typed timeout provenance until conversion with the live context"
    );
    assert!(
        proxy
            .matches("body_hook_ctx.gateway_deadline_response_selected()")
            .count()
            >= 4,
        "every final-body compatibility-clone merge must propagate terminal deadline ownership"
    );
}

#[test]
fn buffered_http3_backend_upload_honors_client_grpc_deadline() {
    let proxy = include_str!("../../../src/proxy/mod.rs");
    let http3 = proxy
        .split("async fn proxy_to_backend_http3(")
        .nth(1)
        .expect("HTTP/3 backend dispatcher must remain present")
        .split("\nasync fn ")
        .next()
        .expect("HTTP/3 backend dispatcher must remain bounded");
    let buffering = http3
        .split("let request_body = match client_request_body")
        .nth(1)
        .expect("HTTP/3 backend request buffering must remain present")
        .split("// Prepared buffers have already contributed")
        .next()
        .expect("HTTP/3 backend request buffering must remain bounded");
    assert_eq!(
        buffering
            .matches("collect_request_body_under_authorization(")
            .count(),
        2,
        "limited and unlimited HTTP/3 upload buffering must share the deadline-aware collector"
    );
    assert_eq!(
        buffering
            .matches("RequestBodyWaitError::DeadlineExceeded")
            .count(),
        2
    );
    assert_eq!(
        buffering
            .matches("AuthorizedUploadWaitError::AuthorizationExpired(")
            .count(),
        2,
        "both buffering branches must also carry the admitted stream's authorization bound"
    );
    assert_eq!(
        buffering
            .matches("client_grpc_deadline_exceeded_response_for_optional_request(")
            .count(),
        2,
        "both buffering branches must preserve native gRPC versus gRPC-Web wire flavor"
    );
}

#[test]
fn native_h3_response_header_deadline_is_not_a_client_disconnect() {
    let source = include_str!("../../../src/http3/server.rs");
    let branch = source
        .split("if let Err(write_error) = response_header_write {")
        .nth(1)
        .expect("native H3 response-header failure branch")
        .split("// Stream the response body with the shared QUIC coalescer")
        .next()
        .expect("bounded response-header failure branch");
    assert!(branch.contains("H3ResponseWriteError::DeadlineExceeded =>"));
    assert!(branch.contains("(true, false)"));
    assert!(branch.contains("H3ResponseWriteError::Write(_) => (false, true)"));
    assert!(branch.contains("response_header_client_disconnected,"));
    assert!(branch.contains("response_header_client_disconnected\n                .then_some"));
}

#[test]
fn h3_send_only_terminal_rejection_write_is_deadline_bounded() {
    let source = include_str!("../../../src/http3/cross_protocol.rs");
    let writer = source
        .split("async fn write_final_grpc_body_reject_send<S>(")
        .nth(1)
        .expect("send-only terminal gRPC rejection writer")
        .split("fn reject_body_as_h3_grpc_message(")
        .next()
        .expect("bounded send-only terminal gRPC rejection writer");
    assert!(writer.contains("ctx.gateway_deadline_response_selected()"));
    assert!(writer.contains("await_post_deadline_terminal_response_write("));
    assert!(!writer.contains("await_terminal_response_write_before_deadline("));
    assert!(writer.contains("abort_response_stream(stream)"));
    assert!(writer.contains("terminal_deadline_write_aborted_outcome("));
    assert!(
        writer.contains("H3ResponseWriteError::Write(_)"),
        "client-reset post-deadline writes must map to an accounting outcome"
    );
    assert!(
        writer.contains("bytes_sent,\n                true,"),
        "client-reset post-deadline writes must report client_disconnected"
    );
    assert!(writer.contains("bytes_sent,\n                false,"));
    let grace_arm = writer
        .split("H3ResponseWriteError::DeadlineExceeded")
        .nth(1)
        .expect("send-only grace expiry arm");
    assert!(grace_arm.contains("abort_response_stream(stream)"));
    assert!(
        !grace_arm.contains("halt_request_body(stream)"),
        "grace expiry must abort the send half without STOP_SENDING"
    );

    let outcome = source
        .split("fn terminal_deadline_write_aborted_outcome(")
        .nth(1)
        .expect("terminal deadline write outcome")
        .split("async fn write_final_body_reject<S>(")
        .next()
        .expect("bounded terminal deadline write outcome");
    assert!(
        outcome.contains("client_disconnected.then_some(ErrorClass::ClientDisconnect)"),
        "deadline expiry must not be reported as a disconnect-oriented body error"
    );
}

#[test]
fn h3_native_grpc_write_deadlines_remain_client_owned_and_observable() {
    let source = include_str!("../../../src/http3/server.rs");
    let relay = source
        .split("async fn dispatch_grpc_native_h3(")
        .nth(1)
        .expect("native H3 gRPC relay")
        .split("async fn log_h3_grpc_transaction(")
        .next()
        .expect("bounded native H3 gRPC relay");
    assert!(relay.contains("await_downstream_grpc_write!(send_half.send_data"));
    assert!(relay.contains("let mut client_deadline_expired = false"));
    assert!(relay.contains("H3GrpcResponseFinish::DeadlineExceeded"));
    assert!(relay.contains("if client_deadline_expired"));
    assert!(relay.contains("insert_grpc_error_metadata("));
}

#[tokio::test]
async fn stalled_h3_flow_control_write_is_cancelled_by_rpc_deadline() {
    let deadline = tokio::time::Instant::now()
        .checked_add(std::time::Duration::from_millis(10))
        .expect("ten milliseconds after now is representable");
    assert!(
        ferrum_edge::_test_support::stalled_h3_response_write_expires_for_test(deadline).await,
        "a permanently pending QUIC write must not outlive the absolute RPC deadline"
    );
}

#[tokio::test]
async fn ready_h3_terminal_status_can_finish_after_deadline_selection() {
    let deadline = tokio::time::Instant::now()
        .checked_sub(std::time::Duration::from_millis(1))
        .expect("one millisecond before now is representable");
    assert!(
        ferrum_edge::_test_support::ready_h3_terminal_write_wins_expired_deadline_for_test(
            deadline
        )
        .await,
        "an immediately-ready status-4 trailer must retain the clean zero-DATA completion path"
    );
}

#[tokio::test]
async fn ready_h3_post_deadline_terminal_write_completes_within_grace() {
    assert!(
        ferrum_edge::_test_support::ready_h3_post_deadline_terminal_write_completes_for_test()
            .await,
        "an immediately-ready post-deadline rejection write, including the \
         post-authorization 401, must complete within the grace"
    );
}

#[tokio::test(start_paused = true)]
async fn stalled_h3_post_deadline_terminal_write_expires_grace() {
    let task = ferrum_edge::_test_support::spawn_stalled_h3_post_deadline_terminal_write_for_test();
    tokio::task::yield_now().await;
    tokio::time::advance(
        ferrum_edge::_test_support::h3_post_deadline_terminal_write_grace_for_test(),
    )
    .await;
    tokio::task::yield_now().await;
    assert!(
        task.await.expect("join"),
        "a flow-control-blocked post-deadline rejection write, including the \
         post-authorization 401, must not outlive the grace"
    );
}

#[test]
fn h3_post_deadline_terminal_write_grace_is_fixed_one_second() {
    assert_eq!(
        ferrum_edge::_test_support::h3_post_deadline_terminal_write_grace_for_test(),
        std::time::Duration::from_secs(1)
    );
    let util = include_str!("../../../src/http3/stream_util.rs");
    assert!(util.contains("H3_POST_DEADLINE_TERMINAL_WRITE_GRACE"));
    assert!(util.contains("await_post_deadline_terminal_response_write"));
}

#[test]
fn cross_protocol_plain_authorization_expired_terminal_uses_post_deadline_grace() {
    let cross = include_str!("../../../src/http3/cross_protocol.rs");
    let dispatch = cross
        .split("async fn dispatch_plain<S>(")
        .nth(1)
        .expect("cross-protocol plain dispatcher")
        .split("async fn dispatch_grpc<S>(")
        .next()
        .expect("bounded cross-protocol plain dispatcher");
    assert_eq!(
        dispatch
            .matches("write_plain_authorization_expired_terminal(")
            .count(),
        10,
        "mesh force-buffer upload, buffered client acquisition, buffered header-wait, \
         mesh retry-delay, two reqwest retry-delays, streaming client acquisition, \
         streaming upload, and both pre-commitment response-header expiry arms \
         must share the bounded 401 writer"
    );
    assert!(
        !dispatch.contains("StatusCode::UNAUTHORIZED"),
        "dispatch_plain must not emit the fixed 401 through the unbounded reject writer"
    );
    assert!(
        !dispatch.contains(r#"{"error":"Unauthorized"}"#),
        "the compiled-in 401 body must live only in the bounded authorization terminal helper"
    );

    let helper = cross
        .split("async fn write_plain_authorization_expired_terminal<S>(")
        .nth(1)
        .expect("bounded plain authorization-expiry terminal writer")
        .split("async fn write_reject_with_headers<S>(")
        .next()
        .expect("bounded plain authorization-expiry terminal writer body");
    assert!(helper.contains("await_post_deadline_terminal_response_write(write)"));
    assert!(
        !helper.contains("await_terminal_response_write_before_deadline("),
        "the already-expired authorization instant must not race the selected 401"
    );
    assert!(
        !helper.contains("await_response_write_before_deadline("),
        "the selected 401 must not reuse the ordinary in-lifetime write bound"
    );
    assert!(helper.contains("StatusCode::UNAUTHORIZED"));
    assert!(helper.contains(r#"{"error":"Unauthorized"}"#));
    assert!(
        helper.contains("write_plain_gateway_reject_with_recv_halt("),
        "plain HTTP must keep the compiled-in 401 rather than a fabricated gRPC status"
    );
    let inner_write = helper
        .split("write_plain_gateway_reject_with_recv_halt(")
        .nth(1)
        .expect("inner send-only 401 writer")
        .split(");")
        .next()
        .expect("bounded inner send-only 401 writer");
    assert!(
        inner_write.contains("false,"),
        "the inner 401 writer must defer STOP_SENDING until the bounded write settles"
    );
    assert_eq!(
        helper.matches("abort_response_stream(stream)").count(),
        2,
        "a blocked or failed post-authorization terminal must reset the response send half"
    );
    assert!(helper.contains("H3ResponseWriteError::Write(_)"));
    assert!(helper.contains("H3ResponseWriteError::DeadlineExceeded"));
    assert!(helper.contains("terminal_deadline_write_aborted_outcome("));
    let write_fail = helper
        .split("H3ResponseWriteError::Write(_)")
        .nth(1)
        .expect("client-reset post-authorization arm")
        .split("H3ResponseWriteError::DeadlineExceeded")
        .next()
        .expect("bounded client-reset post-authorization arm");
    assert!(
        write_fail.contains("true,"),
        "a client-reset post-authorization write must report client_disconnected"
    );
    let grace_expire = helper
        .split("H3ResponseWriteError::DeadlineExceeded")
        .nth(1)
        .expect("grace-expired post-authorization arm");
    assert!(
        grace_expire.contains("false,"),
        "a grace-expired post-authorization write must not claim a client disconnect"
    );
    let grace_write = helper
        .find("await_post_deadline_terminal_response_write(write)")
        .expect("post-authorization 401 must use the shared grace");
    let halt_after_grace = helper
        .find("halt_request_body(stream)")
        .expect("post-authorization 401 must halt the receive half after the bounded write");
    assert!(
        grace_write < halt_after_grace,
        "STOP_SENDING must follow the bounded 401 write, not precede response settlement"
    );
    assert_eq!(
        helper.matches("halt_request_body(stream)").count(),
        1,
        "the receive half must halt exactly once after the bounded write settles"
    );
    assert!(
        !helper[..halt_after_grace].contains("halt_request_body(stream)"),
        "halt_request_body must not run until await_post_deadline_terminal_response_write returns"
    );

    let ordinary = cross
        .split("async fn write_plain_gateway_error<S>(")
        .nth(1)
        .expect("ordinary plain gateway error writer")
        .split("async fn write_plain_gateway_reject<S>(")
        .next()
        .expect("bounded ordinary plain gateway error writer");
    assert!(
        !ordinary.contains("await_post_deadline_terminal_response_write("),
        "ordinary non-authorization rejects must keep the unbounded writer"
    );
}

#[test]
fn h3_native_and_cross_protocol_cancel_writers_use_post_deadline_grace() {
    let server = include_str!("../../../src/http3/server.rs");
    let error_writer = server
        .split("async fn send_h3_error_flavor_aware_with_policy_and_recv_halt(")
        .nth(1)
        .expect("native H3 error writer with recv-halt control")
        .split("async fn send_h3_reject_flavor_aware(")
        .next()
        .expect("bounded native H3 error writer");
    assert!(error_writer.contains("if !halt_recv"));
    assert!(error_writer.contains("await_post_deadline_terminal_response_write("));
    assert!(error_writer.contains("abort_response_stream(stream)"));
    assert_eq!(
        error_writer.matches("halt_request_body(stream)").count(),
        1,
        "the halt_recv=false branch must halt the request direction after the bounded write settles"
    );
    let grace_start = error_writer
        .find("if !halt_recv {")
        .expect("native H3 error writer halt_recv=false branch");
    let grace_arm = &error_writer[grace_start..];
    let grace_write = grace_arm
        .find("await_post_deadline_terminal_response_write(")
        .expect("native H3 error writer must use post-deadline grace");
    let halt_after_grace = grace_arm
        .find("halt_request_body(stream)")
        .expect("native H3 error writer must halt after grace settles");
    assert!(
        grace_write < halt_after_grace,
        "STOP_SENDING must follow the bounded terminal write, not precede response settlement"
    );
    assert!(
        !grace_arm[..halt_after_grace].contains("halt_request_body(stream)"),
        "halt_request_body must not run until await_post_deadline_terminal_response_write returns"
    );

    let cross = include_str!("../../../src/http3/cross_protocol.rs");
    let final_reject = cross
        .split("async fn write_final_body_reject<S>(")
        .nth(1)
        .expect("cross-protocol final reject writer")
        .split("fn normalize_h3_grpc_reject(")
        .next()
        .expect("bounded cross-protocol final reject writer");
    assert_eq!(
        final_reject
            .matches("await_post_deadline_terminal_response_write(")
            .count(),
        3,
        "gRPC-Web, native gRPC, and plain terminal-deadline branches must share the grace helper"
    );
    assert_eq!(
        final_reject
            .matches("abort_response_stream(stream)")
            .count(),
        6,
        "each terminal-deadline branch must abort on both write failure and grace expiry"
    );
    let timed_out = cross
        .split("Err(super::server::H3RequestBodyReadError::TimedOut) => {")
        .nth(1)
        .expect("cross-protocol timed-out bridge arm")
        .split("Err(super::server::H3RequestBodyReadError::DeadlineExceeded(_)) => {")
        .next()
        .expect("bounded timed-out bridge arm");
    assert!(timed_out.contains("await_post_deadline_terminal_response_write("));
    assert!(timed_out.contains("abort_response_stream(stream)"));
    assert_eq!(
        timed_out.matches("halt_request_body(stream)").count(),
        1,
        "timed-out bridge arm must halt the request direction after the bounded write settles"
    );
    let grace_write = timed_out
        .find("await_post_deadline_terminal_response_write(")
        .expect("timed-out bridge arm must use post-deadline grace");
    let halt_after_grace = timed_out
        .find("halt_request_body(stream)")
        .expect("timed-out bridge arm must halt after grace settles");
    assert!(
        grace_write < halt_after_grace,
        "cross-protocol timed-out STOP_SENDING must follow the bounded terminal write"
    );
    assert!(
        !timed_out[..halt_after_grace].contains("halt_request_body(stream)"),
        "halt_request_body must not run until await_post_deadline_terminal_response_write returns"
    );
}

#[test]
fn h3_grpc_deadline_terminal_status_depends_on_client_visible_data() {
    assert!(
        ferrum_edge::_test_support::grpc_deadline_can_send_terminal_status_for_test(0),
        "the first blocked DATA write may still be replaced by clean status-4 trailers"
    );
    assert!(
        !ferrum_edge::_test_support::grpc_deadline_can_send_terminal_status_for_test(1),
        "once any DATA is client-visible the stream must reset instead of hiding a partial message"
    );

    let native = include_str!("../../../src/http3/server.rs");
    let native = native
        .split("async fn dispatch_grpc_native_h3(")
        .nth(1)
        .expect("native H3 gRPC relay")
        .split("async fn log_h3_grpc_transaction(")
        .next()
        .expect("bounded native H3 gRPC relay");
    let native_loop = native
        .split("'outer: loop")
        .nth(1)
        .expect("native response loop");
    let native_select = native_loop
        .split("tokio::select! {")
        .nth(1)
        .expect("native response select");
    let native_deadline = native_select
        .find("_ = &mut grpc_deadline_sleep")
        .expect("native response deadline arm");
    let native_data = native_select
        .find("backend_recv.recv_data()")
        .expect("native response DATA arm");
    assert!(native_select[..native_deadline].contains("biased;"));
    assert!(
        native_deadline < native_data,
        "simultaneously-ready native DATA must lose to the absolute deadline"
    );
    assert!(native.contains("await_downstream_grpc_write!"));
    assert!(native.contains("grpc_deadline_can_send_terminal_status("));

    let bridge = include_str!("../../../src/http3/cross_protocol.rs");
    let bridge = bridge
        .split("async fn stream_hyper_incoming<S>(")
        .nth(1)
        .expect("H3-to-H2 gRPC response relay")
        .split("fn should_finish_h3_stream_without_trailers(")
        .next()
        .expect("bounded H3-to-H2 gRPC response relay");
    assert!(bridge.contains("await_downstream_write!"));
    assert!(bridge.contains("grpc_deadline_can_send_terminal_status("));
    assert!(bridge.contains("trailers = Some(deadline_trailers);"));
    assert!(bridge.contains("abort_response_stream(stream);"));
}

#[test]
fn streaming_h3_grpc_web_dispatch_is_bounded_before_response_headers() {
    let source = include_str!("../../../src/http3/cross_protocol.rs");
    let dispatch = source
        .split("async fn dispatch_plain<S>(")
        .nth(1)
        .expect("cross-protocol plain dispatcher")
        .split("async fn dispatch_grpc<S>(")
        .next()
        .expect("bounded cross-protocol plain dispatcher");
    // The streaming upload/backend-response race runs under the COMPOSED bound
    // `plain_write_bound` — the client's optional gRPC-Web deadline together
    // with the admitted credential's authorization lifetime (issue #3815) — so
    // a plain HTTP client with no RPC deadline is bounded too.
    let bridge = dispatch
        .split("let send_result = if plain_write_bound")
        .nth(1)
        .expect("streaming upload/backend response race");
    // An ALREADY-elapsed composed bound must not poll the race at all: the
    // backend send and the frontend reader are both dropped, and the owner is
    // read from the captured composition rather than from a second clock read.
    let refusal = bridge
        .split("} else {")
        .next()
        .expect("bounded already-elapsed refusal arm");
    assert!(
        refusal.contains("tokio::time::Instant::now() >= at"),
        "an already-elapsed composed bound must refuse before polling the race"
    );
    assert!(
        refusal.contains("plain_write_bound.expired_authorization()"),
        "the refusal must attribute from the captured composition"
    );
    let deadline = bridge
        .find("_ = &mut upload_deadline, if upload_deadline_active =>")
        .expect("composed authorization/deadline arm");
    let response = bridge
        .find("result = &mut send_future")
        .expect("backend response-header arm");
    assert!(bridge[..deadline].contains("biased;"));
    assert!(
        deadline < response,
        "a simultaneous backend response must not outlive the composed bound"
    );
    assert!(
        bridge[deadline..response].contains("plain_write_bound.expired_authorization()"),
        "the winning owner must be captured before the race breaks"
    );
    assert!(bridge[deadline..response].contains("drop(pending_slot.take());"));
    assert!(bridge[deadline..response].contains("break None;"));
    assert!(bridge.contains("halt_request_body(stream);"));
    // No response header was committed, so an authorization expiry takes the
    // fixed `401` pre-commitment terminal while the client's own gRPC-Web
    // deadline keeps its own.
    assert!(bridge.contains("write_plain_authorization_expired_terminal("));
    assert!(bridge.contains("record_plain_grpc_web_client_deadline("));
    assert!(bridge.contains("write_plain_grpc_web_client_deadline("));
}

#[test]
fn deadline_bound_h3_grpc_web_pass_through_bypasses_native_backend_h3() {
    let source = include_str!("../../../src/http3/server.rs");
    let dispatch = source
        .split("let deadline_bound_grpc_web_pass_through =")
        .nth(1)
        .expect("deadline-bound gRPC-Web pass-through classifier")
        .split("let backend_url =")
        .next()
        .expect("native H3 selection block");
    assert!(dispatch.contains("ctx.grpc_deadline_at().is_some()"));
    assert!(dispatch.contains("let use_native_h3_pool ="));
    assert!(dispatch.contains("&& !deadline_bound_grpc_web_pass_through"));

    let bridge = source
        .split("let native_h3_direct_dispatch = use_native_h3_pool || use_native_h3_grpc;")
        .nth(1)
        .expect("native H3 direct-dispatch gate");
    assert!(bridge.contains("if !use_native_h3_pool"));
}

#[test]
fn h3_plain_grpc_web_client_acquisition_is_deadline_bounded() {
    let source = include_str!("../../../src/http3/cross_protocol.rs");
    let dispatch = source
        .split("async fn dispatch_plain<S>(")
        .nth(1)
        .expect("cross-protocol plain dispatcher")
        .split("async fn dispatch_grpc<S>(")
        .next()
        .expect("bounded cross-protocol plain dispatcher");
    assert_eq!(
        dispatch.matches("get_cross_protocol_client(").count(),
        2,
        "both buffered and streaming client acquisitions must remain explicit"
    );
    assert_eq!(
        dispatch
            .matches("let client_result = match crate::plugins::await_deadline_first(")
            .count(),
        2,
        "both client acquisitions must use the composed expiry-first bound"
    );
    assert!(
        dispatch.contains("plain_write_bound.deadline()"),
        "client acquisition must wait under the captured composed bound, not the client deadline alone"
    );
    assert!(dispatch.contains("drop(pending_slot);"));
    assert!(dispatch.contains("halt_request_body(stream);"));
    assert!(dispatch.contains("record_plain_grpc_web_client_deadline("));
    assert!(dispatch.contains("write_plain_grpc_web_client_deadline("));
    assert!(
        dispatch.contains("write_plain_authorization_expired_terminal("),
        "an authorization-owned acquisition expiry must stay on the fixed 401, not the client-deadline writer"
    );
}

#[test]
fn h3_buffered_upload_deadlines_run_rejection_cleanup_and_logging() {
    let source = include_str!("../../../src/http3/server.rs");
    let helper = source
        .split("async fn finalize_h3_upload_deadline_rejection(")
        .nth(1)
        .expect("shared H3 upload-deadline finalizer")
        .split("async fn send_h3_plugin_reject_flavor_aware(")
        .next()
        .expect("bounded H3 upload-deadline finalizer");
    assert!(helper.contains("apply_reject_after_proxy_and_synthetic_body_hooks("));
    assert!(helper.contains("run_h3_reject_response_committed_hooks("));
    assert!(helper.contains("log_rejected_request("));
    assert!(helper.contains("send_h3_plugin_reject_flavor_aware("));
    // Upload-deadline rejection is already selected; the terminal write must use
    // the shared post-deadline grace (via the plugin reject writer) rather than
    // re-racing the expired absolute deadline.
    assert!(!helper.contains("await_terminal_response_write_before_deadline("));
    assert!(!helper.contains("await_post_deadline_terminal_response_write("));
    assert_eq!(
        helper
            .matches("apply_reject_after_proxy_and_synthetic_body_hooks(")
            .count(),
        1
    );
    assert_eq!(
        helper
            .matches("run_h3_reject_response_committed_hooks(")
            .count(),
        1
    );
    assert_eq!(helper.matches("log_rejected_request(").count(), 1);
    assert_eq!(helper.matches("record_request(state,").count(), 1);
    assert_eq!(
        helper
            .matches("send_h3_plugin_reject_flavor_aware(")
            .count(),
        1
    );
    let decorate = helper
        .find("apply_reject_after_proxy_and_synthetic_body_hooks(")
        .expect("upload deadline decorators");
    let commit = helper
        .find("run_h3_reject_response_committed_hooks(")
        .expect("upload deadline commit");
    let log = helper
        .find("log_rejected_request(")
        .expect("upload deadline log");
    let metric = helper
        .find("record_request(state,")
        .expect("upload deadline metric");
    let send = helper
        .find("send_h3_plugin_reject_flavor_aware(")
        .expect("upload deadline send");
    assert!(decorate < commit && commit < log && log < metric && metric < send);
    for phase in [
        "grpc_deadline_upload_before_authenticate",
        "grpc_deadline_upload_before_authorize",
        "grpc_deadline_upload_before_before_proxy",
        "grpc_deadline_terminal_h3_upload",
        "grpc_deadline_upload_before_dispatch",
        "grpc_deadline_upload_before_cross_protocol_dispatch",
        "grpc_deadline_buffered_h3_upload",
    ] {
        assert!(
            source.contains(phase),
            "missing finalized H3 upload deadline phase {phase}"
        );
    }
    assert_eq!(
        source
            .matches("finalize_h3_upload_deadline_rejection(")
            .count(),
        8,
        "the helper definition plus all seven native H3 buffered upload exits must remain finalized"
    );
}

#[test]
fn h3_deadline_preflight_runs_committed_hooks_exactly_once() {
    let source = include_str!("../../../src/http3/server.rs");
    let preflight = source
        .find("// Resolve the effective gRPC policy before any plugin/body await.")
        .expect("H3 gRPC deadline preflight must remain present");
    let preflight = &source[preflight..];
    let preflight_end = preflight
        .find("// Pre-computed capability bitset")
        .expect("H3 gRPC deadline preflight must remain bounded");
    let preflight = &preflight[..preflight_end];

    let reject_hooks = preflight
        .find("apply_reject_after_proxy_and_synthetic_body_hooks(")
        .expect("H3 preflight reject body hooks must remain present");
    let reject_hooks = &preflight[reject_hooks..];
    let reject_hooks_end = reject_hooks
        .find(")\n            .await;")
        .expect("H3 preflight reject body hooks must remain bounded");
    assert!(
        reject_hooks[..reject_hooks_end]
            .trim_end()
            .ends_with("false,"),
        "generic reject finalization must not invoke committed hooks before the bounded helper"
    );
    assert!(preflight.contains("run_h3_deadline_bounded_reject_committed_hooks("));
    assert!(
        preflight.contains("run_h3_reject_response_committed_hooks("),
        "the impossible normalization fallback must retain the same committed-hook contract"
    );
    assert!(preflight.contains("send_h3_finalized_reject_response("));
}

#[test]
fn preacquired_admission_has_exactly_once_outcome_and_release_ownership() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use ferrum_edge::_test_support::PreacquiredBackendAdmissionForTest;
    use ferrum_edge::plugins::{
        BackendAdmissionOutcome, BackendAdmissionPermit, BackendAdmissionPermitSet,
    };
    use ferrum_edge::retry::ErrorClass;

    #[derive(Default)]
    struct PermitState {
        outcomes: AtomicUsize,
        drops: AtomicUsize,
    }

    struct CountingPermit {
        state: Arc<PermitState>,
    }

    impl BackendAdmissionPermit for CountingPermit {
        fn record_backend_outcome(&self, _outcome: BackendAdmissionOutcome) {
            self.state.outcomes.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl Drop for CountingPermit {
        fn drop(&mut self) {
            self.state.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn owner() -> (PreacquiredBackendAdmissionForTest, Arc<PermitState>) {
        let state = Arc::new(PermitState::default());
        let permit: Arc<dyn BackendAdmissionPermit> = Arc::new(CountingPermit {
            state: Arc::clone(&state),
        });
        let permits = BackendAdmissionPermitSet::new(vec![permit])
            .expect("the counting permit set must be non-empty");
        (
            PreacquiredBackendAdmissionForTest::acquired(Some(permits)),
            state,
        )
    }

    for outcome in [
        BackendAdmissionOutcome {
            response_status: 200,
            connection_error: false,
            error_class: None,
            backend_elapsed: Duration::from_millis(5),
        },
        BackendAdmissionOutcome {
            response_status: 502,
            connection_error: true,
            error_class: Some(ErrorClass::ConnectionRefused),
            backend_elapsed: Duration::from_millis(5),
        },
    ] {
        let (mut owner, state) = owner();
        let permits = owner
            .take_if_acquired()
            .expect("preacquired admission must be consumable once")
            .expect("the preacquired permit set must be preserved");
        assert!(
            owner.take_if_acquired().is_none(),
            "a consumed admission owner must not yield a second acquisition"
        );
        permits.record_backend_outcome(outcome);
        drop(permits);
        drop(owner);
        assert_eq!(state.outcomes.load(Ordering::Relaxed), 1);
        assert_eq!(state.drops.load(Ordering::Relaxed), 1);
    }

    let (owner_before_reject, rejected_state) = owner();
    drop(owner_before_reject);
    assert_eq!(rejected_state.outcomes.load(Ordering::Relaxed), 0);
    assert_eq!(rejected_state.drops.load(Ordering::Relaxed), 1);

    let (mut owner_before_cancel, cancelled_state) = owner();
    let permits = owner_before_cancel
        .take_if_acquired()
        .expect("cancelled dispatch must first take ownership")
        .expect("cancelled dispatch must retain the permit set");
    drop(permits);
    drop(owner_before_cancel);
    assert_eq!(cancelled_state.outcomes.load(Ordering::Relaxed), 0);
    assert_eq!(cancelled_state.drops.load(Ordering::Relaxed), 1);

    let mut permitless = PreacquiredBackendAdmissionForTest::acquired(None);
    assert!(matches!(permitless.take_if_acquired(), Some(None)));
    assert!(permitless.take_if_acquired().is_none());
}

#[test]
fn h3_header_limits_precede_grpc_web_response_negotiation() {
    let src = include_str!("../../../src/http3/server.rs");
    let detected = src
        .find(
            "let detected_http_flavor = crate::proxy::backend_dispatch::detect_http_flavor(&req);",
        )
        .expect("H3 handler must classify base request flavor");
    let header_limits = src[detected..]
        .find("// Enforce configured HTTP/3 header limits before deriving any gRPC-Web")
        .map(|offset| detected + offset)
        .expect("H3 handler must validate header limits before gRPC-Web negotiation");
    let grpc_web_negotiation = src[detected..]
        .find("let grpc_web_response_content_type_owned =")
        .map(|offset| detected + offset)
        .expect("H3 handler must retain gRPC-Web response content-type negotiation");
    let context_build = src[detected..]
        .find("let mut ctx = RequestContext::new")
        .map(|offset| detected + offset)
        .expect("H3 handler must retain request context construction");
    let header_limit_block = &src[header_limits..grpc_web_negotiation];

    assert!(
        header_limits < grpc_web_negotiation,
        "H3 must reject oversized headers before parsing attacker-controlled gRPC-Web suffixes"
    );
    assert!(
        grpc_web_negotiation < context_build,
        "valid gRPC-Web requests must still retain negotiated response content type on the request context"
    );
    assert!(header_limit_block.contains("state.max_single_header_size_bytes"));
    assert!(header_limit_block.contains("state.max_header_size_bytes"));
    assert!(header_limit_block.contains("state.max_header_count"));
    assert!(
        !header_limit_block.contains("grpc_web_response_content_type"),
        "header-limit rejection must not depend on pre-validation gRPC-Web response negotiation"
    );
}

#[test]
fn h3_streaming_grpc_web_preserves_native_statuses_and_metadata() {
    let source = include_str!("../../../src/http3/cross_protocol.rs");
    let handler = source
        .split("async fn handle_h3_grpc_streaming_response")
        .nth(1)
        .expect("H3 cross-protocol streaming gRPC response handler")
        .split("/// Resolve the gRPC dispatch transport")
        .next()
        .expect("bounded streaming handler body");

    let translation_gate = handler
        .find("response_body_rewrite_allowed(streaming.status)")
        .expect("H3 gRPC-Web streaming adapter must honor preserved statuses");
    let terminal_take = handler
        .find("take_streaming_initial_terminal_metadata(")
        .expect("H3 streaming terminal metadata extraction");
    assert!(
        translation_gate < terminal_take,
        "preserved statuses must bypass H3 body and terminal translation"
    );

    let metadata_refresh = handler
        .find("refresh_grpc_status_metadata(")
        .expect("H3 client-visible gRPC status refresh");
    assert!(
        metadata_refresh < terminal_take,
        "Trailers-Only status must be recorded before translation removes it from headers"
    );
    assert!(handler.contains("grpc_web_translation_mode"));
    assert!(!handler.contains("grpc_web_text_mode"));
}

#[test]
fn h3_buffered_retry_recomputes_native_h3_on_target_rotation() {
    let src = include_str!("../../../src/http3/server.rs");
    let retry = src
        .split("// ===== BUFFERED RESPONSE PATH =====")
        .nth(1)
        .expect("buffered H3 response path")
        .split("// Record outcome against the final target")
        .next()
        .expect("bounded buffered retry loop");
    assert!(
        retry.contains("let mut current_dispatch_h3 = true;"),
        "H3 buffered retry must lock native-H3 for the first already-selected target"
    );
    assert!(
        retry.contains("if target_changed {")
            && retry.contains("current_dispatch_h3 = crate::proxy::supports_native_http3_backend("),
        "H3 buffered retry must recompute native-H3 eligibility when the concrete target changes"
    );
    assert!(
        retry.contains("h3_buffered_result_from_backend_response(")
            && retry.contains("proxy_to_backend_retry("),
        "Unknown/Unsupported rotated targets must bridge via the buffered cross-protocol path"
    );
    assert!(
        src.contains("fn h3_buffered_result_from_backend_response("),
        "bridge conversion helper must exist"
    );
}

#[test]
fn plain_h3_streaming_body_and_trailer_faults_downgrade_capability() {
    let src = include_str!("../../../src/http3/server.rs");
    // Inline native-H3 streaming body fault (handle_h3_request).
    let inline_body = src
        .split("Error reading backend h3 response during streaming: {}")
        .nth(1)
        .expect("inline streaming body fault log")
        .split("break 'outer;")
        .next()
        .expect("bounded inline body fault arm");
    assert!(
        inline_body.contains("is_h3_transport_error_class(class)")
            && inline_body.contains("mark_h3_unsupported("),
        "plain inline streaming body transport faults must downgrade H3 capability"
    );
    assert!(
        inline_body.contains("!crate::http3::client::is_h3_graceful_close(&e)"),
        "an H3_NO_ERROR / GOAWAY teardown must never downgrade H3 capability"
    );

    // Inline trailer-finish Backend arm.
    let inline_trailer = src
        .split("Error reading backend h3 response trailers during streaming: {}")
        .nth(1)
        .expect("inline streaming trailer fault log")
        .split("H3TrailerFinishError::BackendTimeout")
        .next()
        .expect("bounded inline trailer fault arm");
    assert!(
        inline_trailer.contains("is_h3_transport_error_class(class)")
            && inline_trailer.contains("mark_h3_unsupported("),
        "plain inline streaming trailer transport faults must downgrade H3 capability"
    );
    assert!(
        inline_trailer.contains("!crate::http3::client::is_h3_graceful_close(&err)"),
        "a graceful trailer-boundary teardown must never downgrade H3 capability"
    );

    // Refined streaming body fault.
    let refined_body = src
        .split("Error reading backend h3 response during refined streaming: {}")
        .nth(1)
        .expect("refined streaming body fault log")
        .split("break 'outer;")
        .next()
        .expect("bounded refined body fault arm");
    assert!(
        refined_body.contains("is_h3_transport_error_class(class)")
            && refined_body.contains("mark_h3_unsupported("),
        "refined streaming body transport faults must downgrade H3 capability"
    );
    assert!(
        refined_body.contains("!crate::http3::client::is_h3_graceful_close(&error)"),
        "refined streaming must exclude graceful close from the downgrade signal"
    );

    // Buffered-request streaming body fault (second "during streaming" after
    // the inline path — use the proxy_to_backend_h3_streaming function scope).
    let buffered_req = src
        .split("async fn proxy_to_backend_h3_streaming(")
        .nth(1)
        .expect("buffered-request streaming function")
        .split("Outcome of a buffered HTTP/3 backend request.")
        .next()
        .expect("bounded buffered-request streaming body");
    assert!(
        buffered_req.contains("is_h3_transport_error_class(class)")
            && buffered_req
                .matches("mark_h3_unsupported(proxy, upstream_target)")
                .count()
                >= 2,
        "buffered-request streaming body and trailer transport faults must downgrade"
    );
    assert!(
        buffered_req.matches("is_h3_graceful_close(&").count() >= 3,
        "buffered-request streaming must exclude graceful close at the body \
         recovery check and at both downgrade sites"
    );
}

#[test]
fn buffered_h3_trailers_reconcile_with_response_policy_not_chain_emptiness() {
    let src = include_str!("../../../src/http3/server.rs");

    // The witness must be captured BEFORE the first response-header phase,
    // otherwise the "did the chain change this field?" comparison is against a
    // map the chain already rewrote and every mutation reads as a no-op.
    let buffered_response_region = src
        .split("        // buffered native-H3 path. Unlike the streamed paths")
        .nth(1)
        .expect("buffered native-H3 response region")
        .split("// Build and send buffered response")
        .next()
        .expect("bounded buffered native-H3 response region");
    let (before_capture, after_capture) = buffered_response_region
        .split_once("        // after_proxy hooks")
        .expect("buffered after_proxy phase");
    let capture = after_capture
        .split("// Sticky session cookie injection.")
        .next()
        .expect("bounded after_proxy trailer region");
    assert!(
        before_capture.contains("ResponseTrailerPolicyWitness::capture(")
            && before_capture.contains("ResponseTrailerPolicyWitness::Unproven"),
        "buffered H3 must witness the backend's pre-policy header values before after_proxy runs"
    );
    assert!(
        !capture.contains("if !plugins.is_empty()"),
        "buffered H3 must not wipe trailers merely because the plugin chain is nonempty"
    );

    let gate = src
        .split("        let mut response_body_rejected = false;")
        .nth(1)
        .expect("buffered response body phases")
        .split("// on_response_body hooks")
        .next()
        .expect("bounded trailer gate");
    assert!(
        gate.contains("crate::proxy::response_body_plugins_process_body(&plugins, &ctx)")
            && gate.contains("response_trailers = None;"),
        "buffered H3 must drop trailers exactly when a response-body plugin phase \
         processes this response"
    );
    assert!(
        !gate.contains("if !plugins.is_empty()"),
        "buffered H3 must not wipe trailers merely because the plugin chain is nonempty"
    );

    // Reconciliation runs after the LAST header phase and before the response
    // is built, so sticky-cookie injection and committed hooks are covered too.
    let reconcile = src
        .split("        // Final protocol-aware strip after after_proxy / committed hooks")
        .nth(1)
        .expect("buffered final response-header sanitizer")
        .split("// Build and send buffered response")
        .next()
        .expect("bounded reconciliation region");
    assert!(
        reconcile.contains("reconcile_backend_trailers_with_response_policy(")
            && reconcile.contains("plugin_cache_view.response_trailer_policy_names()")
            && reconcile.contains("plugin_cache_view.response_trailer_policy_prefixes()")
            && reconcile.contains("response_trailer_governance.unbounded"),
        "buffered H3 must reconcile surviving trailers against the precomputed \
         response-header policy names/prefixes and the same request-resolved \
         fail-closed unbounded arm the streaming relays received"
    );

    // Hop-by-hop trailer names are stripped BEFORE the reconciliation, matching
    // `finish_h3_response_with_backend_trailers`. Either order drops the same
    // fields from the wire, but reconciling first counts them as policy-governed
    // removals and inflates the `removed` telemetry.
    let strip_at = reconcile
        .find("strip_response_hop_by_hop_trailers(trailers);")
        .expect("buffered H3 hop-by-hop trailer strip");
    let reconcile_at = reconcile
        .find("reconcile_backend_trailers_with_response_policy(")
        .expect("buffered H3 reconciliation");
    let sanitize_at = reconcile
        .find("sanitize_client_response_headers_for_wire(&mut response_headers, framing);")
        .expect("buffered H3 response-header sanitization");
    assert!(
        sanitize_at < strip_at && strip_at < reconcile_at,
        "buffered H3 must sanitize final response headers, then strip hop-by-hop \
         trailer names, before reconciling surviving trailers"
    );
    let forward_region = src
        .split("// Forward backend response trailers, if any (issue #1630).")
        .nth(1)
        .expect("buffered trailer forward region")
        .split("stream.send_trailers(")
        .next()
        .expect("bounded buffered trailer forward region");
    assert!(
        !forward_region.contains("strip_response_hop_by_hop_trailers("),
        "buffered H3 must not strip hop-by-hop trailer names a second time"
    );

    let send = src
        .split("// Backend trailers survive to here only when no response-body plugin")
        .nth(1)
        .expect("buffered trailer retention comment")
        .split("// Forward backend response trailers, if any (issue #1630).")
        .next()
        .expect("bounded trailer forward comment");
    assert!(
        send.contains("Auth/logging-only plugins must not"),
        "retention rationale for auth/logging-only plugins must remain documented"
    );
}

/// The binding produced by the three PLAIN native/refined H3 streaming relays'
/// pre-policy capture. The native gRPC relay's capture binds
/// `grpc_pre_policy_response_headers` instead, so anchoring on this exact
/// `let` keeps the two families countable apart while the bare
/// `capture_for_streaming(` count still pins the file-wide total.
const PLAIN_STREAMING_CAPTURE: &str = "let pre_policy_response_headers = \
                                       PrePolicyResponseHeaders::capture_for_streaming(";

/// The native gRPC H3 relay's counterpart binding.
const GRPC_STREAMING_CAPTURE: &str = "let grpc_pre_policy_response_headers =";

#[test]
fn streaming_h3_relays_reconcile_backend_trailers_with_response_policy() {
    let src = include_str!("../../../src/http3/server.rs");

    // The shared trailer-finish helper must reconcile BEFORE `send_trailers`:
    // a streaming relay's initial HEADERS frame is already on the wire, so this
    // is the last point at which the response-header policy can bind the
    // trailer section.
    let helper = src
        .split("async fn finish_h3_response_with_backend_trailers<S>")
        .nth(1)
        .expect("trailer finish helper")
        .split("/// Start the HTTP/3 listener")
        .next()
        .expect("bounded trailer finish helper");
    let reconcile_at = helper
        .find("reconcile_streaming_backend_trailers(")
        .expect("streaming trailer reconciliation");
    let send_at = helper.find(".send_trailers(").expect("trailer send");
    assert!(
        reconcile_at < send_at,
        "streaming H3 must reconcile backend trailers before they reach the wire"
    );
    assert!(
        helper.contains("strip_response_hop_by_hop_trailers(&mut trailers);"),
        "streaming H3 must keep the hop-by-hop trailer strip"
    );

    // This file holds FOUR streaming relays that cross the response-header
    // policy boundary, and every one of them must capture pre-policy evidence:
    // the three plain native/refined relays (the inline stream, the refined
    // stream, and the buffered-request streaming helper) plus the native gRPC
    // relay, which inlines its own trailer finish and is pinned separately
    // below. Counting the total — not just the plain subset — is what makes a
    // silently added fifth relay fail here instead of shipping ungoverned.
    assert_eq!(
        src.matches("PrePolicyResponseHeaders::capture_for_streaming(")
            .count(),
        4,
        "every H3 streaming relay must capture its pre-policy response headers: \
         three plain native/refined relays plus the native gRPC relay"
    );
    // The two families are told apart by the binding they produce, never by
    // position, so adding a relay of either kind moves exactly one count.
    assert_eq!(
        src.matches(GRPC_STREAMING_CAPTURE).count(),
        1,
        "the native gRPC H3 relay must own exactly one pre-policy capture"
    );
    assert_eq!(
        src.matches("H3StreamingTrailerPolicy {").count(),
        3,
        "every plain native/refined H3 streaming relay must bind the response \
         trailer policy at its trailer frame"
    );
    let captures: Vec<&str> = src.split(PLAIN_STREAMING_CAPTURE).skip(1).collect();
    assert_eq!(
        captures.len(),
        3,
        "every plain native/refined H3 streaming relay must capture its \
         pre-policy response headers"
    );
    for region in captures {
        let hooks = region.find("run_h3_streaming_after_proxy_hooks(");
        let finish = region.find("finish_h3_response_with_backend_trailers(");
        assert!(
            hooks.is_some() && finish.is_some() && hooks < finish,
            "the pre-policy capture must precede the response-header phases, \
             which must precede the trailer frame"
        );
    }

    // Governance is read once from the precomputed plugin-cache view, not
    // rebuilt per response, and keeps the fail-closed unbounded arm. The
    // unbounded arm is REQUEST-resolved (a `waf` instance governs only the
    // requests its `global_exemptions` do not exempt, and a consumer exemption
    // is known only after authentication), so it must be taken from the
    // request-aware resolver on the finalized context and not from the
    // config-time capability bit.
    let governance = src
        .split("let response_trailer_governance = ResponseTrailerGovernance {")
        .nth(1)
        .expect("streaming trailer governance")
        .split("};")
        .next()
        .expect("bounded streaming trailer governance");
    assert!(
        governance.contains("policy_names: plugin_cache_view.response_trailer_policy_names(),"),
        "streaming governance names must come from the per-reload plugin cache view"
    );
    assert!(
        governance
            .contains("policy_prefixes: plugin_cache_view.response_trailer_policy_prefixes(),"),
        "streaming governance prefixes must come from the per-reload plugin cache view"
    );
    assert!(
        governance.contains(
            "unbounded: plugin_cache_view.unbounded_response_trailer_policy_applies(&ctx),"
        ),
        "streaming governance must keep the fail-closed unbounded arm and resolve it \
         against the finalized request context"
    );
    // The resolution point must be after the request-side phases. Anchoring it to
    // `should_stream_response_body` — which already evaluates the sibling
    // per-request WAF trailer predicate — pins it to the same finalized context
    // and fails if it drifts back to intake.
    let stream_decision_at = src
        .find("let should_stream_response = crate::proxy::should_stream_response_body(")
        .expect("H3 response-body streaming decision");
    let governance_at = src
        .find("let response_trailer_governance = ResponseTrailerGovernance {")
        .expect("H3 streaming trailer governance");
    assert!(
        stream_decision_at < governance_at,
        "the request-resolved trailer governance must be built from the finalized \
         request context, not before the request-side plugin phases"
    );

    // GHSA-r78v-rc86-6r86: native gRPC over H3 inlines its own trailer finish,
    // but that trailer section crosses the SAME response-header policy boundary
    // — its application metadata was the advisory's reproduction. It must
    // reconcile, and it must do so as a NATIVE GRPC TERMINAL section so the
    // reserved status fields survive.
    let grpc = src
        .split("async fn dispatch_grpc_native_h3(")
        .nth(1)
        .expect("native gRPC H3 dispatch")
        .split("async fn log_h3_grpc_transaction(")
        .next()
        .expect("bounded native gRPC H3 dispatch");
    assert!(
        grpc.contains("reconcile_streaming_backend_trailers("),
        "native gRPC H3 application metadata must be reconciled against the \
         response-header policy"
    );
    assert!(
        grpc.contains("TrailerSectionKind::NativeGrpcTerminal"),
        "native gRPC H3 must reconcile as a gRPC terminal section so grpc-status \
         survives"
    );
    assert!(
        !grpc.contains("TrailerSectionKind::PlainResponse"),
        "native gRPC H3 must not reconcile any trailer section as plain"
    );
    // Evidence must predate every response-header phase, and the reconciliation
    // must run before the trailers reach the client.
    let capture_at = grpc
        .find("let grpc_pre_policy_response_headers =")
        .expect("native gRPC H3 pre-policy capture");
    let after_proxy_at = grpc
        .find("run_h3_streaming_after_proxy_hooks(")
        .expect("native gRPC H3 after_proxy phase");
    let reconcile_at = grpc
        .find("reconcile_streaming_backend_trailers(")
        .expect("native gRPC H3 reconciliation");
    let send_at = grpc
        .find("send_h3_grpc_trailers_and_finish_before_deadline(")
        .expect("native gRPC H3 trailer send");
    assert!(
        capture_at < after_proxy_at,
        "the pre-policy capture must precede the first response-header phase"
    );
    assert!(
        reconcile_at < send_at,
        "native gRPC H3 trailers must be reconciled before they are sent"
    );
}

#[test]
fn the_h3_to_h2_grpc_streaming_bridge_governs_its_terminal_metadata() {
    // The advisory's second reproduction: an H3 client against an H2 gRPC
    // backend. The bridge commits its initial HEADERS frame, runs `after_proxy`
    // on headers only, then forwards the backend trailer section verbatim.
    let src = include_str!("../../../src/http3/cross_protocol.rs");
    let relay = src
        .split("async fn handle_h3_grpc_streaming_response<S>(")
        .nth(1)
        .expect("cross-protocol H3 gRPC streaming relay")
        .split("\nasync fn dispatch_grpc<S>(")
        .next()
        .expect("bounded cross-protocol H3 gRPC streaming relay");
    assert!(
        relay.contains("reconcile_streaming_backend_trailers("),
        "the H3->H2 gRPC bridge must reconcile its trailer section"
    );
    assert!(
        relay.contains("TrailerSectionKind::NativeGrpcTerminal"),
        "the H3->H2 gRPC bridge must reconcile as a gRPC terminal section"
    );
    let capture_at = relay
        .find("let grpc_pre_policy_response_headers =")
        .expect("bridge pre-policy capture");
    let after_proxy_at = relay
        .find("crate::proxy::run_after_proxy_hooks(")
        .expect("bridge after_proxy phase");
    let reconcile_at = relay
        .find("reconcile_streaming_backend_trailers(")
        .expect("bridge reconciliation");
    let send_at = relay
        .find("stream.send_trailers(trailers)")
        .expect("bridge trailer send");
    assert!(
        capture_at < after_proxy_at,
        "the bridge capture must precede the first response-header phase"
    );
    assert!(
        reconcile_at < send_at,
        "the bridge must reconcile before sending trailers"
    );
}

#[test]
fn streaming_h3_relays_put_the_default_content_type_on_the_final_header_map() {
    let src = include_str!("../../../src/http3/server.rs");

    // The default `content-type` must reach the response-header MAP, not just
    // the response builder. `H3StreamingTrailerPolicy.final_headers` points at
    // that map, so a builder-only default would leave the trailer boundary
    // reconciling a field set the client never actually received: a backend
    // `content-type` trailer would prove absent -> absent and land on the wire
    // contradicting the media type the gateway itself synthesized.
    assert!(
        !src.contains(r#"resp_builder = resp_builder.header("content-type", "application/json");"#),
        "no streaming relay may add the default content-type to the builder alone"
    );
    // Per relay: the pre-policy capture comes first, then the default lands in
    // the header map, then the response is built from that same map, and only
    // then does the trailer frame bind the policy. Bounded to each relay's own
    // region rather than counted across the file.
    //
    // Scoped to the PLAIN relays by their binding. The fourth streaming capture
    // in this file belongs to the native gRPC relay
    // (`grpc_pre_policy_response_headers`), which never synthesizes a default
    // `content-type` — a gRPC response carries `application/grpc` from the
    // backend — so it has no map write for this contract to order. That
    // exclusion is checked below rather than assumed.
    let relays: Vec<&str> = src
        .split(PLAIN_STREAMING_CAPTURE)
        .skip(1)
        .map(|tail| {
            tail.split("H3StreamingTrailerPolicy {")
                .next()
                .expect("bounded streaming relay region")
        })
        .collect();
    assert_eq!(
        relays.len(),
        3,
        "three plain native/refined streaming relays"
    );
    for relay in &relays {
        let map_write = relay
            .find(r#".entry("content-type".to_string())"#)
            .expect("streaming relay must default content-type onto the header map");
        let build = relay
            .find("apply_response_headers(Response::builder().status(")
            .expect("streaming relay must build its response");
        assert!(
            map_write < build,
            "the default content-type must be in the header map BEFORE the \
             response is built, so the map and the wire agree"
        );
        assert!(
            relay[map_write..build].contains(r#""application/json".to_string()"#),
            "the map write must carry the same default the builder used to add"
        );
    }

    // Synthesizing that field is a gateway-authored wire mutation, so it counts
    // as a response-header phase for the pre-policy capture decision. Without
    // that, an auth/logging-only chain would take the no-clone #2941
    // pass-through and forward a conflicting backend `content-type` trailer.
    for tail in src.split(PLAIN_STREAMING_CAPTURE).skip(1) {
        let args = tail.split(");").next().expect("capture argument list");
        assert!(
            args.contains("gateway_synthesizes_content_type"),
            "the capture predicate must fold in the synthesized default \
             content-type: {args}"
        );
    }
    // The native gRPC relay is exempt only because it authors no default
    // media type. If one is ever added there, this fails and the predicate
    // above has to grow a fourth site rather than silently under-capturing.
    let grpc_relay = src
        .split("async fn dispatch_grpc_native_h3(")
        .nth(1)
        .expect("native gRPC H3 dispatch")
        .split("async fn log_h3_grpc_transaction(")
        .next()
        .expect("bounded native gRPC H3 dispatch");
    assert!(
        !grpc_relay.contains(r#".entry("content-type".to_string())"#),
        "the native gRPC H3 relay must not synthesize a default content-type; \
         if it does, its pre-policy capture predicate must fold that in"
    );
    let flags: Vec<&str> = src
        .split("let gateway_synthesizes_content_type = ")
        .skip(1)
        .collect();
    assert_eq!(
        flags.len(),
        3,
        "each streaming relay decides the synthesis for itself"
    );
    for tail in flags {
        assert!(
            tail.starts_with("!response_headers.contains_key(\"content-type\");"),
            "the synthesis flag must come from this relay's own backend headers"
        );
    }
}

#[test]
fn the_trailer_reconciliation_exempts_no_field_name() {
    let src = include_str!("../../../src/proxy/headers.rs");
    let body = src
        .split("pub(crate) fn reconcile_backend_trailers_with_response_policy(")
        .nth(1)
        .expect("reconciliation function")
        .split("\n/// ")
        .next()
        .expect("bounded reconciliation function");

    // A NAME-based exemption here is a bypass, not a protocol accommodation: a
    // non-gRPC backend could smuggle a governed field past an observed or
    // unbounded policy just by naming its trailer `grpc-status`. Reserved-field
    // handling must therefore be reached STRUCTURALLY, through the `section`
    // the call site chose from the dispatch it committed to — never from a
    // literal field name in this function.
    assert!(
        !body.contains("grpc-status")
            && !body.contains("grpc-message")
            && !body.contains("GRPC_CONTROL_TRAILER_NAMES"),
        "the reconciliation must not name any exempt field: {body}"
    );
    // Exactly one early-out, and it must be the structural section check.
    assert_eq!(
        body.matches("continue;").count(),
        1,
        "the reconciliation must have exactly one early-out: {body}"
    );
    let early_out = body
        .split("continue;")
        .next()
        .expect("region above the early-out");
    let guard = early_out
        .rsplit("if ")
        .next()
        .expect("early-out guard")
        .lines()
        .next()
        .expect("early-out guard line");
    assert!(
        guard.contains("section.field_is_reserved("),
        "the only early-out must be the structural section check, not a name \
         comparison: {guard}"
    );
    // Governance stays the union of every independent signal. Asserted term by
    // term rather than as one formatted line so `cargo fmt` rewrapping the
    // expression cannot silently retire the contract.
    let union = body
        .split("let governed = ")
        .nth(1)
        .expect("governance union")
        .split(';')
        .next()
        .expect("bounded governance union");
    for term in [
        "explicitly_named",
        "prefix_owned",
        "gateway_owned",
        "unbounded_policy",
        "witness.was_mutated(",
    ] {
        assert!(
            union.contains(term),
            "governance must keep the {term} signal in its union: {union}"
        );
    }
    assert!(
        !union.contains("&&"),
        "the governance signals must be OR-ed; ANDing any pair would let one \
         signal veto another: {union}"
    );
}

/// GHSA-484w-rxg2-7jg5: an HTTP/3 request stream is served by a detached task
/// that owns the stream, its `RequestGuard`, and the plugin snapshot. If a
/// fault-injection delay cannot observe the client leaving, a peer that opens
/// streams and immediately closes the QUIC connection multiplies short-lived
/// clients into long-lived server-side retention.
#[test]
fn h3_stamps_a_connection_close_watch_so_injected_delays_cannot_outlive_the_peer() {
    let src = include_str!("../../../src/http3/server.rs");

    // The watch is connection-scoped and built exactly once per connection,
    // before the accept loop, so each stream costs one `Arc` bump.
    let watch = src
        .find("struct QuicPeerConnectionWatch {")
        .expect("HTTP/3 must define a QUIC peer-connection watch");
    let watch_tail = &src[watch..];
    let watch_end = watch_tail
        .find("/// Handle a single HTTP/3 request stream.")
        .expect("the watch must sit immediately before handle_h3_request");
    let watch_body = &watch_tail[..watch_end];
    assert!(
        watch_body.contains("self.connection.closed().await"),
        "the watch must observe QUIC connection close"
    );
    assert!(
        watch_body.contains("self.connection.close_reason().is_some()"),
        "the watch must offer a non-blocking already-closed check"
    );
    // Ownership guard: the watch must never touch the request stream. Reading
    // or polling it from a detached watcher would race the proxy path for
    // request bytes and could mask a stream-accounting failure.
    for forbidden in [
        "recv_data",
        "poll_recv_data",
        "recv_trailers",
        "stop_sending",
        "stop_stream",
    ] {
        assert!(
            !watch_body.contains(forbidden),
            "the peer watch must not touch the request stream ({forbidden})"
        );
    }

    let construction = src
        .find("PeerConnectionSignal::new(")
        .expect("the connection loop must build the peer-connection signal");
    let accept_loop = src
        .find("let is_early_data = identity.is_early_data;")
        .expect("per-stream identity snapshot must remain in the accept loop");
    assert!(
        construction < accept_loop,
        "the watch must be built once per connection, not once per stream"
    );

    let handler = src
        .find("async fn handle_h3_request(")
        .expect("handle_h3_request must exist");
    assert!(
        src[handler..].contains("peer_connection: crate::plugins::PeerConnectionSignal"),
        "each request stream must receive the connection-close watch"
    );
    assert!(
        src[handler..].contains("ctx.peer_connection = Some(peer_connection);"),
        "the watch must reach the plugin pipeline through the request context"
    );
}

/// Issue #3775: destination `http2MaxRequests` is a per-exchange cap. Cancelling
/// one H3 stream must release the permit even when the multiplexed QUIC
/// connection stays open. The header-wait race therefore has to observe
/// per-stream STOP_SENDING (`peer_response_cancelled` / `SendStreamStopped`),
/// not only `PeerConnectionSignal` (whole-connection close).
#[test]
fn h3_plain_header_wait_races_per_stream_stop_sending_not_only_connection_close() {
    let src = include_str!("../../../src/http3/cross_protocol.rs");
    let helper = src
        .split("async fn await_h3_backend_or_peer<")
        .nth(1)
        .expect("await_h3_backend_or_peer must exist")
        .split("\nfn plain_peer_gone_before_response_headers(")
        .next()
        .expect("bounded await_h3_backend_or_peer");
    assert!(
        helper.contains("stream_cancelled"),
        "the header-wait helper must take a per-stream cancellation future: {helper}"
    );
    assert!(
        helper.contains("_ = &mut stream_cancelled => H3BackendOrPeer::PeerGone"),
        "per-stream STOP_SENDING must release the wait as PeerGone: {helper}"
    );
    assert!(
        helper.contains("_ = &mut peer_closed => H3BackendOrPeer::PeerGone"),
        "whole-connection close must remain a PeerGone arm: {helper}"
    );
    assert!(
        helper.contains("H3BackendOrPeer::Deadline"),
        "the gRPC-Web absolute deadline race must be preserved: {helper}"
    );
    assert!(
        helper.contains("if let Some(deadline) = deadline")
            && helper.contains("tokio::time::Instant::now() >= deadline"),
        "an already-elapsed composed bound must refuse before polling the backend: {helper}"
    );
    let bounded = helper
        .split("Some(deadline) => {")
        .nth(1)
        .expect("bounded deadline select")
        .split("}\n        }")
        .next()
        .expect("bounded deadline select body");
    let biased_at = bounded
        .find("biased;")
        .expect("deadline-first biased select");
    let sleep_at = bounded.find("sleep_until(deadline)").expect("deadline arm");
    let ready_at = bounded
        .find("value = &mut future")
        .expect("backend-ready arm");
    assert!(
        biased_at < sleep_at && sleep_at < ready_at,
        "the composed bound must beat a simultaneously ready backend: {bounded}"
    );

    let dispatch = src
        .split("async fn dispatch_plain<S>(")
        .nth(1)
        .expect("dispatch_plain must exist")
        .split("\n#[allow(clippy::too_many_arguments)]\nasync fn dispatch_grpc<S>(")
        .next()
        .expect("bounded dispatch_plain");
    assert!(
        dispatch.contains("crate::http3::stream_util::peer_response_cancelled(stream)"),
        "the prebuffered/no-body header wait must watch per-stream STOP_SENDING"
    );
    assert!(
        dispatch.matches("peer_response_cancelled(stream)").count() >= 2,
        "both prebuffered and streaming-upload header waits must watch per-stream STOP_SENDING"
    );
    assert!(
        dispatch.contains("_ = &mut stream_cancelled =>"),
        "the streaming-upload select must race STOP_SENDING, not only connection close"
    );
    assert!(
        dispatch.contains("reader_peer_reset"),
        "streaming-upload request-stream reset must be treated as downstream cancellation"
    );
    let send_arm = dispatch
        .split("result = &mut send_future =>")
        .nth(1)
        .expect("streaming send_future arm")
        .split("_ = &mut reader_future, if !reader_done =>")
        .next()
        .expect("bounded streaming send_future arm");
    assert!(
        send_arm.contains("reader_peer_reset.load(Ordering::Acquire)"),
        "biased send_future readiness must honor an already-acquired request reset: {send_arm}"
    );
    assert!(
        send_arm.contains("peer_gone = true"),
        "a request reset observed on send() readiness must take the client-disconnect path: {send_arm}"
    );
    assert!(
        send_arm.contains("break None"),
        "a request reset must not classify send() as a backend outcome: {send_arm}"
    );
    assert!(
        !dispatch.contains("hold_client.close()"),
        "production dispatch must not depend on whole-client close"
    );
}

/// The vendored cancellation primitive must be `&self` + `'static` so a header
/// wait can observe STOP_SENDING without exclusive send-stream access (which
/// would conflict with a concurrent recv-half poll on an unsplit bidi stream).
#[test]
fn h3_quinn_vendored_send_stream_stopped_is_shared_and_static() {
    let quic = include_str!("../../../vendor/h3-0.0.8-ferrum-patched/src/quic.rs");
    let trait_src = quic
        .split("pub trait SendStreamStopped {")
        .nth(1)
        .expect("SendStreamStopped trait")
        .split("\npub trait SendStreamUnframed")
        .next()
        .expect("bounded SendStreamStopped");
    assert!(
        trait_src.contains("fn stopped(")
            && trait_src.contains("&self")
            && !trait_src.contains("fn stopped(&mut self)"),
        "stopped must take &self, not &mut self: {trait_src}"
    );
    assert!(
        trait_src.contains(
            "impl Future<Output = Result<Option<u64>, StreamErrorIncoming>> + Send + 'static",
        ) && !trait_src.contains("type Stopped"),
        "stopped must return a stable RPITIT 'static Send future, not an associated type: {trait_src}"
    );
    assert!(
        !trait_src.contains("Pin<Box") && !trait_src.contains("dyn Future"),
        "stopped must not return a boxed trait-object future: {trait_src}"
    );

    let h3_quinn = include_str!("../../../vendor/h3-quinn-0.0.10-ferrum-patched/src/lib.rs");
    let send = h3_quinn
        .split("impl<B> h3::quic::SendStreamStopped for SendStream<B>")
        .nth(1)
        .expect("h3-quinn SendStream Stopped impl")
        .split("\nfn convert_stopped_error(")
        .next()
        .expect("bounded h3-quinn SendStream Stopped impl");
    assert!(
        send.contains("self.stream.stopped()"),
        "the impl must forward to quinn::SendStream::stopped (&self, 'static): {send}"
    );
    assert!(
        send.contains(
            "impl Future<Output = Result<Option<u64>, h3::quic::StreamErrorIncoming>> + Send + 'static"
        ) && !send.contains("type Stopped")
            && !send.contains("Box::pin")
            && !send.contains("dyn Future"),
        "the impl must return a stable RPITIT future, not an associated type or boxed trait object: {send}"
    );
    assert!(
        h3_quinn.contains("impl<B> h3::quic::SendStreamStopped for BidiStream<B>"),
        "unsplit bidi streams must expose the same STOP_SENDING watch"
    );

    let util = include_str!("../../../src/http3/stream_util.rs");
    let watch = util
        .split("pub(crate) fn peer_response_cancelled<")
        .nth(1)
        .expect("peer_response_cancelled must exist")
        .split("\npub(crate) fn abort_response_stream<")
        .next()
        .expect("bounded peer_response_cancelled");
    assert!(
        watch.contains("impl Future<Output = ()> + Send + 'static"),
        "peer_response_cancelled must return a statically dispatched 'static future: {watch}"
    );
    assert!(
        !watch.contains("Box::pin") && !watch.contains("Pin<Box") && !watch.contains("dyn Future"),
        "peer_response_cancelled must not box a trait-object future: {watch}"
    );
    assert!(
        watch.contains("Ok(Some(_)) | Err(_) => {}"),
        "STOP_SENDING and connection loss must complete the cancel watch: {watch}"
    );
    assert!(
        watch.contains("Ok(None) => std::future::pending::<()>().await"),
        "a local finish acknowledgement must not be treated as cancellation: {watch}"
    );
}

/// Regression guard (issue #3284): both H3→gRPC dispatch paths must obtain
/// their HTTP/2 sender from the RESOLVED transport, never from
/// `state.grpc_pool` directly.
///
/// Passing the direct-dial pool would silently restore the unauthenticated
/// dial the mesh refusal existed to prevent — the failure mode is invisible
/// under PERMISSIVE PeerAuthentication (the RPC succeeds, just without
/// SVID-mTLS, identity pinning, and mesh authz identity), so it is worth
/// freezing structurally.
fn bounded_h3_grpc_transport_resolve_calls(region: &str) -> Vec<&str> {
    const RESOLVE_H3_GRPC_TRANSPORT: &str = "resolve_h3_grpc_transport(";
    region
        .match_indices(RESOLVE_H3_GRPC_TRANSPORT)
        .map(|(idx, _)| {
            let tail = &region[idx..];
            let close = tail
                .find(") {")
                .expect("each H3→gRPC transport resolution must close before its match arm");
            &tail[..close + 3]
        })
        .collect()
}

#[test]
fn h3_grpc_dispatch_paths_dial_through_the_resolved_mesh_transport() {
    let source = include_str!("../../../src/http3/cross_protocol.rs");

    let buffered = source
        .split("async fn dispatch_grpc<S>(")
        .nth(1)
        .expect("buffered H3→gRPC dispatcher must remain present")
        .split("pub(crate) async fn dispatch_grpc_streaming(")
        .next()
        .expect("buffered H3→gRPC dispatcher must remain bounded");
    let buffered_resolves = bounded_h3_grpc_transport_resolve_calls(buffered);
    assert_eq!(
        buffered_resolves.len(),
        2,
        "the initial target and every rotated retry target must each be resolved"
    );
    for (i, call) in buffered_resolves.iter().enumerate() {
        assert!(
            call.contains("current_target.as_deref()"),
            "buffered transport resolution #{i} must pass the selected target"
        );
        assert!(
            call.contains("ctx.peer_spiffe_id.as_ref()"),
            "buffered transport resolution #{i} must preserve the authenticated frontend identity"
        );
    }
    assert!(
        buffered.contains("&initial_grpc_transport,"),
        "the initial attempt must dial through the resolved transport"
    );
    assert!(
        buffered.contains("&grpc_retry_transport,"),
        "a rotated retry target must dial through ITS OWN re-resolved transport"
    );
    assert_eq!(
        buffered
            .matches("transport_error.diagnostic().as_str()")
            .count(),
        2,
        "initial and retry-rotated transport refusals must both log the redacted diagnostic"
    );

    let streaming = source
        .split("pub(crate) async fn dispatch_grpc_streaming(")
        .nth(1)
        .expect("streaming H3→gRPC dispatcher must remain present")
        .split("\nasync fn apply_buffered_plain_plugin_reject")
        .next()
        .expect("streaming H3→gRPC dispatcher must remain bounded");
    let streaming_resolves = bounded_h3_grpc_transport_resolve_calls(streaming);
    assert_eq!(
        streaming_resolves.len(),
        1,
        "the streaming path must resolve a transport for its selected target"
    );
    let streaming_resolve = streaming_resolves[0];
    assert!(
        streaming_resolve.contains("current_target.as_deref()"),
        "the streaming path must pass the selected target into transport resolution"
    );
    assert!(
        streaming_resolve.contains("ctx.peer_spiffe_id.as_ref()"),
        "the streaming path must preserve the authenticated frontend identity when resolving transport"
    );
    assert!(
        streaming.contains("&grpc_transport,"),
        "the streaming dispatch must dial through the resolved transport"
    );

    for (path, body) in [("buffered", buffered), ("streaming", streaming)] {
        assert!(
            !body.contains("&state.grpc_pool"),
            "the {path} H3→gRPC path must not hand the direct-dial pool to a dispatch call — \
             that reintroduces the unauthenticated mesh bypass"
        );
        assert!(
            body.contains("write_grpc_error_for_request(")
                && body.contains("grpc_proxy::grpc_status::UNAVAILABLE"),
            "the {path} H3→gRPC path must still fail closed with gRPC UNAVAILABLE when no \
             dispatchable transport exists"
        );
        assert!(
            body.contains("transport_error.diagnostic().as_str()") && body.contains("diagnostic,"),
            "the {path} H3→gRPC refusal warning must expose the redacted field/contract \
             diagnostic category (issue #3284)"
        );
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Issue #3283 — full bidirectional gRPC streaming on native H3 backends.
//
// The native-H3 gRPC relay used to drain the client request stream and FIN the
// backend send side BEFORE reading response headers, so a bidi RPC whose server
// answers before the client half-closes could not progress. These pin the duplex
// structure that replaced it: both ends are `split()`, the request direction runs
// in its own cancellable pump, and the response relay owns the RPC outcome.
// ════════════════════════════════════════════════════════════════════════════

/// Bound the native-H3 gRPC relay's source region.
fn native_h3_grpc_relay_source() -> &'static str {
    let src = include_str!("../../../src/http3/server.rs");
    src.split("async fn dispatch_grpc_native_h3(")
        .nth(1)
        .expect("native H3 gRPC relay")
        .split("async fn log_h3_grpc_transaction(")
        .next()
        .expect("bounded native H3 gRPC relay")
}

#[test]
fn h3_native_grpc_relay_is_full_duplex_not_drain_then_read() {
    let relay = native_h3_grpc_relay_source();

    // The drain-then-read pool entry points FIN the backend send side before
    // `recv_response`, which is exactly what a bidi RPC cannot tolerate.
    for forbidden in [
        "request_streaming_body(",
        "request_with_target_streaming_body(",
    ] {
        assert!(
            !relay.contains(forbidden),
            "regression: the native H3 gRPC relay must NOT drain the request \
             before reading the response ({forbidden})"
        );
    }

    // Both ends are split so the two directions are independently drivable.
    assert!(
        relay.contains("stream.split()"),
        "the frontend QUIC stream must be split for concurrent upload + response"
    );
    assert!(
        relay.contains("open_bidi_backend_stream(")
            && relay.contains("open_bidi_backend_stream_with_target("),
        "the backend stream must be opened through the split (bidi) pool entry"
    );
    assert!(
        relay.contains("tokio::spawn(run_h3_grpc_upload_pump("),
        "the request direction must run in its own task"
    );

    // The response header wait must be concurrent with the upload, not after it.
    let spawn_at = relay
        .find("tokio::spawn(run_h3_grpc_upload_pump(")
        .expect("upload pump spawn");
    let header_at = relay
        .find("recv_h3_backend_response_head(")
        .expect("response header wait");
    assert!(
        spawn_at < header_at,
        "the upload pump must already be running when the relay waits on \
         response headers, or the RPC is still drain-then-read"
    );
}

/// Pump retirement must be true BY CONSTRUCTION, not by counting call sites.
///
/// Counting literal `retire(...)` calls cannot see the exits that matter most:
/// a structural early return (the `?` on the response builder, or a new one
/// added later) leaves no call to count, yet it is exactly the shape that would
/// detach the spawned task and drop the only shutdown notifier. So this asserts
/// the ownership invariant instead — the `JoinHandle` is moved into an RAII
/// guard at the spawn site and never lives as a bare local, and the guard's
/// `Drop` cancels and aborts it.
#[test]
fn h3_native_grpc_relay_retires_its_upload_pump_on_every_exit() {
    let relay = native_h3_grpc_relay_source();

    // The handle is never bound to a local: it is constructed inside the guard's
    // constructor, so there is no window in which an early return could drop it
    // unretired.
    assert!(
        relay.contains("H3GrpcUploadPumpGuard::new(")
            && relay.contains("tokio::spawn(run_h3_grpc_upload_pump("),
        "the pump handle must be handed to the RAII guard at the spawn site"
    );
    let guard_at = relay
        .find("H3GrpcUploadPumpGuard::new(")
        .expect("pump guard construction");
    let spawn_at = relay
        .find("tokio::spawn(run_h3_grpc_upload_pump(")
        .expect("pump spawn");
    assert!(
        guard_at < spawn_at,
        "the spawn must be an argument of the guard constructor, so the handle \
         is owned by the guard from the instant it exists"
    );
    assert!(
        !relay.contains("let pump = tokio::spawn("),
        "regression: a bare JoinHandle local can be leaked by a structural `?` \
         early return, detaching the pump and dropping its shutdown notifier"
    );

    // Ordinary exits still retire explicitly, so the ORDERING contract holds:
    // publish cancellation, join, and only then read the final byte count.
    // A floor, not an exact count — adding another explicitly-retired exit must
    // not require re-tuning this test.
    assert!(
        relay.matches("pump_guard.retire().await").count() >= 5,
        "the ordinary exits (header-wait failure, oversized response, \
         after_proxy reject, header-write failure, completion) must retire \
         explicitly so the join happens before the RPC's bookkeeping"
    );

    // And the backstop itself: Drop must both cancel and abort, or a structural
    // early return would leave the task running.
    let src = include_str!("../../../src/http3/server.rs");
    let guard_drop = src
        .split("impl Drop for H3GrpcUploadPumpGuard {")
        .nth(1)
        .expect("pump guard Drop impl")
        .split("\n}\n")
        .next()
        .expect("bounded pump guard Drop impl");
    assert!(
        guard_drop.contains("self.shutdown.notify_one()") && guard_drop.contains("pump.abort()"),
        "Drop must publish cancellation AND abort, so no exit can leave the \
         pump running: {guard_drop}"
    );
    let retire = src
        .split("async fn retire(mut self)")
        .nth(1)
        .expect("pump guard retire")
        .split("\n    }\n")
        .next()
        .expect("bounded pump guard retire");
    assert!(
        retire.contains("self.pump.take()"),
        "retire must take the handle so Drop cannot retire it a second time"
    );
}

/// The cross-protocol H3→H2 gRPC upload pump ends the same way as the native
/// one: `pump_shutdown` can cancel `recv_half.recv_data()` /
/// `recv_half.recv_trailers()` mid-poll (the ordinary shape of a bidi RPC whose
/// backend answers before the client half-closes), and the receive half must
/// then be closed with `STOP_SENDING(H3_NO_ERROR)` — NOT by dropping it, which
/// emits `STOP_SENDING(0)`, a code outside the HTTP/3 error space, and makes
/// clients log a spurious remote reset on a successful RPC.
///
/// Reaching the parked `quinn::RecvStream` for that call is what the vendored
/// `h3-quinn` patch provides; stock 0.0.10 would `unwrap` a `None` and abort the
/// process under `panic = "abort"`. See
/// `docs/upstream-h3-quinn-patches/001-stop-sending-during-in-flight-read/`.
///
/// Cancellation is NOT weakened and the request body stays bounded: every await
/// still races `pump_shutdown`, and the backend upload is still reset through
/// `backend_upload_cancelled` rather than cleanly truncated.
#[test]
fn h3_cross_protocol_grpc_upload_pump_halts_the_frontend_receive_half_gracefully() {
    let src = include_str!("../../../src/http3/cross_protocol.rs");
    let pump = src
        .split("pub(crate) async fn dispatch_grpc_streaming")
        .nth(1)
        .expect("cross-protocol streaming gRPC dispatch")
        .split("let mut pump_shutdown_guard = H3RequestPumpShutdownGuard::new(")
        .next()
        .expect("bounded cross-protocol request-upload pump");

    assert!(
        pump.contains("halt_request_body(&mut recv_half)"),
        "the post-loop STOP_SENDING(H3_NO_ERROR) must be unconditional, \
         including after a receive cancelled mid-poll"
    );
    assert!(
        !pump.contains("halt_request_body_if_idle("),
        "regression: gating the halt on an idle receive half silently downgrades \
         the headline bidi exit to quinn's STOP_SENDING(0)"
    );

    // Cancellation itself is untouched: every await still races the shutdown
    // signal, and a cancelled upload still RSTs the backend request direction.
    let cancellable = pump.matches("pump_shutdown_signal.notified()").count();
    assert_eq!(cancellable, 6, "every pump await must remain cancellable");
    for cancellable_await in ["recv_half.recv_data()", "recv_half.recv_trailers()"] {
        let Some(at) = pump.find(cancellable_await) else {
            panic!("cross-protocol pump must forward {cancellable_await}");
        };
        let Some(arm_start) = pump[..at].rfind("tokio::select! {") else {
            panic!("each frontend receive must sit in a shutdown select");
        };
        assert!(
            pump[arm_start..at].contains("pump_shutdown_signal.notified()"),
            "the select racing {cancellable_await} must carry the shutdown arm"
        );
    }
    assert!(
        pump.contains("pump_backend_cancelled.store(true, Ordering::Release)"),
        "a cancelled upload must still reset the backend request direction \
         instead of a clean END_STREAM"
    );
}

/// The vendored `h3-quinn` shape both request-upload pumps depend on.
///
/// Stock 0.0.10 moves its `quinn::RecvStream` into a `ReusableBoxFuture` while a
/// read is pending and leaves its own field as `None`, so `stop_sending` unwraps
/// that `None`. Every graceful `STOP_SENDING(H3_NO_ERROR)` after a cancelled
/// frontend receive rests on the vendored crate keeping the stream reachable, so
/// pin the shape here: a silent revert to the upstream form would turn the
/// headline bidi path into a process abort.
#[test]
fn h3_quinn_vendored_recv_stream_can_stop_sending_during_an_in_flight_read() {
    let src = include_str!("../../../vendor/h3-quinn-0.0.10-ferrum-patched/src/lib.rs");
    let recv_stream = src
        .split("pub struct RecvStream {")
        .nth(1)
        .expect("vendored h3-quinn RecvStream")
        .split("\nfn convert_read_error_to_stream_error(")
        .next()
        .expect("bounded vendored h3-quinn RecvStream");

    assert!(
        recv_stream.starts_with("\n    stream: quinn::RecvStream,\n}"),
        "the quinn::RecvStream must be owned INLINE, not behind an Option that \
         a pending read empties: {}",
        &recv_stream[..recv_stream.len().min(120)]
    );
    assert!(
        !recv_stream.contains("ReusableBoxFuture"),
        "regression: parking the stream inside a reusable boxed future is what \
         makes stop_sending unreachable mid-read"
    );
    let stop_sending = recv_stream
        .split("fn stop_sending(&mut self, error_code: u64) {")
        .nth(1)
        .expect("vendored h3-quinn stop_sending")
        .split("\n    }")
        .next()
        .expect("bounded vendored h3-quinn stop_sending");
    assert!(
        !stop_sending.contains("unwrap()"),
        "stop_sending must be total — no Option::unwrap that a pending read can \
         trip: {stop_sending}"
    );
    assert!(
        recv_stream.contains("self.stream.read_chunk(usize::MAX, true)")
            && recv_stream.contains("pin!("),
        "poll_data must build the (cancel-safe) read_chunk future per poll so \
         the stream stays borrowed rather than moved"
    );
}

/// Bound the native-H3 gRPC request-upload pump's source region.
fn native_h3_grpc_upload_pump_source() -> &'static str {
    let src = include_str!("../../../src/http3/server.rs");
    src.split("async fn run_h3_grpc_upload_pump(")
        .nth(1)
        .expect("native H3 gRPC upload pump")
        .split("\n/// Immutable per-request context")
        .next()
        .expect("bounded native H3 gRPC upload pump")
}

fn native_h3_grpc_upload_await_helper_source() -> &'static str {
    let src = include_str!("../../../src/http3/server.rs");
    // Match the helper by name, then take the item through the next type
    // boundary. The signature may be generic (`<F>(...)`) or not (`(...)`);
    // pinning `name(` would miss a generic declaration the way `name<` would
    // miss a non-generic one.
    let Some(name_at) = src.find("fn h3_grpc_upload_await_until_authorization") else {
        panic!("native H3 gRPC upload-pump authorization helper");
    };
    src[name_at..]
        .split("impl H3UploadPumpExit")
        .next()
        .expect("bounded native H3 gRPC upload-pump authorization helper")
}

#[test]
fn h3_native_grpc_upload_pump_awaits_are_all_cancellable() {
    let pump = native_h3_grpc_upload_pump_source();
    let helper = native_h3_grpc_upload_await_helper_source();

    // Every await the pump performs races shutdown and the admitted
    // authorization plan through the shared helper: frontend DATA, backend
    // DATA, frontend trailers, backend trailers, and the backend FIN.
    assert_eq!(
        pump.matches("h3_grpc_upload_await_until_authorization(")
            .count(),
        5,
        "each pump await must race shutdown and the authorization plan"
    );
    assert!(
        helper.contains("shutdown.notified()"),
        "the helper must remain cancellable through the pump shutdown signal"
    );
    assert!(
        helper.contains("biased;") && helper.contains("tokio::time::sleep_until(plan.at)"),
        "the helper must race authorization first so an exact-deadline tie fails closed"
    );
    assert!(
        helper.contains("if tokio::time::Instant::now() >= plan.at"),
        "an already-elapsed plan must never poll the inner receive or commit"
    );
    for awaited in [
        "frontend_recv.recv_data()",
        "backend_send.send_data(data)",
        "frontend_recv.recv_trailers()",
        "backend_send.send_trailers(trailers)",
        "backend_send.finish()",
    ] {
        assert!(pump.contains(awaited), "pump must forward {awaited}");
    }
    // Four of the five cancellation points record the exit; the fifth (the
    // backend FIN) has nothing after it, and leaving the upload incomplete is
    // precisely what makes teardown RESET the backend request direction.
    assert_eq!(
        pump.matches("H3UploadPumpExit::Cancelled").count(),
        4,
        "every cancellation point that is followed by more backend work must \
         record the Cancelled exit, so teardown never FINishes a backend whose \
         RPC is already over"
    );
    assert!(
        pump.contains("stop_stream(h3::error::Code::H3_REQUEST_CANCELLED)"),
        "an upload that never reached a clean FIN must RESET the backend \
         request direction rather than leave it half-open"
    );
    assert!(
        pump.contains("sanitize_backend_request_trailers(&mut trailers)"),
        "client trailing metadata must be sanitized before it reaches the backend"
    );
    assert!(
        pump.contains("max_request_body_size"),
        "the pump must enforce the effective gRPC receive ceiling incrementally"
    );
    assert!(
        pump.contains("H3GrpcUploadFault::AuthorizationExpired("),
        "authorization expiry must publish a typed fault rather than a clean backend FIN"
    );
}

/// The headline bidi exit — the relay retires a pump parked in `recv_data`
/// because the backend's terminal trailers arrived — must still close the
/// client's request direction with `STOP_SENDING(H3_NO_ERROR)`.
///
/// Dropping the receive half instead falls through to
/// `quinn::RecvStream::drop`, which emits `STOP_SENDING(0)`; `0x0` is not an
/// HTTP/3 error code (RFC 9114 §8.1 defines `H3_NO_ERROR = 0x0100`), so clients
/// log a spurious remote reset on an RPC that SUCCEEDED. Reaching the stream
/// mid-read is what the vendored `h3-quinn` patch provides — pinned by
/// `h3_quinn_vendored_recv_stream_can_stop_sending_during_an_in_flight_read`.
#[test]
fn h3_native_grpc_upload_pump_halts_the_frontend_receive_half_gracefully() {
    let pump = native_h3_grpc_upload_pump_source();
    assert!(
        pump.contains("halt_request_body(&mut frontend_recv)"),
        "the pump must always emit the graceful STOP_SENDING(H3_NO_ERROR)"
    );
    assert!(
        !pump.contains("halt_request_body_if_idle("),
        "regression: gating the halt on an idle receive half silently downgrades \
         the headline bidi exit to quinn's STOP_SENDING(0)"
    );
}

/// The pump publishes `blocked_on_backend` around BACKEND awaits only. Earlier
/// client progress is deliberately not shared into health attribution because
/// it is attacker-controlled and says nothing about whether request EOF is owed.
#[test]
fn h3_native_grpc_upload_pump_publishes_only_backend_blocked_state() {
    let pump = native_h3_grpc_upload_pump_source();

    assert!(
        !pump.contains("note_progress") && !pump.contains("progress_at_wait_start"),
        "client-controlled historical progress must not be promoted into shared \
         backend health state"
    );

    // `blocked_on_backend` must be set true only immediately before a backend
    // await, and cleared on every path out of it — including the cancellation
    // arm — so a stale `true` cannot blame the backend for a later expiry.
    let set_true = pump.matches("upload.set_blocked_on_backend(true)").count();
    let set_false = pump.matches("upload.set_blocked_on_backend(false)").count();
    assert_eq!(
        set_true, 3,
        "the backend send_data / send_trailers / finish awaits are the only \
         places the gateway is blocked on the backend"
    );
    let expected_clears = set_true + 1;
    assert_eq!(
        set_false, expected_clears,
        "every backend await must clear the flag afterwards, plus once inside \
         the send_data cancellation arm that breaks out of the loop"
    );
    for backend_await in [
        "backend_send.send_data(data)",
        "backend_send.send_trailers(trailers)",
        "backend_send.finish()",
    ] {
        let at = pump
            .find(backend_await)
            .unwrap_or_else(|| panic!("pump must forward {backend_await}"));
        let arm_start = pump[..at]
            .rfind("h3_grpc_upload_await_until_authorization(")
            .unwrap_or_else(|| panic!("{backend_await} must sit in the authorization helper"));
        let prefix = &pump[..arm_start];
        let last_true = prefix
            .rfind("upload.set_blocked_on_backend(true);")
            .unwrap_or_else(|| {
                panic!("{backend_await} must be preceded by the blocked-on-backend publish")
            });
        let last_false = prefix.rfind("upload.set_blocked_on_backend(false);");
        assert!(
            last_false.is_none_or(|false_at| false_at < last_true),
            "the most recent blocked-on-backend publish before {backend_await} \
             must be `true`, or an expiry while it is parked there would be \
             charged to the client"
        );
    }
}

#[test]
fn h3_native_grpc_upload_fault_arm_cannot_lose_to_backend_data() {
    let relay = native_h3_grpc_relay_source();
    let response_loop = relay
        .split("'outer: loop")
        .nth(1)
        .expect("native response loop");
    let select = response_loop
        .split("tokio::select! {")
        .nth(1)
        .expect("native response select");
    let deadline = select
        .find("_ = &mut grpc_deadline_sleep")
        .expect("absolute deadline arm");
    let fault = select
        .find("fault = &mut upload_fault_wait")
        .expect("terminating upload-fault arm");
    let data = select
        .find("backend_recv.recv_data()")
        .expect("backend DATA arm");
    assert!(select[..deadline].contains("biased;"));
    assert!(
        deadline < fault && fault < data,
        "a terminating upload fault must not lose a race to a \
         simultaneously-ready backend DATA frame"
    );
    // Same truncation rule as the deadline arm: never cap a partially-written
    // length-prefixed gRPC message with clean trailers.
    let fault_arm = &select[fault..data];
    assert!(fault_arm.contains("grpc_deadline_can_send_terminal_status("));
    assert!(fault_arm.contains("abort_response_stream(&mut send_half)"));
    assert!(
        fault_arm.contains("body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect)"),
        "a client-caused upload fault must stay neutral for backend health"
    );
    assert!(
        !fault_arm.contains("grpc_trailer_status = Some("),
        "a gateway-authored fault status must never train the adaptive limiter \
         as if the backend had returned it"
    );
}

/// Reaching backend DATA EOS does not retire the concurrent request upload.
/// The terminal trailer wait must therefore keep racing the same terminating
/// upload-fault future; otherwise a malformed/oversized/aborted client upload
/// can pin the RPC behind a backend that never supplies trailers.
#[test]
fn h3_native_grpc_trailer_wait_stays_in_the_upload_cancellation_domain() {
    let relay = native_h3_grpc_relay_source();
    let trailer_phase = relay
        .split("let trailer_fut = async {")
        .nth(1)
        .expect("native gRPC trailer wait future")
        .split("let trailer_wait_result =")
        .next()
        .expect("bounded native gRPC trailer wait future");
    let fault = trailer_phase
        .find("fault = &mut upload_fault_wait")
        .expect("terminal trailer wait must observe terminating upload faults");
    let trailers = trailer_phase
        .find("backend_recv.recv_trailers()")
        .expect("terminal trailer wait must still read backend trailers");
    assert!(trailer_phase[..fault].contains("biased;"));
    assert!(
        fault < trailers,
        "a simultaneous client-upload fault must win over backend trailers"
    );

    let fault_arm = relay
        .split("let trailers_result = match trailer_wait_result {")
        .nth(1)
        .expect("terminal trailer wait outcome")
        .split("match trailers_result {")
        .next()
        .expect("bounded terminal trailer upload-fault arm");
    assert!(fault_arm.contains("fault.grpc_signal()"));
    assert!(fault_arm.contains("grpc_deadline_can_send_terminal_status("));
    assert!(fault_arm.contains("abort_response_stream(&mut send_half)"));
    assert!(
        fault_arm.contains("body_error_class = Some(crate::retry::ErrorClass::ClientDisconnect)")
    );
    assert!(
        !fault_arm.contains("grpc_trailer_status = Some("),
        "a gateway-authored upload-fault status must not train adaptive concurrency"
    );
}

/// Isolate the two non-authorization upload-fault terminal writers. A broad
/// trailer-phase substring for `downstream_write_bound.deadline()` is satisfied
/// by the neighboring authorization and backend-trailer FIN calls, so a
/// regression that rebinds either of these gateway-authored trailer/FIN writes
/// to the optional client `grpc_deadline_at` would otherwise stay green.
#[test]
fn h3_native_grpc_non_auth_upload_fault_terminals_use_the_composed_write_bound() {
    let relay = native_h3_grpc_relay_source();

    let response_loop = relay
        .split("'outer: loop")
        .nth(1)
        .expect("native response loop");
    let select = response_loop
        .split("tokio::select! {")
        .nth(1)
        .expect("native response select");
    let fault = select
        .find("fault = &mut upload_fault_wait")
        .expect("terminating upload-fault arm");
    let data = select
        .find("backend_recv.recv_data()")
        .expect("backend DATA arm");
    let mid_response_non_auth = select[fault..data]
        .split("let (fault_status, fault_message) = fault.grpc_signal();")
        .nth(1)
        .expect("mid-response non-authorization upload-fault branch");
    assert_non_auth_upload_fault_terminal_uses_composed_bound(
        mid_response_non_auth,
        "mid-response non-authorization upload-fault terminal",
    );

    let trailer_wait_non_auth = relay
        .split("let trailers_result = match trailer_wait_result {")
        .nth(1)
        .expect("terminal trailer wait outcome")
        .split("match trailers_result {")
        .next()
        .expect("bounded terminal trailer upload-fault arm")
        .split("Err(fault) => {")
        .nth(1)
        .expect("trailer-wait non-authorization upload-fault branch");
    assert_non_auth_upload_fault_terminal_uses_composed_bound(
        trailer_wait_non_auth,
        "trailer-wait non-authorization upload-fault terminal",
    );
}

fn assert_non_auth_upload_fault_terminal_uses_composed_bound(arm: &str, context: &str) {
    assert!(
        arm.contains("fault_status") && arm.contains("fault_message"),
        "{context} must be the gateway-authored non-authorization fault writer"
    );
    assert_eq!(
        arm.matches("send_h3_grpc_terminal_trailers(").count(),
        1,
        "{context} must have exactly one terminal trailer/FIN writer"
    );
    let call = arm
        .split("send_h3_grpc_terminal_trailers(")
        .nth(1)
        .expect("terminal trailer call")
        .split(".await")
        .next()
        .expect("awaited terminal trailer write");
    assert!(
        call.contains("downstream_write_bound.deadline()"),
        "{context} must bound send_trailers/finish by the composed downstream write bound"
    );
    assert!(
        !call.contains("grpc_deadline_at"),
        "{context} must not regress to the optional client grpc-timeout as the sole bound"
    );
}

/// Every native-H3 gRPC failure/reject path writes the client's response BEFORE
/// it tears anything down.
///
/// Pre-split (the backend stream never opened) the relay still owns the whole
/// bidirectional stream, and its receive half has provably never been polled —
/// the opener writes only request HEADERS — so the graceful
/// `STOP_SENDING(H3_NO_ERROR)` belongs there, after the error write, exactly as
/// the unsplit reject writers do it. Post-split the same ordering applies to
/// pump retirement: halting or resetting the client's request direction ahead of
/// the response lets a client observe the reset instead of the gRPC status.
#[test]
fn h3_native_grpc_failure_paths_write_the_response_before_tearing_down() {
    let relay = native_h3_grpc_relay_source();

    // Pre-split: response, then the graceful halt, then the bookkeeping.
    let pre_split = relay
        .split("let backend = match opened {")
        .nth(1)
        .expect("pre-split backend-open failure arm")
        .split("// ── Phase 2")
        .next()
        .expect("bounded pre-split failure arm");
    // Two pre-split arms reach a client-visible terminal: the authorization
    // terminal and the ordinary dispatch failure. Each is bounded by the
    // `return Ok(());` that closes it, so an arm's ordering is checked against
    // its OWN halt and record rather than against the first one in the block.
    for write in [
        "send_h3_grpc_authorization_expired_terminal(",
        "send_failed_h3_grpc_dispatch_error(&dispatch_env, &mut stream, error)",
    ] {
        let arm = pre_split
            .split_inclusive("return Ok(());")
            .find(|arm| arm.contains(write))
            .unwrap_or_else(|| panic!("pre-split arm writing `{write}` must remain present"));
        let send_at = arm
            .find(write)
            .expect("pre-split failure must write the trailers-only gRPC error");
        let halt_at = arm
            .find("halt_request_body(&mut stream)")
            .expect("pre-split failure must halt the unsplit receive half gracefully");
        let record_at = arm
            .find("record_failed_h3_grpc_dispatch(")
            .expect("pre-split failure must record the outcome");
        assert!(
            send_at < halt_at && halt_at < record_at,
            "pre-split ordering must be response -> STOP_SENDING(H3_NO_ERROR) -> record"
        );
    }

    // Post-split: each ordinary failure/reject arm writes, then retires. Arms
    // are bounded by the `return Ok(());` that closes the previous one, so a
    // retire belonging to an earlier arm cannot satisfy (or break) the check.
    let assert_writes_then_retires = |write: &str, what: &str| {
        let at = relay
            .find(write)
            .unwrap_or_else(|| panic!("{what} must write a client response"));
        let arm_start = relay[..at]
            .rfind("return Ok(());")
            .map_or(0, |i| i + "return Ok(());".len());
        assert!(
            !relay[arm_start..at].contains("pump_guard.retire().await"),
            "{what} must not retire the pump before writing the client response \
             — the client would see its request direction torn down first"
        );
        let tail = &relay[at..];
        let retire_at = tail
            .find("pump_guard.retire().await")
            .unwrap_or_else(|| panic!("{what} must retire the upload pump"));
        let return_at = tail
            .find("return Ok(());")
            .unwrap_or_else(|| panic!("{what} must return after recording"));
        assert!(
            retire_at < return_at,
            "{what} must retire the pump within its own arm, after the write"
        );
    };
    assert_writes_then_retires(
        "send_failed_h3_grpc_dispatch_error(&dispatch_env, &mut send_half, error)",
        "response-header wait failure",
    );
    assert_writes_then_retires(
        "\"Backend response exceeds maximum size\"",
        "oversized backend response",
    );
    assert_writes_then_retires("send_h3_grpc_reject_trailers_only(", "after_proxy reject");
}

#[test]
fn h3_native_grpc_terminal_writes_cannot_pin_the_upload_pump() {
    let source = include_str!("../../../src/http3/server.rs");
    let relay = native_h3_grpc_relay_source();
    let failure_writer = source
        .split("async fn send_failed_h3_grpc_dispatch_error<S>(")
        .nth(1)
        .expect("native H3 gRPC dispatch-failure writer")
        .split("async fn record_failed_h3_grpc_dispatch(")
        .next()
        .expect("bounded native H3 gRPC dispatch-failure writer");
    let grace_helper = source
        .split("async fn await_h3_grpc_terminal_write_with_grace<F, E>(")
        .nth(1)
        .expect("native H3 gRPC terminal-write grace helper")
        .split("async fn send_h3_grpc_terminal_trailers<S>(")
        .next()
        .expect("bounded native H3 gRPC terminal-write grace helper");

    assert!(failure_writer.contains("await_h3_grpc_terminal_write_with_grace("));
    assert!(failure_writer.contains("abort_response_stream(stream)"));
    assert_eq!(
        relay
            .matches("await_h3_grpc_terminal_write_with_grace(")
            .count(),
        3,
        "the oversized-response, after_proxy and authorization-expiry terminal writes must all \
         be bounded before pump retirement"
    );
    assert!(
        relay
            .matches("abort_response_stream(&mut send_half)")
            .count()
            >= 2,
        "a failed or expired bounded terminal write must reset the response half"
    );
    assert!(grace_helper.contains("await_post_deadline_terminal_response_write(write)"));
}

#[test]
fn h3_native_grpc_bidi_open_is_pre_wire_and_splits() {
    let client = include_str!("../../../src/http3/client.rs");
    let opener = client
        .split("async fn do_open_bidi_backend_stream(")
        .nth(1)
        .expect("bidi opener")
        .split("/// Pooled entry point")
        .next()
        .expect("bounded bidi opener");
    assert!(
        opener.contains("stream.split()"),
        "the backend stream must be handed back already split"
    );
    for forbidden in ["send_data(", "finish()", "recv_response("] {
        assert!(
            !opener.contains(forbidden),
            "opening must stay pre-wire — no body write and no response read ({forbidden})"
        );
    }
    assert!(
        opener.contains("build_h3_backend_request_preserving_te("),
        "the duplex opener must share the `te: trailers` header rule with the \
         drain-then-read streaming path"
    );
}

#[test]
fn h3_native_grpc_upload_fault_signalling_matches_the_h2_bridge() {
    use ferrum_edge::_test_support::{
        H3GrpcUploadFaultKind, h3_grpc_upload_fault_signal_for_test,
        h3_grpc_upload_fault_terminates_rpc_for_test,
    };

    assert_eq!(
        h3_grpc_upload_fault_signal_for_test(H3GrpcUploadFaultKind::Oversize),
        Some((8, "Request body exceeds maximum size")),
        "an oversized client upload is RESOURCE_EXHAUSTED"
    );
    assert_eq!(
        h3_grpc_upload_fault_signal_for_test(H3GrpcUploadFaultKind::MalformedTrailers),
        Some((3, "Malformed request trailers")),
        "undecodable trailing metadata is INVALID_ARGUMENT, not a server outage"
    );
    assert_eq!(
        h3_grpc_upload_fault_signal_for_test(H3GrpcUploadFaultKind::ClientAbort),
        Some((14, "Service unavailable")),
    );
    assert_eq!(
        h3_grpc_upload_fault_signal_for_test(H3GrpcUploadFaultKind::AuthorizationExpired),
        Some((16, "credential expired")),
        "an expired upload-pump authorization lifetime is UNAUTHENTICATED"
    );

    for terminating in [
        H3GrpcUploadFaultKind::ClientAbort,
        H3GrpcUploadFaultKind::MalformedTrailers,
        H3GrpcUploadFaultKind::Oversize,
        H3GrpcUploadFaultKind::AuthorizationExpired,
    ] {
        assert!(
            h3_grpc_upload_fault_terminates_rpc_for_test(terminating),
            "{terminating:?} must end the RPC"
        );
    }
    assert!(
        !h3_grpc_upload_fault_terminates_rpc_for_test(H3GrpcUploadFaultKind::BackendUploadHalted),
        "a gRPC server that stops reading the request once it has everything it \
         needs must NOT terminate a still-streaming response"
    );
    // A non-terminating fault has no client-visible signalling AT ALL, and the
    // type system says so: only `terminating()` mints a value carrying one, so
    // there is no dead `BackendUploadHalted` arm for a reader to mistake for a
    // live signalling decision.
    assert_eq!(
        h3_grpc_upload_fault_signal_for_test(H3GrpcUploadFaultKind::BackendUploadHalted),
        None,
        "a fault the response direction survives must not carry a gRPC status"
    );
    let src = include_str!("../../../src/http3/server.rs");
    let terminating_impl = src
        .split("impl H3GrpcTerminatingUploadFault {")
        .nth(1)
        .expect("terminating-fault impl")
        .split("\n}\n")
        .next()
        .expect("bounded terminating-fault impl");
    assert!(
        !terminating_impl.contains("BackendUploadHalted"),
        "the terminating-fault mappings must have no arm for the \
         non-terminating fault: {terminating_impl}"
    );
    assert!(
        terminating_impl.contains("fn as_pool_error("),
        "the pre-headers H3PoolError equivalence belongs to the proven-terminating \
         type, so its every arm is reachable"
    );
}

#[test]
fn h3_native_grpc_upload_fault_latches_the_first_observation() {
    use ferrum_edge::_test_support::{
        H3GrpcUploadFaultKind, h3_grpc_upload_fault_latches_first_for_test,
    };
    assert_eq!(
        h3_grpc_upload_fault_latches_first_for_test(
            H3GrpcUploadFaultKind::Oversize,
            H3GrpcUploadFaultKind::ClientAbort,
        ),
        H3GrpcUploadFaultKind::Oversize,
        "the first fault explains the RPC; a follow-on failure is its consequence"
    );
}

#[tokio::test]
async fn h3_native_grpc_terminating_upload_fault_wakes_the_relay() {
    use ferrum_edge::_test_support::{
        H3GrpcUploadFaultKind, h3_grpc_upload_fault_wakes_relay_for_test,
    };

    // Published BEFORE the relay ever polls the wait: `notify_one` stores a
    // permit, so the wakeup cannot be lost.
    assert!(
        h3_grpc_upload_fault_wakes_relay_for_test(H3GrpcUploadFaultKind::Oversize, true).await,
        "a fault latched before the wait is polled must still wake the relay"
    );
    assert!(
        h3_grpc_upload_fault_wakes_relay_for_test(H3GrpcUploadFaultKind::ClientAbort, false).await,
        "a fault latched while the relay waits must wake it"
    );
    assert!(
        h3_grpc_upload_fault_wakes_relay_for_test(
            H3GrpcUploadFaultKind::AuthorizationExpired,
            true
        )
        .await,
        "an authorization-expired upload fault must wake the response relay"
    );
    assert!(
        !h3_grpc_upload_fault_wakes_relay_for_test(
            H3GrpcUploadFaultKind::BackendUploadHalted,
            true
        )
        .await,
        "a non-terminating fault must leave the response relay streaming"
    );
}

/// A response-header wait that expires must be attributed by WHO the gateway was
/// waiting on, not by whether the client upload happened to be complete.
///
/// On the duplex relay an incomplete request can be either a healthy
/// bidirectional RPC or a client-streaming RPC whose backend legitimately waits
/// for request EOF. Earlier client progress cannot distinguish those cases: an
/// untrusted client can send one frame and then stall, so using that progress to
/// indict the backend would let the client poison shared health state.
#[test]
fn h3_native_grpc_header_wait_expiry_blames_the_party_it_waited_on() {
    use ferrum_edge::_test_support::{
        H3GrpcHeaderWaitScenario, H3GrpcUploadFaultKind,
        h3_grpc_header_wait_expiry_blames_backend_for_test as blames_backend,
    };

    // The backend is not even draining the upload it asked for.
    assert!(
        blames_backend(H3GrpcHeaderWaitScenario {
            blocked_on_backend: true,
            ..Default::default()
        }),
        "a pump parked on a backend write is waiting on the BACKEND"
    );

    // The backend closed the request direction itself and then never answered.
    assert!(
        blames_backend(H3GrpcHeaderWaitScenario {
            fault: Some(H3GrpcUploadFaultKind::BackendUploadHalted),
            ..Default::default()
        }),
        "a backend that stopped accepting the upload and then never sent HEADERS \
         is a dead backend, not a stalled client"
    );

    // The pre-duplex case still holds.
    assert!(
        blames_backend(H3GrpcHeaderWaitScenario {
            upload_complete: true,
            ..Default::default()
        }),
        "a completed upload leaves only the backend to wait on"
    );

    // Incomplete upload while parked on the frontend receive stays neutral. This
    // covers both a valid zero-message/trailers-only client-streaming RPC and a
    // client that sent one or more frames and then stopped without half-closing.
    assert!(
        !blames_backend(H3GrpcHeaderWaitScenario::default()),
        "a wait in which the client produced nothing is neutral for backend health"
    );

    // A terminating fault is client-caused even when the deadline ties with it.
    for client_fault in [
        H3GrpcUploadFaultKind::ClientAbort,
        H3GrpcUploadFaultKind::MalformedTrailers,
        H3GrpcUploadFaultKind::Oversize,
        H3GrpcUploadFaultKind::AuthorizationExpired,
    ] {
        assert!(
            !blames_backend(H3GrpcHeaderWaitScenario {
                fault: Some(client_fault),
                ..Default::default()
            }),
            "{client_fault:?} is client-caused and must stay health-neutral"
        );
    }
}

/// Historical client progress must not be used to blame the backend for a
/// response-header timeout: it is attacker-controlled and cannot distinguish a
/// bidirectional RPC from a client-streaming RPC waiting for request EOF.
#[test]
fn h3_native_grpc_header_wait_does_not_trust_client_progress() {
    let relay = native_h3_grpc_relay_source();
    assert!(
        !relay.contains("upload_progress_before_wait") && !relay.contains("upload.progress()"),
        "client-controlled historical progress must not drive backend health attribution"
    );
    let expiry = relay
        .split("await_deadline_first(dispatch_deadline_at, header_fut)")
        .nth(1)
        .expect("header-wait expiry arm")
        .split("let h3_resp = match head_result")
        .next()
        .expect("bounded header-wait expiry arm");
    assert!(
        expiry.contains("classify_h3_grpc_header_wait_expiry(&upload)"),
        "the expiry must be attributed through the current pump-owner classifier"
    );
    assert!(
        !expiry.contains("upload.is_complete()"),
        "the dispatch arm must use the centralized classifier rather than \
         re-implementing upload ownership ad hoc"
    );
}

#[test]
fn h3_native_grpc_trailer_phase_composes_the_authorization_plan() {
    let relay = native_h3_grpc_relay_source();
    let trailer = relay
        .split("if stream_done {")
        .nth(1)
        .expect("native H3 gRPC trailer phase")
        .split("pump_guard.retire().await")
        .next()
        .expect("bounded native H3 gRPC trailer phase");
    assert!(
        trailer.contains(
            "let trailer_bound = crate::proxy::auth_lifetime::ComposedAuthBound::compose("
        ),
        "the trailer wait must compose the captured authorization plan"
    );
    assert!(
        trailer.contains("trailer_bound.expired_authorization()"),
        "a withheld trailer must be attributed from the captured composition"
    );
    assert!(
        trailer.contains("await_deadline_first(trailer_wait_at, trailer_fut)"),
        "the trailer wait must refuse an already-elapsed composed bound before polling"
    );
    assert!(
        !trailer.contains("timeout_at(at, trailer_fut)"),
        "timeout_at polls the trailer future first"
    );
    assert!(
        trailer.contains("downstream_write_bound.deadline()"),
        "trailer and FIN writes must race the composed downstream bound"
    );
    assert!(
        trailer.contains("H3GrpcResponseFinish::DeadlineExceeded"),
        "parked trailer/FIN writes must remain observable as DeadlineExceeded"
    );
}

#[tokio::test(start_paused = true)]
async fn a_parked_h3_grpc_upload_commit_is_dropped_at_the_authorization_deadline() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use ferrum_edge::_test_support::{
        H3GrpcUploadAwaitOutcomeForTest, h3_grpc_upload_await_until_authorization_for_test,
    };
    use ferrum_edge::proxy::auth_lifetime::{StreamAuthDeadline, StreamAuthTermination};

    async fn gated_commit(
        release: tokio::sync::oneshot::Receiver<()>,
        emitted: Arc<AtomicBool>,
    ) -> &'static [u8] {
        let _ = release.await;
        emitted.store(true, Ordering::SeqCst);
        b"late"
    }

    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let emitted = Arc::new(AtomicBool::new(false));
    let emitted_commit = Arc::clone(&emitted);
    let plan = StreamAuthDeadline {
        at: tokio::time::Instant::now() + Duration::from_millis(20),
        termination: StreamAuthTermination::CredentialExpired,
    };
    let shutdown = tokio::sync::Notify::new();
    let raced = tokio::spawn(async move {
        h3_grpc_upload_await_until_authorization_for_test(
            Some(plan),
            &shutdown,
            gated_commit(release_rx, emitted_commit),
        )
        .await
    });
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(20)).await;
    let _ = release_tx.send(());
    assert_eq!(
        raced.await.expect("join"),
        H3GrpcUploadAwaitOutcomeForTest::AuthorizationExpired(
            StreamAuthTermination::CredentialExpired
        )
    );
    assert!(
        !emitted.load(Ordering::SeqCst),
        "a parked backend DATA/trailer/FIN commit must not run after expiry"
    );
}

#[tokio::test(start_paused = true)]
async fn an_already_elapsed_h3_grpc_upload_commit_never_polls() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use ferrum_edge::_test_support::{
        H3GrpcUploadAwaitOutcomeForTest, h3_grpc_upload_await_until_authorization_for_test,
    };
    use ferrum_edge::proxy::auth_lifetime::{StreamAuthDeadline, StreamAuthTermination};

    let plan = StreamAuthDeadline {
        at: tokio::time::Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(tokio::time::Instant::now),
        termination: StreamAuthTermination::CredentialExpired,
    };
    let polled = Arc::new(AtomicBool::new(false));
    let polled_commit = Arc::clone(&polled);
    let shutdown = tokio::sync::Notify::new();
    let outcome = h3_grpc_upload_await_until_authorization_for_test(
        Some(plan),
        &shutdown,
        std::future::poll_fn(move |_| {
            polled_commit.store(true, Ordering::SeqCst);
            std::task::Poll::Ready(b"late")
        }),
    )
    .await;
    assert_eq!(
        outcome,
        H3GrpcUploadAwaitOutcomeForTest::AuthorizationExpired(
            StreamAuthTermination::CredentialExpired
        )
    );
    assert!(
        !polled.load(Ordering::SeqCst),
        "an already-elapsed plan must not poll a ready backend commit"
    );
}

#[tokio::test(start_paused = true)]
async fn an_exact_tie_on_a_ready_h3_grpc_upload_commit_is_expiry_first() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use ferrum_edge::_test_support::{
        H3GrpcUploadAwaitOutcomeForTest, h3_grpc_upload_await_until_authorization_for_test,
    };
    use ferrum_edge::proxy::auth_lifetime::{StreamAuthDeadline, StreamAuthTermination};

    let plan = StreamAuthDeadline {
        at: tokio::time::Instant::now() + Duration::from_millis(0),
        termination: StreamAuthTermination::CredentialExpired,
    };
    let polled = Arc::new(AtomicBool::new(false));
    let polled_commit = Arc::clone(&polled);
    let shutdown = tokio::sync::Notify::new();
    let outcome = h3_grpc_upload_await_until_authorization_for_test(
        Some(plan),
        &shutdown,
        std::future::poll_fn(move |_| {
            polled_commit.store(true, Ordering::SeqCst);
            std::task::Poll::Ready(b"tie")
        }),
    )
    .await;
    assert_eq!(
        outcome,
        H3GrpcUploadAwaitOutcomeForTest::AuthorizationExpired(
            StreamAuthTermination::CredentialExpired
        )
    );
    assert!(
        !polled.load(Ordering::SeqCst),
        "an exact-deadline tie must not commit a simultaneously-ready backend byte"
    );
}

#[tokio::test(start_paused = true)]
async fn a_withheld_h3_grpc_trailer_beyond_authorization_is_attributed_to_auth() {
    use std::time::Duration;

    use ferrum_edge::proxy::auth_lifetime::{
        ComposedAuthBound, StreamAuthDeadline, StreamAuthTermination,
    };

    let plan = StreamAuthDeadline {
        at: tokio::time::Instant::now() + Duration::from_millis(20),
        termination: StreamAuthTermination::CredentialExpired,
    };
    let bound = ComposedAuthBound::compose(None, Some(plan));
    tokio::time::advance(Duration::from_millis(20)).await;
    assert_eq!(
        bound.expired_authorization(),
        Some(StreamAuthTermination::CredentialExpired),
        "a withheld trailer with no protocol bound belongs to authorization"
    );
}

#[tokio::test(start_paused = true)]
async fn a_parked_h3_grpc_trailer_write_expires_under_authorization() {
    use std::time::Duration;

    use ferrum_edge::proxy::auth_lifetime::{
        ComposedAuthBound, StreamAuthDeadline, StreamAuthTermination,
    };

    let plan = StreamAuthDeadline {
        at: tokio::time::Instant::now() + Duration::from_millis(20),
        termination: StreamAuthTermination::CredentialExpired,
    };
    let bound = ComposedAuthBound::compose(None, Some(plan));
    let deadline = bound
        .deadline()
        .expect("authorization supplies the write bound");
    let task = tokio::spawn(async move {
        ferrum_edge::_test_support::stalled_h3_response_write_expires_for_test(deadline).await
    });
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(20)).await;
    assert!(
        task.await.expect("join"),
        "a parked trailer/FIN write must not commit after authorization expiry"
    );
    tokio::time::advance(Duration::from_millis(1)).await;
    assert_eq!(
        bound.expired_authorization(),
        Some(StreamAuthTermination::CredentialExpired)
    );
}

#[test]
fn h3_native_grpc_zero_data_trailer_uses_the_message_safe_rule() {
    let util = include_str!("../../../src/http3/stream_util.rs");
    let helper = util
        .split("fn grpc_deadline_can_send_terminal_status")
        .nth(1)
        .expect("shared message-safe rule helper must remain present")
        .split("\npub(crate) async fn await_response_write_before_deadline")
        .next()
        .expect("bounded message-safe rule helper");
    assert!(
        helper.contains("bytes_streamed == 0"),
        "zero-DATA vs post-DATA trailer termination stays on the shared message-safe rule"
    );
    let relay = native_h3_grpc_relay_source();
    let trailer = relay
        .split("if stream_done {")
        .nth(1)
        .expect("native H3 gRPC trailer phase");
    assert!(
        trailer.contains("grpc_deadline_can_send_terminal_status("),
        "authorization trailer expiry must keep the zero-DATA vs post-DATA message-safe split"
    );
}

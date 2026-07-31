#[test]
fn h3_native_mesh_refusal_screens_plain_and_grpc_before_dispatch() {
    let src = include_str!("../../../src/http3/server.rs");
    let native_gate = src
        .find("let native_h3_direct_dispatch = use_native_h3_pool || use_native_h3_grpc;")
        .expect("native H3 direct-dispatch gate must remain explicit");
    let after_gate = &src[native_gate..];
    let refusal = after_gate
        .find("direct_http_mesh_transport_refusal(")
        .expect("native H3 dispatch must screen mesh transport refusal");
    let native_grpc = after_gate
        .find("if use_native_h3_grpc")
        .expect("native H3 gRPC dispatch branch must remain present");
    let native_plain_bridge_bypass = after_gate
        .find("if !use_native_h3_pool")
        .expect("native plain H3 bridge-bypass branch must remain present");

    assert!(
        refusal < native_grpc,
        "mesh-transport-tagged gRPC targets must fail closed before native H3 gRPC dispatch can dial the QUIC pool"
    );
    assert!(
        refusal < native_plain_bridge_bypass,
        "mesh-transport-tagged plain targets must fail closed before native H3 plain dispatch can bypass the bridge"
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
    assert!(terminal_dispatch.contains("collect_h3_request_body_with_deadline("));
    assert!(terminal_dispatch.contains("drain_h3_request_body("));
    // Ok(None): idle recv after a completed oversize drain — the flavor-aware
    // writer already halts after HEADERS; do not duplicate STOP_SENDING.
    // Read: client gone — halt, finalize cleanup, no response write.
    // TimedOut: mid-recv_data cancel — write under post-deadline grace with
    // halt_recv=false; STOP_SENDING would unwrap-abort h3-quinn's empty slot.
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
        "timed-out terminal upload must pass halt_recv=false after mid-recv cancel"
    );
    assert!(
        !timed_out.contains("halt_cancelled_h3_upload("),
        "timed-out mid-recv cancel must not STOP_SENDING the invalid receive slot"
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
    let replacement = cross_protocol
        .find("fn replace_buffered_grpc_response_with_deadline(")
        .expect("cross-protocol buffered gRPC replacement must remain present");
    let replacement = &cross_protocol[replacement..];
    assert!(replacement.contains("is_grpc_web_content_type(content_type)"));
    assert!(replacement.contains("replace_buffered_h3_response_with_grpc_deadline("));
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
        "timed-out bridge upload must skip STOP_SENDING after mid-recv cancel"
    );
    assert!(timed_out.contains("await_post_deadline_terminal_response_write("));
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

#[test]
fn native_h3_client_deadlines_remain_health_neutral() {
    let source = include_str!("../../../src/http3/server.rs");
    let body_deadline = source
        .find("_ = &mut grpc_deadline_sleep, if grpc_deadline_active && !stream_done =>")
        .expect("native H3 body deadline branch must remain present");
    let body_deadline = &source[body_deadline..];
    let body_end = body_deadline
        .find("chunk_result = h3_resp.recv_stream.recv_data()")
        .expect("native H3 body deadline branch must remain bounded");
    let body_deadline = &body_deadline[..body_end];
    assert_eq!(
        body_deadline
            .matches("Some(crate::retry::ErrorClass::ClientDisconnect)")
            .count(),
        3,
        "clean trailer, send failure, and post-DATA abort must all stay neutral"
    );
    assert!(!body_deadline.contains("ErrorClass::ReadWriteTimeout"));

    let trailer_deadline = source
        .find("Err(_) if trailer_timeout_is_deadline =>")
        .expect("native H3 trailer deadline branch must remain present");
    let trailer_deadline = &source[trailer_deadline..];
    let trailer_end = trailer_deadline
        .find("Err(_) =>")
        .expect("native H3 trailer deadline branch must remain bounded");
    let trailer_deadline = &trailer_deadline[..trailer_end];
    assert_eq!(
        trailer_deadline
            .matches("Some(crate::retry::ErrorClass::ClientDisconnect)")
            .count(),
        3,
        "clean trailer, send failure, and post-DATA abort must all stay neutral"
    );
    assert!(!trailer_deadline.contains("ErrorClass::ReadWriteTimeout"));
}

#[test]
fn h3_cross_protocol_streaming_grpc_consumes_deadline_and_read_bounds() {
    let source = include_str!("../../../src/http3/cross_protocol.rs");
    let handler = source
        .split("async fn handle_h3_grpc_streaming_response")
        .nth(1)
        .expect("H3 cross-protocol streaming gRPC response handler")
        .split("/// Mesh-transport fail-closed guard")
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
        2,
        "write-bound and select-loop deadlines must both use client-visible DATA"
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
    assert_eq!(
        server
            .matches("await_request_plugin_deadline_with_provenance(")
            .count(),
        5,
        "every native H3 request plugin phase must retain deadline provenance"
    );
    let writer = server
        .split("async fn send_h3_plugin_reject_flavor_aware(")
        .nth(1)
        .expect("native H3 plugin rejection writer must remain present")
        .split("/// Send a trailers-only gRPC error response over H3.")
        .next()
        .expect("native H3 plugin rejection deadline wrapper must remain bounded");
    assert!(writer.contains("ctx.gateway_deadline_response_selected()"));
    assert!(writer.contains("replace_buffered_h3_response_with_grpc_deadline("));
    // Already-selected gateway deadline rejections use the shared post-deadline
    // grace (not the expired absolute deadline). Grace expiry aborts the send
    // half without STOP_SENDING after a mid-recv cancel.
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
    assert!(
        !writer.contains("halt_request_body(stream)"),
        "post-cancel grace paths must not STOP_SENDING the invalid receive slot"
    );
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
            .matches("collect_request_body_with_deadline(")
            .count(),
        2,
        "limited and unlimited HTTP/3 upload buffering must share the deadline-aware collector"
    );
    assert_eq!(
        buffering
            .matches("Err(RequestBodyWaitError::DeadlineExceeded)")
            .count(),
        2
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
        .split("fn content_type_of(")
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
    assert!(relay.contains("await_downstream_grpc_write!(stream.send_data"));
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
        "an immediately-ready post-deadline rejection write must complete within the grace"
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
        "a flow-control-blocked post-deadline rejection write must not outlive the grace"
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
    assert!(!error_writer.contains("halt_request_body(stream)"));

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
        .split("Err(super::server::H3RequestBodyReadError::DeadlineExceeded) => {")
        .next()
        .expect("bounded timed-out bridge arm");
    assert!(timed_out.contains("await_post_deadline_terminal_response_write("));
    assert!(timed_out.contains("abort_response_stream(stream)"));
    assert!(!timed_out.contains("halt_request_body(stream)"));
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
        .find("h3_resp.recv_stream.recv_data()")
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
    let bridge = dispatch
        .split("let send_result = {")
        .nth(1)
        .expect("streaming upload/backend response race");
    let deadline = bridge
        .find("_ = &mut grpc_web_deadline")
        .expect("absolute gRPC-Web deadline arm");
    let response = bridge
        .find("result = &mut send_future")
        .expect("backend response-header arm");
    assert!(bridge[..deadline].contains("biased;"));
    assert!(
        deadline < response,
        "a simultaneous backend response must not outlive the RPC deadline"
    );
    assert!(bridge[deadline..response].contains("drop(pending_slot.take());"));
    assert!(bridge[deadline..response].contains("break None;"));
    assert!(bridge.contains("halt_request_body(stream);"));
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
            .matches("let client_result = match crate::plugins::await_grpc_deadline(")
            .count(),
        2,
        "both client acquisitions must use the absolute RPC deadline"
    );
    assert!(dispatch.contains("drop(pending_slot);"));
    assert!(dispatch.contains("halt_request_body(stream);"));
    assert!(dispatch.contains("record_plain_grpc_web_client_deadline("));
    assert!(dispatch.contains("write_plain_grpc_web_client_deadline("));
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
        .split("/// Mesh-transport fail-closed guard")
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

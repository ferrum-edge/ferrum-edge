//! Issue #6772: one terminal convention for a proven client-origin abort.
//!
//! A client that resets its request stream, sends STOP_SENDING, or loses its
//! connection before response headers are committed is recorded the same way
//! on every HTTP-family path: `499` in HTTP logs and request metrics, gRPC
//! `CANCELLED` (1) for native gRPC, the `ClientDisconnect` error class,
//! `client_disconnected`, and neutral backend health. The `499` is keyed on the
//! typed `ProvenClientAbort` evidence, never on `ErrorClass::ClientDisconnect`
//! alone, which also marks health-neutral deadlines and authorization-lifetime
//! terminals while the client is still connected.
//!
//! h3's error variants cannot be built outside the crate, so the per-path
//! keying is guarded structurally here. On-the-wire proof lives in
//! `functional_h3_drain_refusal_hooks_test.rs` (`h3_*_client_abort_*`).

use ferrum_edge::_test_support::{
    error_class_is_backend_failure_for_test, error_class_is_health_neutral_for_test,
    map_http_reject_status_to_grpc_status,
};
use ferrum_edge::plugins::TransactionSummary;
use ferrum_edge::proxy::client_abort::{
    CLIENT_ABORT_GRPC_STATUS, CLIENT_ABORT_HTTP_BODY, CLIENT_ABORT_MESSAGE,
    CLIENT_CLOSED_REQUEST_STATUS, PRE_HEADER_CLIENT_ABORT_TERMINAL, ProvenClientAbort,
};
use ferrum_edge::proxy::grpc_proxy::grpc_status;
use ferrum_edge::retry::ErrorClass;
use ferrum_edge::runtime_metrics::RuntimeMetrics;
use http::StatusCode;

const CLIENT_ABORT: &str = include_str!("../../../src/proxy/client_abort.rs");
const SERVER: &str = include_str!("../../../src/http3/server.rs");
const CLIENT: &str = include_str!("../../../src/http3/client.rs");
const CROSS_PROTOCOL: &str = include_str!("../../../src/http3/cross_protocol.rs");
const PROXY: &str = include_str!("../../../src/proxy/mod.rs");

/// `src` with every whitespace character removed, so a guard does not depend
/// on rustfmt's line breaks.
fn compact(src: &str) -> String {
    src.chars().filter(|c| !c.is_whitespace()).collect()
}

/// The text between `start` and the first `end` after it.
fn region<'a>(src: &'a str, start: &str, end: &str) -> &'a str {
    let after_start = src
        .split(start)
        .nth(1)
        .unwrap_or_else(|| panic!("missing {start:?}"));
    after_start
        .split(end)
        .next()
        .unwrap_or_else(|| panic!("unbounded region after {start:?}"))
}

// ── The shared terminal ────────────────────────────────────────────────────

#[test]
fn the_pre_header_client_abort_terminal_is_499_cancelled_client_disconnect() {
    assert_eq!(CLIENT_CLOSED_REQUEST_STATUS, 499);
    assert_eq!(CLIENT_ABORT_GRPC_STATUS, grpc_status::CANCELLED);
    assert_eq!(CLIENT_ABORT_MESSAGE, "Client disconnected");
    assert_eq!(CLIENT_ABORT_HTTP_BODY, r#"{"error":"Client disconnected"}"#);

    let terminal = PRE_HEADER_CLIENT_ABORT_TERMINAL;
    assert_eq!(terminal.http_status, 499);
    assert_eq!(terminal.grpc_status, 1, "CANCELLED, never UNAVAILABLE (14)");
    assert_ne!(terminal.grpc_status, grpc_status::UNAVAILABLE);
    assert_eq!(terminal.grpc_message, "Client disconnected");
    assert_eq!(terminal.error_class, ErrorClass::ClientDisconnect);
    assert!(terminal.client_disconnected);
}

#[test]
fn every_kind_of_client_abort_evidence_reaches_the_same_terminal() {
    for abort in [
        ProvenClientAbort::peer_gone_before_response_headers(),
        ProvenClientAbort::latched_upload_abort(),
    ] {
        assert_eq!(
            abort.pre_header_terminal(),
            PRE_HEADER_CLIENT_ABORT_TERMINAL
        );
    }
}

#[test]
fn the_http_and_grpc_vocabularies_map_onto_each_other() {
    // A `499` that reaches a gRPC terminal (an HTTP/3 reject, a gRPC-Web
    // translation) is the same cancellation.
    let client_closed = StatusCode::from_u16(CLIENT_CLOSED_REQUEST_STATUS).expect("499");
    assert_eq!(
        map_http_reject_status_to_grpc_status(client_closed),
        CLIENT_ABORT_GRPC_STATUS
    );
}

#[test]
fn a_client_abort_is_neutral_for_backend_health() {
    let class = PRE_HEADER_CLIENT_ABORT_TERMINAL.error_class;
    assert!(
        error_class_is_health_neutral_for_test(class),
        "circuit breaker, passive health, least-latency, and adaptive concurrency must skip it"
    );
    assert!(
        !error_class_is_backend_failure_for_test(class),
        "a client abort is never a post-wire backend failure"
    );
}

#[test]
fn a_client_abort_counts_exactly_one_disconnect() {
    let terminal = PRE_HEADER_CLIENT_ABORT_TERMINAL;
    let metrics = RuntimeMetrics::new();
    metrics.record_transaction(&TransactionSummary {
        proxy_id: Some("abort-http".to_string()),
        response_status_code: terminal.http_status,
        error_class: Some(terminal.error_class),
        body_error_class: Some(terminal.error_class),
        client_disconnected: terminal.client_disconnected,
        ..TransactionSummary::default()
    });
    assert_eq!(metrics.client_disconnects(), 1);
    assert_eq!(metrics.http_errors_by_class.len(), 1);
    assert_eq!(metrics.grpc_errors_by_class.len(), 0);

    // A native gRPC RPC rides on HTTP 200 and carries its CANCELLED status in
    // metadata; it files under the gRPC counters and still counts once.
    let mut metadata = std::collections::HashMap::new();
    metadata.insert("grpc_status".to_string(), terminal.grpc_status.to_string());
    metrics.record_transaction(&TransactionSummary {
        proxy_id: Some("abort-grpc".to_string()),
        response_status_code: 200,
        error_class: Some(terminal.error_class),
        client_disconnected: terminal.client_disconnected,
        metadata,
        ..TransactionSummary::default()
    });
    assert_eq!(metrics.client_disconnects(), 2);
    assert_eq!(metrics.grpc_errors_by_class.len(), 1);

    // A normal FIN: nothing counted.
    metrics.record_transaction(&TransactionSummary {
        proxy_id: Some("abort-http".to_string()),
        response_status_code: 200,
        body_completed: true,
        ..TransactionSummary::default()
    });
    assert_eq!(metrics.client_disconnects(), 2);
}

#[test]
fn the_499_is_defined_once_and_minted_only_from_client_evidence() {
    assert!(CLIENT_ABORT.contains("pub const CLIENT_CLOSED_REQUEST_STATUS: u16 = 499;"));
    // The H3 read-error evidence is the buffered drains' own predicate.
    assert!(CLIENT_ABORT.contains("h3_request_read_error_is_client_abort(error)"));
    // gRPC's 499 <-> CANCELLED mapping reads the same constant.
    let grpc = include_str!("../../../src/proxy/grpc_proxy.rs");
    assert!(
        compact(grpc).contains(
            "constCLIENT_CLOSED_REQUEST_STATUS:u16=crate::proxy::client_abort::CLIENT_CLOSED_REQUEST_STATUS;"
        )
    );
    // No error class is blanket-remapped to the client-abort status.
    for (name, src) in [
        ("server.rs", SERVER),
        ("cross_protocol.rs", CROSS_PROTOCOL),
        ("client.rs", CLIENT),
    ] {
        assert!(
            !compact(src).contains("ErrorClass::ClientDisconnect=>499"),
            "{name} must not map the ClientDisconnect class to 499"
        );
    }
}

// ── H1/H2 buffered intake ───────────────────────────────────────────────────

#[test]
fn h1_h2_buffered_upload_aborts_use_the_shared_constants() {
    let proxy = compact(PROXY);
    assert!(
        proxy
            .matches("record_request(&state,client_abort::CLIENT_CLOSED_REQUEST_STATUS);")
            .count()
            >= 4,
        "every H1/H2 buffered client-disconnect arm records the shared 499"
    );
    assert!(proxy.contains("ifstatus.as_u16()==client_abort::CLIENT_CLOSED_REQUEST_STATUS{"));
}

// ── Native HTTP/3 streamed upload ──────────────────────────────────────────

/// The native-H3 streaming dispatch failure arm.
fn native_h3_streaming_failure_arm() -> String {
    compact(region(
        SERVER,
        "// ===== STREAMING REQUEST + RESPONSE PATH =====",
        "let backend_admission_response_elapsed =",
    ))
}

#[test]
fn native_h3_upload_read_failures_carry_typed_provenance() {
    let upload = compact(region(
        CLIENT,
        "async fn do_request_streaming_body(",
        "upload.completed = true;",
    ));
    assert_eq!(
        upload
            .matches("ProvenClientAbort::from_h3_request_read_error(&e)")
            .count(),
        2,
        "both the DATA read and the end-of-stream read classify with the shared predicate"
    );
    assert!(upload.contains("H3ClientRequestFault::Abort(abort)"));
    assert!(upload.contains("H3ClientRequestFault::MalformedBody"));
    assert!(upload.contains("H3ClientRequestFault::MalformedTrailers"));

    let detection = compact(region(
        SERVER,
        "fn is_h3_client_request_body_disconnect(",
        "\n}\n",
    ));
    assert!(
        detection.contains("e.client_request_fault().is_some()")
            && !detection.contains("contains("),
        "the client-upload decision reads the typed fault, never the error text"
    );
}

#[test]
fn native_h3_streamed_upload_abort_logs_499_and_writes_no_502() {
    let arm = native_h3_streaming_failure_arm();
    let keyed = arm
        .find(
            "letclient_abort=e.proven_client_abort().map(ProvenClientAbort::pre_header_terminal);",
        )
        .expect("the terminal is keyed on the typed abort");
    let class = arm
        .find("Some(terminal)=>terminal.error_class,None=>classify_h3_error(&e),")
        .expect("a client abort's class is ClientDisconnect");
    let status = arm
        .find("client_abort.map_or(reject_status.as_u16(),|terminal|terminal.http_status)")
        .expect("a client abort records 499");
    let reset = arm
        .find("stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);")
        .expect("the departed client's response is reset");
    let write = arm
        .find("send_h3_backend_failure_response(")
        .expect("other failures still answer");
    assert!(keyed < class && keyed < status && reset < write);
    assert!(
        arm.contains("letreject_sent=ifclient_abort.is_some(){"),
        "a client abort never writes the gateway 502"
    );
    assert!(arm.contains("client_disconnected:!reject_sent,"));
    assert!(arm.contains("response_status_code:reject_status_code,"));
    assert!(arm.contains("record_request(&state,reject_status_code);"));
}

#[test]
fn native_h3_controls_keep_their_own_terminals() {
    let arm = native_h3_streaming_failure_arm();
    // Malformed input stays 400.
    assert!(arm.contains(
        "h3_malformed_client_request_status_body(&e).unwrap_or_else(||h3_backend_failure_status_body(&e))"
    ));
    let malformed = compact(region(
        SERVER,
        "fn h3_malformed_client_request_status_body(",
        "\n}\n",
    ));
    assert!(malformed.contains("StatusCode::BAD_REQUEST"));
    assert!(malformed.contains("H3ClientRequestFault::Abort(_))|None=>None"));
    // Deadlines and backend failures keep 504 / 502.
    let failure = compact(region(
        SERVER,
        "fn h3_backend_failure_status_body(",
        "\n}\n",
    ));
    assert!(failure.contains("StatusCode::GATEWAY_TIMEOUT"));
    assert!(failure.contains("StatusCode::BAD_GATEWAY"));
}

// ── Native HTTP/3 gRPC ─────────────────────────────────────────────────────

#[test]
fn native_h3_grpc_pre_header_abort_is_cancelled_and_disconnected() {
    let writer = compact(region(
        SERVER,
        "async fn send_failed_h3_grpc_dispatch_error<S>(",
        "async fn send_h3_grpc_authorization_expired_terminal<S>(",
    ));
    let malformed = writer
        .find("}elseifletSome(message)=malformed_request_message{")
        .expect("malformed input is INVALID_ARGUMENT first");
    let cancelled = writer
        .find("}elseifletSome(terminal)=client_abort{(terminal.grpc_status,terminal.grpc_message)")
        .expect("a client abort answers CANCELLED");
    let unavailable = writer
        .find("crate::proxy::grpc_proxy::grpc_status::UNAVAILABLE")
        .expect("backend failures still answer UNAVAILABLE");
    assert!(malformed < cancelled && cancelled < unavailable);
    // Health: a client abort is recorded neutrally under 499, never as an
    // upstream 502; a client-side deadline keeps its own neutral 504.
    let health = &writer[writer
        .find("let(health_status,outcome_error_class)=")
        .expect("health classification")..];
    let abort_health = health
        .find("(terminal.http_status,Some(terminal.error_class))")
        .expect("a client abort is recorded under 499 with its neutral class");
    let deadline_health = health
        .find("(504,Some(crate::retry::ErrorClass::ClientDisconnect))")
        .expect("a client-side deadline keeps its neutral 504");
    let backend_health = health
        .find("letstatus=ifis_read_timeout{504}else{502};")
        .expect("a backend failure keeps 502 / 504");
    assert!(abort_health < deadline_health && deadline_health < backend_health);
    assert!(writer.contains("client_aborted:client_abort.is_some(),"));

    let recorder = compact(region(
        SERVER,
        "async fn record_failed_h3_grpc_dispatch(",
        "fn record_h3_grpc_dispatch_attempt(",
    ));
    assert!(
        recorder.contains("!error_sent||client_aborted,"),
        "a client abort is client_disconnected even when the CANCELLED trailers left"
    );

    // An authorization-lifetime terminal is ClientDisconnect-classed but is not
    // a client abort.
    let authorization = compact(region(
        SERVER,
        "fn h3_grpc_authorization_dispatch_failure(",
        "\n}\n",
    ));
    assert!(authorization.contains("client_aborted:false,"));
}

#[test]
fn native_h3_grpc_upload_pump_latches_only_proven_aborts() {
    let pump = compact(region(SERVER, "async fn run_h3_grpc_upload_pump(", "\n}\n"));
    let data_read = pump
        .find("ProvenClientAbort::from_h3_request_read_error(&error,).is_some(){H3GrpcUploadFault::ClientAbort}else{H3GrpcUploadFault::MalformedBody}")
        .or_else(|| {
            pump.find("ProvenClientAbort::from_h3_request_read_error(&error).is_some(){H3GrpcUploadFault::ClientAbort}else{H3GrpcUploadFault::MalformedBody}")
        });
    assert!(
        data_read.is_some(),
        "a DATA read failure is a client abort only on the shared predicate"
    );
}

#[test]
fn native_h3_grpc_post_header_abort_keeps_the_committed_status() {
    let relay = compact(SERVER);
    assert_eq!(
        relay
            .matches(
                "iffault==H3GrpcTerminatingUploadFault::ClientAbort{client_disconnected=true;}"
            )
            .count(),
        2,
        "both relay-phase upload-fault arms mark a client abort client_disconnected"
    );
}

// ── HTTP/3 to HTTP bridge ──────────────────────────────────────────────────

#[test]
fn the_plain_bridge_never_records_status_zero_for_a_departed_client() {
    let terminal = region(
        CROSS_PROTOCOL,
        "\nfn plain_peer_gone_before_response_headers(",
        "\nfn cross_protocol_header_write_disconnect_outcome(",
    );
    let compacted = compact(terminal);
    assert!(
        compacted.contains(
            "ProvenClientAbort::peer_gone_before_response_headers().pre_header_terminal()"
        )
    );
    assert!(compacted.contains("outcome.error_class=Some(terminal.error_class);"));
    assert!(
        !terminal.contains("        0,\n"),
        "the departed client is recorded as 499, never status 0"
    );
    // Refused input is a 400, not a client abort.
    assert!(compacted.contains("client_abort.map_or(StatusCode::BAD_REQUEST.as_u16(),"));
}

#[test]
fn the_plain_bridge_reader_separates_refused_input_from_a_client_abort() {
    let reader = compact(region(
        CROSS_PROTOCOL,
        "let reader_future = async {",
        "// Race resolution:",
    ));
    assert_eq!(
        reader
            .matches("reader_upload_refused.store(true,Ordering::Release);")
            .count(),
        2,
        "both the DATA read and the end-of-stream read record refused input"
    );
    assert_eq!(
        reader
            .matches("ProvenClientAbort::from_h3_request_read_error(")
            .count(),
        2
    );
    let dispatch = compact(region(
        CROSS_PROTOCOL,
        "async fn dispatch_plain<S>(",
        "\n#[allow(clippy::too_many_arguments)]\nasync fn dispatch_grpc<S>(",
    ));
    assert!(dispatch.contains("upload_refused:false,"));
    assert!(dispatch.contains("letupload_refused=reader_upload_refused.load(Ordering::Acquire);"));
}

// ── HTTP/3 to gRPC bridge ──────────────────────────────────────────────────

#[test]
fn the_grpc_bridge_answers_a_client_abort_cancelled() {
    let dispatch = compact(region(
        CROSS_PROTOCOL,
        "pub(crate) async fn dispatch_grpc_streaming(",
        "async fn apply_buffered_plain_plugin_reject(",
    ));
    // Controls: deadline and authorization terminals keep their own status.
    assert!(dispatch.contains(
        "grpc_proxy::GrpcProxyError::ClientDeadlineExceeded(_)|grpc_proxy::GrpcProxyError::BackendTimeout{..}|grpc_proxy::GrpcProxyError::AuthorizationExpired{..}"
    ));
    let malformed = dispatch
        .find("letmalformed_upload=malformed_record!=GRPC_BRIDGE_UPLOAD_NOT_MALFORMED;")
        .expect("malformed input is tracked apart from a client abort");
    let cancelled = dispatch
        .find("}elseifletSome(terminal)=client_abort{(terminal.grpc_status,terminal.grpc_message)")
        .expect("a client abort answers CANCELLED");
    assert!(malformed < cancelled);
    assert!(
        dispatch
            .contains("lethealth_status=client_abort.map_or(502,|terminal|terminal.http_status);")
    );
    assert!(dispatch.contains("outcome.client_disconnected=terminal.client_disconnected;"));
    assert!(
        dispatch.contains("Err(_)ifclient_abort.is_some()=>{"),
        "a client gone entirely still reaches the transaction log"
    );
    // The DATA-read arm records refused input too.
    assert!(dispatch.contains("GRPC_BRIDGE_UPLOAD_MALFORMED_BODY,Ordering::Release"));
}

// ── Buffered HTTP/3 drains ─────────────────────────────────────────────────

#[test]
fn buffered_h3_drains_mint_the_same_terminal() {
    let finalizer = compact(region(
        SERVER,
        "fn boxed_finalize_h3_upload_read_failure<'a>(",
        "/// Optional HTTP/3 listener settings",
    ));
    assert!(finalizer.contains("letclient_abort=error.proven_client_abort();"));
    assert!(finalizer.contains("letterminal=abort.pre_header_terminal();"));
    let bridge = compact(region(
        CROSS_PROTOCOL,
        "async fn write_bridge_upload_client_disconnect<S>(",
        "enum FinalRejectHooks {",
    ));
    assert!(bridge.contains("abort:ProvenClientAbort,"));
    assert!(bridge.contains("status_code:terminal.http_status,"));
}

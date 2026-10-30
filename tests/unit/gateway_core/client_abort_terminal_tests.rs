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
//! A gateway-local close is never laundered into a client cancellation: it is
//! the gateway-closed `503` / `UNAVAILABLE` terminal, also neutral for backend
//! health.
//!
//! h3's stream error variants cannot be built outside the crate, so the per-path
//! keying is guarded structurally here. On-the-wire proof lives in
//! `functional_h3_drain_refusal_hooks_test.rs` (`h3_*_client_abort_*`).

use ferrum_edge::_test_support::{
    H3GrpcUploadFaultKind, H3RequestReadFailureKind, PreHeaderSendTerminationForTest,
    error_class_is_backend_failure_for_test, error_class_is_health_neutral_for_test,
    h3_connection_error_incoming_failure_for_test, h3_grpc_upload_fault_latched_with_peer_for_test,
    map_http_reject_status_to_grpc_status, pre_header_upload_termination_response_for_test,
    quic_close_latch_verdict_for_test,
};
use ferrum_edge::plugins::{PeerConnectionSignal, PeerConnectionWatch, TransactionSummary};
use ferrum_edge::proxy::client_abort::{
    CLIENT_ABORT_GRPC_STATUS, CLIENT_ABORT_HTTP_BODY, CLIENT_ABORT_MESSAGE,
    CLIENT_CLOSED_REQUEST_STATUS, ConnectionCloseLatch, GATEWAY_CLOSED_UPLOAD_TERMINAL,
    MALFORMED_UPLOAD_GRPC_MESSAGE, MALFORMED_UPLOAD_HTTP_BODY, PRE_HEADER_CLIENT_ABORT_TERMINAL,
    ProvenClientAbort,
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
        ProvenClientAbort::from_response_cancellation(true, None).expect("STOP_SENDING"),
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
        metadata: metadata.into_iter().collect(),
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

/// A connection watch with a fixed state, standing in for the QUIC watcher.
struct FixedPeer {
    closed: bool,
    by_peer: bool,
}

impl PeerConnectionWatch for FixedPeer {
    fn closed(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(std::future::pending::<()>())
    }

    fn is_closed(&self) -> bool {
        self.closed
    }

    fn closed_by_peer(&self) -> bool {
        self.by_peer
    }
}

fn peer(closed: bool, by_peer: bool) -> PeerConnectionSignal {
    PeerConnectionSignal::new(std::sync::Arc::new(FixedPeer { closed, by_peer }))
}

#[test]
fn only_the_client_can_prove_a_response_cancellation() {
    // A STOP_SENDING only the client can send.
    assert!(ProvenClientAbort::from_response_cancellation(true, None).is_some());
    // A connection the client closed or lost.
    assert!(
        ProvenClientAbort::from_response_cancellation(false, Some(&peer(true, true))).is_some()
    );
    // The gateway's own close (a shutdown, an h3 error close) is not proof.
    assert!(
        ProvenClientAbort::from_response_cancellation(false, Some(&peer(true, false))).is_none(),
        "a gateway-local close must never become a client cancellation"
    );
    // No evidence at all is not proof either.
    assert!(
        ProvenClientAbort::from_response_cancellation(false, Some(&peer(false, false))).is_none()
    );
    assert!(ProvenClientAbort::from_response_cancellation(false, None).is_none());
}

#[test]
fn a_remote_application_close_is_a_client_abort_whatever_its_code() {
    use h3::quic::ConnectionErrorIncoming;
    // A peer CONNECTION_CLOSE carries the code the client chose: `0x0` (what
    // a client that simply drops its connection sends) and `H3_NO_ERROR`
    // (`0x100`) are both the client closing its connection.
    for error_code in [0x0_u64, 0x100] {
        assert_eq!(
            h3_connection_error_incoming_failure_for_test(
                &ConnectionErrorIncoming::ApplicationClose { error_code }
            ),
            H3RequestReadFailureKind::ClientAbort,
            "remote ApplicationClose {error_code:#x} is the client's close"
        );
    }
    // A stateless reset only the peer can send.
    assert_eq!(
        h3_connection_error_incoming_failure_for_test(&ConnectionErrorIncoming::Undefined(
            std::sync::Arc::new(quinn::ConnectionError::Reset)
        )),
        H3RequestReadFailureKind::ClientAbort
    );
}

#[test]
fn a_local_close_or_idle_timeout_stays_gateway_terminated() {
    use h3::quic::ConnectionErrorIncoming;
    for incoming in [
        // The gateway's own idle-timeout expiry, as h3-quinn reports it.
        ConnectionErrorIncoming::Timeout,
        ConnectionErrorIncoming::InternalError("internal".to_string()),
        // The gateway closed the connection itself.
        ConnectionErrorIncoming::Undefined(std::sync::Arc::new(
            quinn::ConnectionError::LocallyClosed,
        )),
        ConnectionErrorIncoming::Undefined(std::sync::Arc::new(quinn::ConnectionError::TimedOut)),
        // A cause the classifier cannot observe is never proof.
        ConnectionErrorIncoming::Undefined(std::sync::Arc::new(std::io::Error::other(
            "unobservable",
        ))),
    ] {
        assert_eq!(
            h3_connection_error_incoming_failure_for_test(&incoming),
            H3RequestReadFailureKind::GatewayTerminated,
            "{incoming:?} must not become a client abort"
        );
    }
}

#[test]
fn a_gateway_terminated_read_on_a_connection_the_client_closed_is_its_abort() {
    // A read on a connection the client closed can fail as an unclassified
    // closed stream; the connection's own close reason is the proof.
    assert!(ProvenClientAbort::from_peer_connection(Some(&peer(true, true))).is_some());
    // The gateway's own close or idle timeout, an open connection, and no
    // connection at all prove nothing.
    assert!(ProvenClientAbort::from_peer_connection(Some(&peer(true, false))).is_none());
    assert!(ProvenClientAbort::from_peer_connection(Some(&peer(false, false))).is_none());
    assert!(ProvenClientAbort::from_peer_connection(None).is_none());

    // The native-H3 gRPC upload state settles a published gateway-terminated
    // read the same way, and leaves every other fault alone.
    assert_eq!(
        h3_grpc_upload_fault_latched_with_peer_for_test(
            H3GrpcUploadFaultKind::GatewayTerminated,
            Some(peer(true, true)),
        ),
        H3GrpcUploadFaultKind::ClientAbort
    );
    assert_eq!(
        h3_grpc_upload_fault_latched_with_peer_for_test(
            H3GrpcUploadFaultKind::GatewayTerminated,
            Some(peer(true, false)),
        ),
        H3GrpcUploadFaultKind::GatewayTerminated
    );
    assert_eq!(
        h3_grpc_upload_fault_latched_with_peer_for_test(
            H3GrpcUploadFaultKind::GatewayTerminated,
            None,
        ),
        H3GrpcUploadFaultKind::GatewayTerminated
    );
    assert_eq!(
        h3_grpc_upload_fault_latched_with_peer_for_test(
            H3GrpcUploadFaultKind::MalformedBody,
            Some(peer(true, true)),
        ),
        H3GrpcUploadFaultKind::MalformedBody
    );

    // Every terminal decision point consults the connection before recording
    // the gateway-closed terminal.
    assert!(compact(CROSS_PROTOCOL).contains(
        "PLAIN_READER_GATEWAY_TERMINATED=>{matchProvenClientAbort::from_peer_connection(peer){Some(abort)=>Self::ClientAbort(abort),None=>Self::GatewayClosed,}}"
    ));
    assert_eq!(
        compact(CROSS_PROTOCOL)
            .matches("proven_client_abort_with_peer(ctx.peer_connection.as_ref())")
            .count(),
        2,
        "both buffered bridge drains settle against the connection"
    );
    assert_eq!(
        compact(CROSS_PROTOCOL)
            .matches("grpc_bridge_upload_fault_with_peer(")
            .count(),
        3,
        "the gRPC bridge settles its pre- and post-header upload faults"
    );
    let server = compact(SERVER);
    assert!(server.contains(
        "letclient_abort=error.proven_client_abort_with_peer(ctx.peer_connection.as_ref());"
    ));
    assert!(server.contains(
        "Ok(Ok(result))=>{result.map_err(|e|e.with_peer_closed_upload(ctx.peer_connection.as_ref()))}"
    ));
    assert_eq!(
        server
            .matches("leterror=error.with_peer_closed_upload(ctx.peer_connection.as_ref());")
            .count(),
        2,
        "both native gRPC dispatch-failure writers settle against the connection"
    );
    assert!(
        server
            .contains("H3GrpcUploadState::new().with_peer_connection(ctx.peer_connection.clone())")
    );
}

#[test]
fn the_first_observed_connection_close_wins() {
    let latch = ConnectionCloseLatch::new();
    assert_eq!(latch.latched(), None);
    // An open connection latches nothing.
    assert_eq!(latch.observe(None), None);
    assert_eq!(latch.latched(), None);
    // The client's close is latched once observed...
    assert_eq!(latch.observe(Some(true)), Some(true));
    // ...and the gateway's later teardown close never overwrites it.
    assert_eq!(latch.observe(Some(false)), Some(true));
    assert_eq!(latch.observe(None), Some(true));
    assert_eq!(latch.latched(), Some(true));

    // A close the gateway made first stays the gateway's.
    let gateway = ConnectionCloseLatch::new();
    assert_eq!(gateway.observe(Some(false)), Some(false));
    assert_eq!(gateway.observe(Some(true)), Some(false));
    assert_eq!(gateway.latched(), Some(false));
}

fn application_close(code: u32) -> quinn::ConnectionError {
    quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
        error_code: quinn::VarInt::from_u32(code),
        reason: bytes::Bytes::new(),
    })
}

#[test]
fn a_client_close_survives_the_h3_teardown_close() {
    // Client close -> accept loop ends (the guard observes the peer close) ->
    // h3 connection drop calls `close()`, which Quinn records as
    // `LocallyClosed` over the peer's reason -> a request task settles its
    // terminal afterwards and must still see the client's close.
    for code in [0x0, 0x100] {
        assert_eq!(
            quic_close_latch_verdict_for_test(vec![
                None,
                Some(application_close(code)),
                Some(quinn::ConnectionError::LocallyClosed),
            ]),
            Some(true),
            "a client close with code {code:#x} must outlive the teardown close"
        );
    }
    assert_eq!(
        quic_close_latch_verdict_for_test(vec![
            Some(quinn::ConnectionError::Reset),
            Some(quinn::ConnectionError::LocallyClosed),
        ]),
        Some(true)
    );
    // The gateway's own close, or its idle timeout, observed first stays the
    // gateway's: 503, never 499.
    for first in [
        quinn::ConnectionError::LocallyClosed,
        quinn::ConnectionError::TimedOut,
    ] {
        assert_eq!(
            quic_close_latch_verdict_for_test(vec![Some(first), Some(application_close(0))]),
            Some(false)
        );
    }
    // Still open: nothing is proven.
    assert_eq!(quic_close_latch_verdict_for_test(vec![None, None]), None);

    // The watch answers from the latch, and the accept loop latches the close
    // before `h3_conn` (whose destructor closes the transport) drops.
    let server = compact(SERVER);
    assert!(server.contains("fnclosed_by_peer(&self)->bool{self.observe_close()==Some(true)}"));
    let h3_conn = server
        .find("letmuth3_conn=h3::server::builder()")
        .expect("h3 connection");
    let guard = server
        .find("let_close_verdict=QuicCloseVerdictGuard(quic_peer_watch);")
        .expect("the close verdict guard");
    assert!(
        h3_conn < guard,
        "the guard is declared after h3_conn so it drops first"
    );
    assert!(server.contains(
        "implDropforQuicCloseVerdictGuard{fndrop(&mutself){let_=self.0.observe_close();}}"
    ));
}

#[test]
fn a_connection_watch_that_cannot_tell_is_never_proof() {
    struct Unknown;
    impl PeerConnectionWatch for Unknown {
        fn closed(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
            Box::pin(std::future::pending::<()>())
        }
        fn is_closed(&self) -> bool {
            true
        }
    }
    let signal = PeerConnectionSignal::new(std::sync::Arc::new(Unknown));
    assert!(!signal.closed_by_peer(), "the default is no proof");
    assert!(ProvenClientAbort::from_response_cancellation(false, Some(&signal)).is_none());
}

#[test]
fn the_gateway_closed_terminal_is_neither_a_client_abort_nor_a_backend_fault() {
    let terminal = GATEWAY_CLOSED_UPLOAD_TERMINAL;
    assert_eq!(terminal.http_status, 503);
    assert_eq!(terminal.grpc_status, grpc_status::UNAVAILABLE);
    assert_ne!(terminal.http_status, CLIENT_CLOSED_REQUEST_STATUS);
    assert_ne!(terminal.grpc_status, CLIENT_ABORT_GRPC_STATUS);
    let quic = compact(region(
        SERVER,
        "pub(crate) fn quinn_close_reason_is_peer(",
        "\n}\n",
    ));
    assert!(
        !quic.contains("ConnectionError::LocallyClosed")
            && !quic.contains("ConnectionError::TimedOut")
            && quic.contains("ApplicationClosed(_)"),
        "the QUIC watcher counts only a close the client sent, a reset, or a timeout"
    );
}

#[test]
fn the_499_is_defined_once_and_minted_only_from_client_evidence() {
    assert!(CLIENT_ABORT.contains("pub const CLIENT_CLOSED_REQUEST_STATUS: u16 = 499;"));
    // The H3 read-error evidence is the classifier every path shares.
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

#[test]
fn the_relayed_upload_dispatcher_terminal_shares_the_one_definition() {
    // Issue #6776's mesh-mTLS, HBONE, and Unix-socket terminal records the same
    // client-abort terminal, from the same constants, as every HTTP/3 path.
    let http = pre_header_upload_termination_response_for_test(
        PreHeaderSendTerminationForTest::ClientAbort,
        false,
        None,
    );
    assert_eq!(http.status_code, CLIENT_CLOSED_REQUEST_STATUS);
    assert_eq!(http.error_class, Some(ErrorClass::ClientDisconnect));
    let grpc = pre_header_upload_termination_response_for_test(
        PreHeaderSendTerminationForTest::ClientAbort,
        true,
        None,
    );
    assert_eq!(
        grpc.headers.get("grpc-status").map(String::as_str),
        Some(CLIENT_ABORT_GRPC_STATUS.to_string().as_str())
    );
    assert_eq!(
        grpc.headers.get("grpc-message").map(String::as_str),
        Some(CLIENT_ABORT_MESSAGE)
    );
    // Malformed input is the same 400 / INVALID_ARGUMENT vocabulary everywhere.
    let malformed = pre_header_upload_termination_response_for_test(
        PreHeaderSendTerminationForTest::MalformedUpload,
        true,
        None,
    );
    assert_eq!(
        malformed.headers.get("grpc-status").map(String::as_str),
        Some(grpc_status::INVALID_ARGUMENT.to_string().as_str())
    );
    assert_eq!(
        malformed.headers.get("grpc-message").map(String::as_str),
        Some(MALFORMED_UPLOAD_GRPC_MESSAGE)
    );
    assert_eq!(
        MALFORMED_UPLOAD_HTTP_BODY,
        r#"{"error":"Malformed request body"}"#
    );

    // One definition: the dispatcher's constants and the gRPC mapping's
    // `grpc_proxy::CLIENT_CLOSED_REQUEST_STATUS` path alias `client_abort`.
    let proxy = compact(PROXY);
    for alias in [
        "constGRPC_CLIENT_DISCONNECT_MESSAGE:&str=client_abort::CLIENT_ABORT_MESSAGE;",
        "constMALFORMED_REQUEST_BODY_JSON:&[u8]=client_abort::MALFORMED_UPLOAD_HTTP_BODY.as_bytes();",
        "constMALFORMED_REQUEST_BODY_GRPC_MESSAGE:&str=client_abort::MALFORMED_UPLOAD_GRPC_MESSAGE;",
    ] {
        assert!(proxy.contains(alias), "missing shared alias {alias}");
    }
    let terminal = compact(region(
        PROXY,
        "pub(crate) fn pre_header_upload_termination_response(",
        "upload_pump::PreHeaderSendTermination::MalformedUpload =>",
    ));
    assert!(terminal.contains(
        "client_abort::ProvenClientAbort::latched_upload_abort().pre_header_terminal();"
    ));
    assert!(terminal.contains("client_abort::CLIENT_ABORT_HTTP_BODY.as_bytes(),"));
    assert!(!terminal.contains("Clientdisconnected"));
    let grpc_source = compact(include_str!("../../../src/proxy/grpc_proxy.rs"));
    assert!(grpc_source.contains(
        "pub(crate)constCLIENT_CLOSED_REQUEST_STATUS:u16=crate::proxy::client_abort::CLIENT_CLOSED_REQUEST_STATUS;"
    ));
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

// ── Native HTTP/3 ──────────────────────────────────────────────────────────

/// The native-H3 streaming dispatch and its failure arm.
fn native_h3_streaming_branch() -> String {
    compact(region(
        SERVER,
        "// ===== STREAMING REQUEST + RESPONSE PATH =====",
        "let backend_admission_response_elapsed =",
    ))
}

#[test]
fn native_h3_upload_read_failures_carry_typed_provenance() {
    let helper = compact(region(CLIENT, "fn h3_client_upload_read_error(", "\n}\n"));
    assert!(helper.contains("crate::http3::stream_util::classify_h3_request_read_error(error)"));
    assert!(helper.contains("H3RequestReadFailure::ClientAbort=>H3PoolError::client_request("));
    assert!(helper.contains("H3RequestReadFailure::Malformed=>{"));
    assert!(helper.contains(
        "H3RequestReadFailure::GatewayTerminated=>H3PoolError::client_request(H3ClientRequestFault::GatewayTerminated,"
    ));
    let upload = compact(region(
        CLIENT,
        "async fn do_request_streaming_body(",
        "upload.completed = true;",
    ));
    assert!(
        upload.contains("h3_client_upload_read_error(&e,H3ClientRequestFault::MalformedBody,)")
    );
    assert!(
        upload.contains("h3_client_upload_read_error(&e,H3ClientRequestFault::MalformedTrailers,)")
    );

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
fn native_h3_streamed_upload_abort_logs_499_without_a_gateway_502() {
    let arm = native_h3_streaming_branch();
    let keyed = arm
        .find(
            "letclient_abort=e.proven_client_abort().map(ProvenClientAbort::pre_header_terminal);",
        )
        .expect("the terminal is keyed on the typed abort");
    let status = arm
        .find("Some(terminal)=>terminal.http_status,Noneifgateway_closed=>{crate::proxy::client_abort::GATEWAY_CLOSED_UPLOAD_TERMINAL.http_status}None=>reject_status.as_u16(),")
        .expect("a client abort records 499, a gateway close 503");
    let reset = arm
        .find("stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);")
        .expect("the departed client's response is reset");
    let write = arm
        .find("send_h3_backend_failure_response(")
        .expect("other failures still answer");
    assert!(keyed < status && reset < write);
    assert!(
        arm.contains("letreject_sent=ifclient_abort.is_some(){"),
        "a client abort never writes the gateway 502"
    );
    assert!(arm.contains("client_disconnected:!reject_sent&&!gateway_closed,"));
    assert!(arm.contains("record_request(&state,reject_status_code);"));
}

#[test]
fn native_h3_watches_the_response_direction_until_the_head_arrives() {
    let branch = native_h3_streaming_branch();
    let watcher = branch
        .find("letresponse_stopped=crate::http3::stream_util::peer_response_stopped(&stream);")
        .expect("the client's response direction is watched");
    let race = branch
        .find("biased;result=&mutbounded=>Ok(result),peer_stop_sending=&mutresponse_stopped=>Err(peer_stop_sending),")
        .expect("a settled attempt or deadline keeps precedence over the cancel");
    let typed = branch
        .find("Err(peer_stop_sending)=>Err(h3_response_cancelled_pool_error(peer_stop_sending,ctx.peer_connection.as_ref(),")
        .expect("the cancel becomes a typed pool error");
    assert!(watcher < race && race < typed);
    let helper = compact(region(
        SERVER,
        "fn h3_response_cancelled_pool_error(",
        "\n}\n",
    ));
    assert!(
        helper.contains("ProvenClientAbort::from_response_cancellation(peer_stop_sending,peer)")
    );
    assert!(
        helper.contains("None=>(crate::http3::client::H3ClientRequestFault::GatewayTerminated,")
    );

    let grpc = compact(region(
        SERVER,
        "async fn dispatch_grpc_native_h3(",
        "let head_result = match",
    ));
    assert!(grpc.contains(
        "letresponse_stopped=crate::http3::stream_util::peer_response_stopped(&send_half);"
    ));
    let head = grpc
        .find("head=crate::http3::client::recv_h3_backend_response_head(&mutbackend_recv)=>{")
        .expect("backend head arm");
    let cancel = grpc
        .find("peer_stop_sending=response_stopped=>Some(Ok(Err(h3_response_cancelled_pool_error(")
        .expect("the native gRPC header wait watches the client too");
    assert!(head < cancel, "a ready backend head keeps precedence");
    let open = compact(region(
        SERVER,
        "// ── Phase 1: open the backend request stream",
        "let opened = match open_result {",
    ));
    assert!(open.contains(
        "letopen_response_stopped=crate::http3::stream_util::peer_response_stopped(&stream);"
    ));
    assert!(
        open.contains(
            "biased;result=&mutscoped=>result,peer_stop_sending=&mutopen_response_stopped=>Err(h3_response_cancelled_pool_error("
        ),
        "backend acquisition watches the client too, with a settled open first"
    );
}

#[test]
fn native_h3_controls_keep_their_own_terminals() {
    let arm = native_h3_streaming_branch();
    assert!(arm.contains(
        "h3_malformed_client_request_status_body(&e).unwrap_or_else(||h3_backend_failure_status_body(&e))"
    ));
    let malformed = compact(region(
        SERVER,
        "fn h3_malformed_client_request_status_body(",
        "\n}\n",
    ));
    assert!(malformed.contains("StatusCode::BAD_REQUEST"));
    assert!(malformed.contains(
        "Some(crate::http3::client::H3ClientRequestFault::Abort(_)|crate::http3::client::H3ClientRequestFault::GatewayTerminated,)|None=>None"
    ));
    let failure = compact(region(
        SERVER,
        "fn h3_backend_failure_status_body(",
        "\n}\n",
    ));
    assert!(failure.contains("StatusCode::GATEWAY_TIMEOUT"));
    assert!(failure.contains("StatusCode::BAD_GATEWAY"));
}

#[test]
fn buffered_h3_drains_classify_three_ways() {
    let finalizer = compact(region(
        SERVER,
        "fn boxed_finalize_h3_upload_read_failure<'a>(",
        "/// Optional HTTP/3 listener settings",
    ));
    let abort = finalizer
        .find("letterminal=abort.pre_header_terminal();")
        .expect("client abort");
    let malformed = finalizer
        .find("}elseiferror.failure()==crate::http3::stream_util::H3RequestReadFailure::Malformed{")
        .expect("only a framing violation is malformed");
    let closed = finalizer
        .find("\"gateway_closed_h3_upload\",")
        .expect("the gateway's own close has its own terminal");
    assert!(abort < malformed && malformed < closed);
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
    let closed = writer
        .find("}elseifgateway_closed{letterminal=crate::proxy::client_abort::GATEWAY_CLOSED_UPLOAD_TERMINAL;(terminal.grpc_status,terminal.grpc_message)")
        .expect("the gateway's own close is its UNAVAILABLE");
    let unavailable = writer
        .find("crate::proxy::grpc_proxy::grpc_status::UNAVAILABLE")
        .expect("backend failures still answer UNAVAILABLE");
    assert!(malformed < cancelled && cancelled < closed && closed < unavailable);
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
        .find("letstatus=ifis_backend_timeout{504}else{502};")
        .expect("a backend failure keeps 502 / 504");
    assert!(abort_health < deadline_health && deadline_health < backend_health);

    let end = compact(region(SERVER, "impl H3FrontendEnd {", "\n}\n"));
    assert!(end.contains("Self::Open=>!error_sent,"));
    assert!(end.contains("Self::ClientAbort=>true,"));
    assert!(end.contains("Self::GatewayClosed=>false,"));
    let recorder = compact(region(
        SERVER,
        "async fn record_failed_h3_grpc_dispatch(",
        "fn record_h3_grpc_dispatch_attempt(",
    ));
    assert!(recorder.contains("frontend_end.client_disconnected(error_sent),"));
    let authorization = compact(region(
        SERVER,
        "fn h3_grpc_authorization_dispatch_failure(",
        "\n}\n",
    ));
    assert!(
        authorization.contains("frontend_end:H3FrontendEnd::Open,"),
        "an authorization terminal is ClientDisconnect-classed but not a client abort"
    );
}

#[test]
fn native_h3_grpc_upload_pump_classifies_positively() {
    let pump = compact(region(SERVER, "async fn run_h3_grpc_upload_pump(", "\n}\n"));
    assert!(pump.contains(
        "upload.publish_fault(H3GrpcUploadFault::from_read_error(&error,H3GrpcUploadFault::MalformedBody,));"
    ));
    assert!(pump.contains(
        "upload.publish_fault(H3GrpcUploadFault::from_read_error(&error,H3GrpcUploadFault::MalformedTrailers,));"
    ));
}

#[test]
fn native_h3_grpc_post_header_abort_logs_the_status_the_client_got() {
    let server = compact(SERVER);
    assert_eq!(
        server
            .matches("iffault==H3GrpcTerminatingUploadFault::ClientAbort{client_disconnected=true;}gateway_grpc_terminal=Some(fault_status);")
            .count(),
        2,
        "both relay-phase upload-fault arms mark a client abort and carry the gateway terminal"
    );
    assert!(
        server.contains("letgrpc_status=gateway_grpc_terminal.or(grpc_trailer_status)"),
        "the transaction log records the gateway-selected terminal, not a fallback UNKNOWN"
    );
    // The gateway terminal never trains backend health: the admission sample
    // still reads only the backend's terminal.
    let admission = region(
        SERVER,
        "let admission_status = if grpc_trailer_status.is_some()",
        "record_h3_backend_admission_outcome(",
    );
    assert!(!admission.contains("gateway_grpc_terminal"));
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
            "PlainPeerGone::ClientAbort(abort)=>abort.pre_header_terminal().http_status,"
        )
    );
    assert!(compacted.contains("PlainPeerGone::Malformed=>StatusCode::BAD_REQUEST.as_u16(),"));
    assert!(compacted.contains(
        "PlainPeerGone::GatewayClosed=>{crate::proxy::client_abort::GATEWAY_CLOSED_UPLOAD_TERMINAL.http_status}"
    ));
    assert!(compacted.contains("outcome.error_class=Some(terminal.error_class);"));
    assert!(
        !terminal.contains("        0,\n"),
        "the departed client is recorded as 499, never status 0"
    );
    let watcher = compact(region(CROSS_PROTOCOL, "fn from_watcher(", "\n    }\n"));
    assert!(
        watcher.contains("ProvenClientAbort::from_response_cancellation(stop_sending,peer)")
            && !watcher.contains("is_closed()"),
        "the watcher's own typed STOP_SENDING decides, never the later connection state"
    );
    assert!(watcher.contains("None=>Self::GatewayClosed,"));
}

#[test]
fn the_plain_bridge_reader_records_one_classified_cause() {
    let reader = compact(region(
        CROSS_PROTOCOL,
        "let reader_future = async {",
        "// Race resolution:",
    ));
    assert_eq!(
        reader
            .matches("reader_upload_failure.store(plain_reader_failure_code(")
            .count(),
        2,
        "both the DATA read and the end-of-stream read record their classified cause"
    );
    let dispatch = compact(region(
        CROSS_PROTOCOL,
        "async fn dispatch_plain<S>(",
        "\n#[allow(clippy::too_many_arguments)]\nasync fn dispatch_grpc<S>(",
    ));
    assert!(dispatch.contains(
        "letcause=PlainPeerGone::from_watcher(plain_stop_sending.load(Ordering::Acquire),ctx.peer_connection.as_ref(),);"
    ));
    assert!(dispatch.contains(
        "letcause=PlainPeerGone::from_reader(reader_upload_failure.load(Ordering::Acquire),response_stop_sending.load(Ordering::Acquire),ctx.peer_connection.as_ref(),);"
    ));
    assert!(dispatch.contains(
        "peer_response_cancelled(crate::http3::stream_util::peer_response_stopped(stream),&plain_stop_sending,)"
    ));
    assert!(dispatch.contains(
        "peer_response_cancelled(crate::http3::stream_util::peer_response_stopped(stream),&response_stop_sending,)"
    ));
    assert_eq!(dispatch.matches("cause.reset_response(stream);").count(), 2);
}

#[test]
fn the_buffered_plain_bridge_never_writes_499() {
    let reject = compact(region(
        CROSS_PROTOCOL,
        "async fn write_final_body_reject<S>(",
        "fn normalize_h3_grpc_reject(",
    ));
    let plain = reject
        .find("}elseifhooks==FinalRejectHooks::UploadClientDisconnect{")
        .expect("a departed plain-HTTP client has its own arm");
    let grpc = reject
        .find("}elseifmatches!(flavor,HttpFlavor::Grpc){")
        .expect("gRPC keeps its CANCELLED trailers");
    let deadline = reject[plain..]
        .find("}elseifterminal_gateway_deadline{")
        .expect("the plain arm precedes the plain writers");
    let arm = &reject[plain..plain + deadline];
    assert!(grpc < plain);
    assert!(
        arm.contains("stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);")
            && !arm.contains("write_reject_with_headers"),
        "a departed plain-HTTP client's response is reset, never answered 499"
    );
}

// ── HTTP/3 to gRPC bridge ──────────────────────────────────────────────────

#[test]
fn the_grpc_bridge_keys_its_terminal_on_the_relayed_upload_fault() {
    let dispatch = compact(region(
        CROSS_PROTOCOL,
        "pub(crate) async fn dispatch_grpc_streaming(",
        "async fn apply_buffered_plain_plugin_reject(",
    ));
    // One published fault, read only after the relay flag.
    let signals = compact(region(
        CROSS_PROTOCOL,
        "fn relayed_fault(self) -> u8 {",
        "\n    }\n",
    ));
    assert!(signals.contains(
        "ifself.relayed.load(Ordering::Acquire){self.fault.load(Ordering::Acquire)}else{GRPC_BRIDGE_UPLOAD_OK}"
    ));
    assert!(dispatch.contains("Some(Arc::clone(&frontend_failure_relayed)),"));
    assert!(dispatch.contains("upload_signals.relayed_fault()"));
    // The latch counts only with the typed local-reset evidence; a backend
    // reset that beat hyper's own reset stays the backend's failure.
    assert!(dispatch.contains(
        "}elseifgateway_terminal||!error_chain_is_local_h2_reset(&err){GRPC_BRIDGE_UPLOAD_OK}else{upload_signals.relayed_fault()};"
    ));
    let reset = compact(region(
        CROSS_PROTOCOL,
        "fn error_chain_is_local_h2_reset(",
        "\n}\n",
    ));
    assert!(reset.contains("returnh2_err.is_reset()&&!h2_err.is_remote()&&!h2_err.is_library();"));
    // A clean upload FIN followed by a cancel is observed before the head.
    let race = dispatch
        .find("letresponse_stopped=crate::http3::stream_util::peer_response_stopped(&send_half);")
        .expect("response-direction watcher");
    let select = dispatch
        .find("biased;result=&mutscoped=>result,peer_stop_sending=&mutresponse_stopped=>{response_cancel=Some(peer_stop_sending);")
        .expect("a settled attempt keeps precedence over the cancel");
    assert!(race < select);
    assert!(dispatch.contains("letupload_fault=ifletSome(peer_stop_sending)=response_cancel{"));
    // The frontend-selected terminal write is bounded by the shared grace.
    assert!(dispatch.contains(
        "letwrite=ifupload_terminal_selected{crate::http3::stream_util::await_post_deadline_terminal_response_write(write).await"
    ));
    // Controls: deadline and authorization terminals keep their own status.
    assert!(dispatch.contains(
        "grpc_proxy::GrpcProxyError::ClientDeadlineExceeded(_)|grpc_proxy::GrpcProxyError::BackendTimeout{..}|grpc_proxy::GrpcProxyError::AuthorizationExpired{..}"
    ));
    let cancelled = dispatch
        .find("}elseifletSome(terminal)=client_abort{(terminal.grpc_status,terminal.grpc_message)")
        .expect("a client abort answers CANCELLED");
    let closed = dispatch
        .find("}elseifgateway_closed{letterminal=crate::proxy::client_abort::GATEWAY_CLOSED_UPLOAD_TERMINAL;")
        .expect("the gateway's own close answers its UNAVAILABLE");
    assert!(cancelled < closed);
    assert!(
        dispatch.contains("Err(_)ifupload_terminal_selected=>{"),
        "every frontend-selected terminal still reaches the transaction log once"
    );
    // Post-header: a relayed client abort records CANCELLED and the disconnect.
    let relay = compact(region(
        CROSS_PROTOCOL,
        "async fn handle_h3_grpc_streaming_response<S>(",
        "fn resolve_h3_grpc_transport<'a>(",
    ));
    assert!(
        relay.contains("letclient_cancelled=relayed_upload_fault==GRPC_BRIDGE_UPLOAD_CLIENT_ABORT")
    );
    assert!(relay.contains("ifclient_cancelled{final_client_disconnected=true;}"));
    assert!(
        relay.contains("letrelayed_upload_fault=ifbody_error_local_reset.load(Ordering::Relaxed){")
    );
    assert!(relay.contains("body_error_local_reset:&body_error_local_reset,"));
    assert!(relay.contains("}elseifclient_cancelled{ProvenClientAbort::latched_upload_abort().pre_header_terminal().grpc_status}"));
    // The channel body sets the relay flag exactly when it hands the failure on.
    let body = compact(include_str!("../../../src/proxy/grpc_proxy.rs"));
    assert!(body.contains(
        "Poll::Ready(Some(Err(())))=>{ifletSome(relayed)=frontend_failure_relayed{relayed.store(true,Ordering::Release);}"
    ));
}

#[test]
fn buffered_bridges_settle_a_gateway_close_without_a_client_abort() {
    let bridge = compact(CROSS_PROTOCOL);
    assert_eq!(
        bridge
            .matches("H3RequestReadFailure::GatewayTerminated{returnOk(bridge_upload_gateway_closed_outcome(")
            .count(),
        2,
        "both buffered bridge drains settle a gateway-closed stream as such"
    );
    let writer = compact(region(
        CROSS_PROTOCOL,
        "async fn write_bridge_upload_client_disconnect<S>(",
        "enum FinalRejectHooks {",
    ));
    assert!(writer.contains("abort:ProvenClientAbort,"));
    assert!(writer.contains("status_code:terminal.http_status,"));
}

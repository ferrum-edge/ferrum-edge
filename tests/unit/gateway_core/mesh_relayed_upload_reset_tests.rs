//! Issue #6776: termination provenance for the sidecar mesh-mTLS, HBONE, and
//! Unix-socket dispatchers.
//!
//! Those dispatchers hand the client body to a pooled hyper client. When the
//! gateway's request body fails, hyper ends the backend exchange itself, and
//! `send_request` fails before the response head. These tests pin the two
//! halves of the attribution:
//!
//! * the typed transport proof, driven through REAL hyper HTTP/1.1 (the HBONE
//!   inner client and the Unix-socket pool) and HTTP/2 (sidecar mesh-mTLS and
//!   Unix h2c) client connections, so a backend-origin reset, `CANCEL`,
//!   `NO_ERROR`, protocol failure, or close is never mistaken for one the
//!   gateway raised; and
//! * the typed upload terminals that name the cause, mirroring the direct-H2
//!   early-response refusal (issue #6314), and the response, retry boundary,
//!   and circuit-breaker feedback each cause produces.

use std::convert::Infallible;
use std::time::Duration;

use bytes::Bytes;
use ferrum_edge::_test_support::{
    PreHeaderSendTerminationForTest as Termination, UploadPumpOutcomeForTest as Pump,
    apply_circuit_breaker_outcome_for_test, hyper_send_error_ended_by_gateway_upload_for_test,
    pre_header_send_termination_for_test, pre_header_upload_termination_response_for_test,
};
use ferrum_edge::circuit_breaker::CircuitBreaker;
use ferrum_edge::config::types::CircuitBreakerConfig;
use ferrum_edge::retry::{BackendResponse, ErrorClass, request_reached_wire};
use http_body::Frame;
use http_body_util::{BodyExt, Empty, StreamBody};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncReadExt, DuplexStream};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type UploadFrame = Result<Frame<Bytes>, BoxError>;
type UploadBody = StreamBody<ReceiverStream<UploadFrame>>;

const STEP: Duration = Duration::from_secs(5);

/// The streaming upload a dispatcher hands its pooled client: one DATA frame
/// is queued, and the returned sender decides what happens next.
async fn upload_with_first_frame() -> (mpsc::Sender<UploadFrame>, UploadBody) {
    let (tx, rx) = mpsc::channel(4);
    tx.send(Ok(Frame::data(Bytes::from_static(b"hello"))))
        .await
        .expect("queue first upload frame");
    (tx, StreamBody::new(ReceiverStream::new(rx)))
}

/// What the gateway's body yields when the client's own upload fails: the
/// adapter's relayed client error (no pump), or the pump's typed `CANCEL` for
/// an HTTP/2 client reset.
#[derive(Clone, Copy, Debug)]
enum RelayedClientFailure {
    TransportError,
    H2Cancel,
}

impl RelayedClientFailure {
    fn error(self) -> BoxError {
        match self {
            Self::TransportError => Box::new(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "client connection lost mid-upload",
            )),
            Self::H2Cancel => Box::new(h2::Error::from(h2::Reason::CANCEL)),
        }
    }
}

fn upload_request(body: UploadBody) -> Request<UploadBody> {
    Request::builder()
        .method("POST")
        .uri("http://backend.test/upload")
        .body(body)
        .expect("build upload request")
}

/// An HTTP/1.1 backend that keeps reading the upload and never answers.
async fn h1_holding_backend(io: DuplexStream) {
    let service = service_fn(|req: Request<Incoming>| async move {
        let mut body = req.into_body();
        while let Some(frame) = body.frame().await {
            if frame.is_err() {
                break;
            }
        }
        std::future::pending::<()>().await;
        Ok::<_, Infallible>(Response::new(Empty::<Bytes>::new()))
    });
    let _ = hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(io), service)
        .await;
}

/// An HTTP/2 backend that keeps reading the upload and never answers.
async fn h2_holding_backend(io: DuplexStream) {
    let service = service_fn(|req: Request<Incoming>| async move {
        let mut body = req.into_body();
        while let Some(frame) = body.frame().await {
            if frame.is_err() {
                break;
            }
        }
        std::future::pending::<()>().await;
        Ok::<_, Infallible>(Response::new(Empty::<Bytes>::new()))
    });
    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(io), service)
        .await;
}

/// An HTTP/2 backend that resets the request stream with `reason` once the
/// first upload frame has arrived, before any response head.
async fn h2_resetting_backend(io: DuplexStream, reason: h2::Reason) {
    let service = service_fn(move |req: Request<Incoming>| async move {
        let mut body = req.into_body();
        let _ = body.frame().await;
        Err::<Response<Empty<Bytes>>, h2::Error>(h2::Error::from(reason))
    });
    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(io), service)
        .await;
}

/// An HTTP/2 backend that answers `status` as soon as the request arrives,
/// without reading the upload.
async fn h2_early_answer_backend(io: DuplexStream, status: u16) {
    let service = service_fn(move |_req: Request<Incoming>| async move {
        let response = Response::builder()
            .status(status)
            .body(Empty::<Bytes>::new())
            .expect("early response");
        Ok::<_, Infallible>(response)
    });
    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(io), service)
        .await;
}

/// An HTTP/1.1 backend that reads the request head and then closes the
/// connection while the upload is still streaming.
async fn h1_closing_backend(mut io: DuplexStream) {
    let mut seen = Vec::new();
    let mut buf = [0u8; 1024];
    while !seen.windows(4).any(|window| window == b"\r\n\r\n") {
        match io.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => seen.extend_from_slice(&buf[..n]),
        }
    }
    drop(io);
}

async fn h1_send(
    backend: impl std::future::Future<Output = ()> + Send + 'static,
    client_io: DuplexStream,
    body: UploadBody,
) -> Result<Response<Incoming>, hyper::Error> {
    let server = tokio::spawn(backend);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(client_io))
        .await
        .expect("h1 handshake");
    let client_conn = tokio::spawn(async move {
        let _ = conn.await;
    });
    let result = tokio::time::timeout(STEP, sender.send_request(upload_request(body)))
        .await
        .expect("the h1 exchange must settle in time");
    client_conn.abort();
    server.abort();
    result
}

async fn h2_send(
    backend: impl std::future::Future<Output = ()> + Send + 'static,
    client_io: DuplexStream,
    body: UploadBody,
) -> Result<Response<Incoming>, hyper::Error> {
    let server = tokio::spawn(backend);
    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(client_io))
            .await
            .expect("h2 handshake");
    let client_conn = tokio::spawn(async move {
        let _ = conn.await;
    });
    let result = tokio::time::timeout(STEP, sender.send_request(upload_request(body)))
        .await
        .expect("the h2 exchange must settle in time");
    client_conn.abort();
    server.abort();
    result
}

/// The circuit breaker the dispatch outcome is fed to. Every status the
/// attribution can produce is a configured failure status, so only the class
/// can keep an outcome neutral.
fn hair_trigger_breaker() -> CircuitBreaker {
    CircuitBreaker::new(CircuitBreakerConfig {
        failure_threshold: 1,
        timeout_seconds: 300,
        failure_status_codes: vec![401, 499, 502, 504],
        trip_on_connection_errors: true,
        ..CircuitBreakerConfig::default()
    })
}

/// Settle `response` on a fresh breaker the way the dispatch pipeline does,
/// and report whether it was charged as a backend failure.
fn charged_to_backend(response: &BackendResponse) -> bool {
    let cb = hair_trigger_breaker();
    apply_circuit_breaker_outcome_for_test(
        &cb,
        response.status_code,
        response.connection_error,
        response.error_class,
        false,
    );
    cb.failure_count() > 0 || cb.state_name() == "open"
}

fn assert_retry_boundary(response: &BackendResponse) {
    let class = response
        .error_class
        .expect("an attributed dispatch failure has a class");
    assert_eq!(
        response.connection_error,
        !request_reached_wire(class),
        "connection_error must follow the wire boundary for {class:?}"
    );
}

// ── The typed transport proof, from real hyper clients ───────────────────

#[tokio::test]
async fn h1_relayed_client_upload_failure_is_the_gateway_ending_the_exchange() {
    for failure in [
        RelayedClientFailure::TransportError,
        RelayedClientFailure::H2Cancel,
    ] {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (tx, body) = upload_with_first_frame().await;
        tx.send(Err(failure.error()))
            .await
            .expect("relay the client failure");
        let err = h1_send(h1_holding_backend(server_io), client_io, body)
            .await
            .expect_err("a failed upload must fail the h1 exchange");
        assert!(
            hyper_send_error_ended_by_gateway_upload_for_test(&err),
            "{failure:?}: hyper's user body error is typed proof: {err:?}"
        );
        drop(tx);
    }
}

#[tokio::test]
async fn h1_backend_close_mid_upload_is_not_the_gateway() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    // The upload stays open: only the backend can end this exchange.
    let (tx, body) = upload_with_first_frame().await;
    let err = h1_send(h1_closing_backend(server_io), client_io, body)
        .await
        .expect_err("a backend that closes mid-upload fails the exchange");
    assert!(
        !hyper_send_error_ended_by_gateway_upload_for_test(&err),
        "a backend close stays a backend failure: {err:?}"
    );
    drop(tx);
}

#[tokio::test]
async fn h2_relayed_client_upload_failure_is_a_locally_initiated_reset() {
    for failure in [
        RelayedClientFailure::TransportError,
        RelayedClientFailure::H2Cancel,
    ] {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (tx, body) = upload_with_first_frame().await;
        tx.send(Err(failure.error()))
            .await
            .expect("relay the client failure");
        let err = h2_send(h2_holding_backend(server_io), client_io, body)
            .await
            .expect_err("a failed upload must reset the h2 stream");
        assert!(
            hyper_send_error_ended_by_gateway_upload_for_test(&err),
            "{failure:?}: h2 records the gateway's reset as user-initiated: {err:?}"
        );
        drop(tx);
    }
}

#[tokio::test]
async fn h2_backend_resets_stay_backend_failures() {
    for reason in [
        h2::Reason::CANCEL,
        h2::Reason::NO_ERROR,
        h2::Reason::PROTOCOL_ERROR,
        h2::Reason::INTERNAL_ERROR,
        h2::Reason::REFUSED_STREAM,
    ] {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        // The upload stays open: only the backend's reset can end it.
        let (tx, body) = upload_with_first_frame().await;
        let err = h2_send(h2_resetting_backend(server_io, reason), client_io, body)
            .await
            .expect_err("a backend reset before the head fails the exchange");
        assert!(
            !hyper_send_error_ended_by_gateway_upload_for_test(&err),
            "a backend {reason:?} reset must never be read as the gateway's: {err:?}"
        );
        // And the dispatcher keeps the transport classification for it.
        assert_eq!(
            pre_header_send_termination_for_test(false, false, true, false, None),
            Termination::Transport
        );
        drop(tx);
    }
}

#[tokio::test]
async fn h2_early_backend_response_keeps_the_backend_status() {
    // The backend commits its response head before the client's upload fails:
    // `send_request` resolves with that head, so no pre-header attribution
    // runs, and the original status is kept.
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (tx, body) = upload_with_first_frame().await;
    let response = h2_send(h2_early_answer_backend(server_io, 503), client_io, body)
        .await
        .expect("an early response head resolves the exchange");
    assert_eq!(response.status().as_u16(), 503);
    let _ = tx
        .send(Err(RelayedClientFailure::TransportError.error()))
        .await;
}

// ── The typed upload terminals that name the cause ───────────────────────

#[test]
fn a_proven_client_upload_failure_is_a_client_abort() {
    let client_failures = [
        // No pump: the adapter reads only the client body.
        (false, None),
        // A pump's own client-source terminal.
        (true, Some(Pump::SourceError)),
    ];
    for (pumped, pump) in client_failures {
        assert_eq!(
            pre_header_send_termination_for_test(true, false, true, pumped, pump),
            Termination::ClientAbort,
            "pumped {pumped}, pump {pump:?}"
        );
    }
}

#[test]
fn indeterminate_or_backend_first_terminals_keep_the_transport_class() {
    let cases = [
        // The backend failed first, whatever the upload did afterwards.
        (false, false, true, false, None),
        (false, false, true, true, Some(Pump::SourceError)),
        (false, true, true, true, Some(Pump::AuthorizationExpired)),
        (false, false, true, true, Some(Pump::WriteTimeout)),
        // A pumped upload's other terminals prove nothing about the client.
        (true, false, true, true, Some(Pump::Cancelled)),
        (true, false, true, true, Some(Pump::ConsumerGone)),
        (true, false, true, true, Some(Pump::Completed)),
        (true, false, true, true, None),
        // A replayable body has no client source that could fail.
        (true, false, false, false, None),
        (true, false, false, true, Some(Pump::SourceError)),
        (true, false, false, true, Some(Pump::Cancelled)),
    ];
    for (gateway, auth, streamed, pumped, pump) in cases {
        assert_eq!(
            pre_header_send_termination_for_test(gateway, auth, streamed, pumped, pump),
            Termination::Transport,
            "gateway {gateway}, auth {auth}, streamed {streamed}, pumped {pumped}, pump {pump:?}"
        );
    }
}

#[test]
fn gateway_deadlines_keep_their_own_outcome() {
    // The authorization lifetime wins over every other terminal, streaming or
    // replayable, because the gateway's security decision ended the upload.
    for (auth, streamed, pumped, pump) in [
        (true, true, false, None),
        (true, true, true, Some(Pump::SourceError)),
        (false, true, true, Some(Pump::AuthorizationExpired)),
        (true, false, true, Some(Pump::WriteTimeout)),
    ] {
        assert_eq!(
            pre_header_send_termination_for_test(true, auth, streamed, pumped, pump),
            Termination::AuthorizationExpired,
            "auth {auth}, streamed {streamed}, pumped {pumped}, pump {pump:?}"
        );
    }
    // The pump's write watermark is the backend-charged write timeout, for a
    // streaming or a replayable upload alike.
    for streamed in [true, false] {
        assert_eq!(
            pre_header_send_termination_for_test(
                true,
                false,
                streamed,
                true,
                Some(Pump::WriteTimeout)
            ),
            Termination::BackendWriteTimeout,
            "streamed {streamed}"
        );
    }
}

// ── Status, accounting, retry boundary, and breaker feedback ─────────────

#[test]
fn a_client_abort_is_a_health_neutral_499_never_replayed() {
    let response =
        pre_header_upload_termination_response_for_test(Termination::ClientAbort, false, None);
    assert_eq!(response.status_code, 499);
    assert_eq!(response.error_class, Some(ErrorClass::ClientDisconnect));
    assert!(
        !response.connection_error,
        "a client abort must never be replayed as a connect failure"
    );
    assert!(response.request_on_wire);
    assert_retry_boundary(&response);
    assert!(
        !charged_to_backend(&response),
        "a client abort must not train the breaker, even with 499 configured"
    );
}

#[test]
fn a_grpc_client_abort_is_a_health_neutral_cancelled() {
    let response =
        pre_header_upload_termination_response_for_test(Termination::ClientAbort, true, None);
    assert_eq!(response.status_code, 200, "gRPC errors ride HTTP 200");
    assert_eq!(
        response.headers.get("grpc-status").map(String::as_str),
        Some("1"),
        "the client's own cancellation is CANCELLED, never UNAVAILABLE"
    );
    assert_eq!(response.error_class, Some(ErrorClass::ClientDisconnect));
    assert_retry_boundary(&response);
    assert!(!charged_to_backend(&response));
}

#[test]
fn a_backend_write_watermark_stays_a_charged_timeout() {
    let http = pre_header_upload_termination_response_for_test(
        Termination::BackendWriteTimeout,
        false,
        None,
    );
    assert_eq!(http.status_code, 504);
    assert_eq!(http.error_class, Some(ErrorClass::ReadWriteTimeout));
    assert_retry_boundary(&http);
    assert!(
        charged_to_backend(&http),
        "a backend write stall is charged"
    );

    let grpc = pre_header_upload_termination_response_for_test(
        Termination::BackendWriteTimeout,
        true,
        None,
    );
    assert_eq!(
        grpc.headers.get("grpc-status").map(String::as_str),
        Some("4"),
        "DEADLINE_EXCEEDED"
    );
    assert_eq!(grpc.error_class, Some(ErrorClass::ReadWriteTimeout));
    assert!(charged_to_backend(&grpc));
}

#[test]
fn an_authorization_expiry_stays_the_neutral_placeholder() {
    let response = pre_header_upload_termination_response_for_test(
        Termination::AuthorizationExpired,
        false,
        None,
    );
    assert_eq!(response.status_code, 401);
    assert_eq!(response.error_class, Some(ErrorClass::ClientDisconnect));
    assert!(!response.connection_error);
    assert!(!charged_to_backend(&response));
}

#[test]
fn the_transport_fallback_is_still_a_charged_protocol_failure() {
    let response =
        pre_header_upload_termination_response_for_test(Termination::Transport, false, None);
    assert_eq!(response.status_code, 502);
    assert_eq!(response.error_class, Some(ErrorClass::ProtocolError));
    assert_retry_boundary(&response);
    assert!(charged_to_backend(&response));
}

/// The whole chain for each transport shape: a real hyper failure, its typed
/// proof, the attribution an unpumped streaming upload gets, and the breaker.
#[tokio::test]
async fn end_to_end_relayed_client_abort_is_neutral_and_backend_reset_is_charged() {
    // HTTP/1.1 relayed client abort (HBONE inner client, Unix-socket pool).
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (tx, body) = upload_with_first_frame().await;
    tx.send(Err(RelayedClientFailure::TransportError.error()))
        .await
        .expect("relay the client failure");
    let h1_err = h1_send(h1_holding_backend(server_io), client_io, body)
        .await
        .expect_err("h1 exchange fails");
    drop(tx);

    // HTTP/2 relayed client abort (sidecar mesh-mTLS, Unix h2c).
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (tx, body) = upload_with_first_frame().await;
    tx.send(Err(RelayedClientFailure::H2Cancel.error()))
        .await
        .expect("relay the client failure");
    let h2_err = h2_send(h2_holding_backend(server_io), client_io, body)
        .await
        .expect_err("h2 exchange fails");
    drop(tx);

    for err in [&h1_err, &h2_err] {
        let termination = pre_header_send_termination_for_test(
            hyper_send_error_ended_by_gateway_upload_for_test(err),
            false,
            true,
            false,
            None,
        );
        assert_eq!(termination, Termination::ClientAbort, "{err:?}");
        let response = pre_header_upload_termination_response_for_test(termination, false, None);
        assert!(!charged_to_backend(&response), "{err:?}");
    }

    // HTTP/2 backend-origin CANCEL while the client is still uploading.
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (tx, body) = upload_with_first_frame().await;
    let backend_err = h2_send(
        h2_resetting_backend(server_io, h2::Reason::CANCEL),
        client_io,
        body,
    )
    .await
    .expect_err("backend reset fails the exchange");
    drop(tx);
    let termination = pre_header_send_termination_for_test(
        hyper_send_error_ended_by_gateway_upload_for_test(&backend_err),
        false,
        true,
        false,
        None,
    );
    assert_eq!(termination, Termination::Transport);
}

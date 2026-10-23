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
    ClientUploadFaultForTest as Fault, PreHeaderSendTerminationForTest as Termination,
    UploadPumpOutcomeForTest as Pump, apply_circuit_breaker_outcome_for_test,
    client_upload_error_fault_for_test, hyper_send_error_ended_by_gateway_upload_for_test,
    pre_header_send_termination_for_test, pre_header_upload_termination_response_for_test,
    record_buffered_native_grpc_header_status_for_test,
};
use ferrum_edge::circuit_breaker::CircuitBreaker;
use ferrum_edge::config::types::CircuitBreakerConfig;
use ferrum_edge::plugins::TransactionSummary;
use ferrum_edge::retry::{BackendResponse, ErrorClass, request_reached_wire};
use http_body::Frame;
use http_body_util::{BodyExt, Empty, StreamBody};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
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
            pre_header_send_termination_for_test(false, false, true, false, None, None),
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
fn a_proven_client_disconnect_is_a_client_abort() {
    let client_disconnects = [
        // No pump: the adapter's latch recorded the client leaving.
        (false, None),
        // A pump's own client-source terminal, recorded as a disconnect.
        (true, Some(Pump::SourceError)),
    ];
    for (pumped, pump) in client_disconnects {
        assert_eq!(
            pre_header_send_termination_for_test(
                true,
                false,
                true,
                pumped,
                pump,
                Some(Fault::Disconnected)
            ),
            Termination::ClientAbort,
            "pumped {pumped}, pump {pump:?}"
        );
    }
}

#[test]
fn a_client_upload_failure_without_disconnect_proof_is_a_malformed_upload() {
    // A malformed upload, or a client failure with no recorded fault, is never
    // a client-closed request: the client may still be reading.
    for (pumped, pump) in [(false, None), (true, Some(Pump::SourceError))] {
        for fault in [Some(Fault::Malformed), None] {
            assert_eq!(
                pre_header_send_termination_for_test(true, false, true, pumped, pump, fault),
                Termination::MalformedUpload,
                "pumped {pumped}, pump {pump:?}, fault {fault:?}"
            );
        }
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
        for fault in [None, Some(Fault::Disconnected), Some(Fault::Malformed)] {
            assert_eq!(
                pre_header_send_termination_for_test(gateway, auth, streamed, pumped, pump, fault),
                Termination::Transport,
                "gateway {gateway}, auth {auth}, streamed {streamed}, pumped {pumped}, \
                 pump {pump:?}, fault {fault:?}"
            );
        }
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
            pre_header_send_termination_for_test(
                true,
                auth,
                streamed,
                pumped,
                pump,
                Some(Fault::Disconnected)
            ),
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
                Some(Pump::WriteTimeout),
                None
            ),
            Termination::BackendWriteTimeout,
            "streamed {streamed}"
        );
    }
}

// ── The typed client upload fault, from real frontend body errors ─────────

/// A served HTTP/1.1 frontend request: one signal per body DATA frame, and the
/// typed fault of the first error its body yields.
struct H1Frontend {
    frames: mpsc::UnboundedReceiver<()>,
    faults: mpsc::UnboundedReceiver<Fault>,
    server: tokio::task::JoinHandle<()>,
}

impl H1Frontend {
    fn serve<I>(io: I) -> Self
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (frame_tx, frames) = mpsc::unbounded_channel();
        let (fault_tx, faults) = mpsc::unbounded_channel();
        let service = service_fn(move |req: Request<Incoming>| {
            let frame_tx = frame_tx.clone();
            let fault_tx = fault_tx.clone();
            async move {
                let mut body = req.into_body();
                while let Some(frame) = body.frame().await {
                    match frame {
                        Ok(_) => {
                            let _ = frame_tx.send(());
                        }
                        Err(err) => {
                            let _ = fault_tx.send(client_upload_error_fault_for_test(&err));
                            break;
                        }
                    }
                }
                Ok::<_, Infallible>(Response::new(Empty::<Bytes>::new()))
            }
        });
        let server = tokio::spawn(async move {
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(io), service)
                .await;
        });
        Self {
            frames,
            faults,
            server,
        }
    }

    async fn first_frame(&mut self) {
        tokio::time::timeout(STEP, self.frames.recv())
            .await
            .expect("the first upload bytes arrive in time")
            .expect("a body frame");
    }

    async fn fault(mut self) -> Fault {
        let fault = tokio::time::timeout(STEP, self.faults.recv())
            .await
            .expect("the frontend body must fail in time")
            .expect("a body fault");
        self.server.abort();
        fault
    }
}

const TRUNCATED_CHUNKED_UPLOAD: &[u8] =
    b"POST /upload HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel";

#[tokio::test]
async fn an_h1_client_that_half_closes_mid_upload_is_not_proven_gone() {
    // A client may shut down its write side mid-upload and keep reading: the
    // early EOF proves an incomplete request, not a departed client.
    let (mut client, server_io) = tokio::io::duplex(64 * 1024);
    let frontend = H1Frontend::serve(server_io);
    client
        .write_all(TRUNCATED_CHUNKED_UPLOAD)
        .await
        .expect("write a truncated upload");
    client.shutdown().await.expect("half-close the write side");
    assert_eq!(frontend.fault().await, Fault::Malformed);
    drop(client);
}

#[tokio::test]
async fn an_h1_client_whose_connection_resets_mid_upload_is_a_disconnect() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind frontend");
    let addr = listener.local_addr().expect("frontend addr");
    let mut client = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect frontend");
    let (server_io, _) = listener.accept().await.expect("accept frontend");
    let mut frontend = H1Frontend::serve(server_io);
    client
        .write_all(TRUNCATED_CHUNKED_UPLOAD)
        .await
        .expect("write a truncated upload");
    frontend.first_frame().await;
    // An abortive close: the frontend read fails with a connection reset.
    client.set_zero_linger().expect("set abortive close");
    drop(client);
    assert_eq!(frontend.fault().await, Fault::Disconnected);
}

#[tokio::test]
async fn an_h1_client_with_invalid_chunk_framing_is_malformed() {
    let (mut client, server_io) = tokio::io::duplex(64 * 1024);
    // Still connected and reading: only its framing is bad.
    let frontend = H1Frontend::serve(server_io);
    client
        .write_all(b"POST /upload HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n")
        .await
        .expect("write a malformed chunk");
    assert_eq!(frontend.fault().await, Fault::Malformed);
    drop(client);
}

#[tokio::test]
async fn an_h2_client_reset_mid_upload_is_a_disconnect() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (fault_tx, mut fault_rx) = mpsc::unbounded_channel();
    let (first_tx, mut first_rx) = mpsc::unbounded_channel::<()>();
    let service = service_fn(move |req: Request<Incoming>| {
        let fault_tx = fault_tx.clone();
        let first_tx = first_tx.clone();
        async move {
            let mut body = req.into_body();
            while let Some(frame) = body.frame().await {
                match frame {
                    Ok(_) => {
                        let _ = first_tx.send(());
                    }
                    Err(err) => {
                        let _ = fault_tx.send(client_upload_error_fault_for_test(&err));
                        break;
                    }
                }
            }
            Ok::<_, Infallible>(Response::new(Empty::<Bytes>::new()))
        }
    });
    let server = tokio::spawn(async move {
        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(server_io), service)
            .await;
    });
    let (client, connection) = h2::client::handshake(client_io)
        .await
        .expect("h2 client handshake");
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut client = client.ready().await.expect("h2 client ready");
    let request = Request::builder()
        .method("POST")
        .uri("http://frontend.test/upload")
        .body(())
        .expect("request");
    let (_response, mut upload) = client.send_request(request, false).expect("open stream");
    upload
        .send_data(Bytes::from_static(b"hello"), false)
        .expect("first upload frame");
    tokio::time::timeout(STEP, first_rx.recv())
        .await
        .expect("the first frame arrives in time");
    upload.send_reset(h2::Reason::CANCEL);
    let fault = tokio::time::timeout(STEP, fault_rx.recv())
        .await
        .expect("the reset reaches the body in time")
        .expect("a body fault");
    assert_eq!(fault, Fault::Disconnected);
    driver.abort();
    server.abort();
}

#[test]
fn typed_io_and_h2_faults_classify_without_heuristics() {
    let malformed = std::io::Error::new(std::io::ErrorKind::InvalidData, "bad chunk size");
    assert_eq!(
        client_upload_error_fault_for_test(&malformed),
        Fault::Malformed
    );
    let malformed = std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad chunk ext");
    assert_eq!(
        client_upload_error_fault_for_test(&malformed),
        Fault::Malformed
    );
    // The payload of a wrapping io::Error is inspected too.
    let wrapped = std::io::Error::other(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "bad trailer",
    ));
    assert_eq!(
        client_upload_error_fault_for_test(&wrapped),
        Fault::Malformed
    );
    // Typed proof the connection is gone.
    for kind in [
        std::io::ErrorKind::ConnectionReset,
        std::io::ErrorKind::ConnectionAborted,
        std::io::ErrorKind::BrokenPipe,
        std::io::ErrorKind::NotConnected,
    ] {
        let gone = std::io::Error::new(kind, "client gone");
        assert_eq!(
            client_upload_error_fault_for_test(&gone),
            Fault::Disconnected,
            "{kind:?}"
        );
    }
    // An early EOF (a client may half-close and keep reading), a timeout, or
    // an untyped error is not proof the client left.
    for kind in [
        std::io::ErrorKind::UnexpectedEof,
        std::io::ErrorKind::TimedOut,
        std::io::ErrorKind::Other,
    ] {
        let incomplete = std::io::Error::new(kind, "upload incomplete");
        assert_eq!(
            client_upload_error_fault_for_test(&incomplete),
            Fault::Malformed,
            "{kind:?}"
        );
    }
    // A bare reason (the reset the END_STREAM gate raises for a stream that
    // ended without one) was not sent by the client: not proof either.
    let reset = h2::Error::from(h2::Reason::CANCEL);
    assert_eq!(client_upload_error_fault_for_test(&reset), Fault::Malformed);
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
            Some(Fault::Disconnected),
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
        Some(Fault::Disconnected),
    );
    assert_eq!(termination, Termination::Transport);
}

#[test]
fn a_malformed_upload_is_a_health_neutral_400_never_499() {
    let response =
        pre_header_upload_termination_response_for_test(Termination::MalformedUpload, false, None);
    assert_eq!(
        response.status_code, 400,
        "a client that may still be reading gets a bad request, never 499"
    );
    assert_eq!(response.error_class, Some(ErrorClass::ClientDisconnect));
    assert!(!response.connection_error);
    assert_retry_boundary(&response);
    assert!(!charged_to_backend(&response));

    let grpc =
        pre_header_upload_termination_response_for_test(Termination::MalformedUpload, true, None);
    assert_eq!(grpc.status_code, 200, "gRPC errors ride HTTP 200");
    assert_eq!(
        grpc.headers.get("grpc-status").map(String::as_str),
        Some("3"),
        "INVALID_ARGUMENT"
    );
    assert!(!charged_to_backend(&grpc));
}

fn grpc_summary(metadata: HashMap<String, String>) -> TransactionSummary {
    TransactionSummary {
        response_status_code: 200,
        metadata: metadata.into_iter().collect(),
        ..TransactionSummary::default()
    }
}

#[test]
fn a_buffered_mesh_grpc_cancel_reaches_the_transaction_summary_as_cancelled() {
    let response =
        pre_header_upload_termination_response_for_test(Termination::ClientAbort, true, None);
    let mut metadata = HashMap::from([("request_protocol".to_string(), "grpc".to_string())]);
    record_buffered_native_grpc_header_status_for_test(
        &mut metadata,
        true,
        true,
        &response.headers,
    );
    let summary = grpc_summary(metadata);
    assert_eq!(summary.grpc_status(), Some(1), "CANCELLED, never UNKNOWN");
    let logged = serde_json::to_value(&summary).expect("serialize summary");
    assert_eq!(logged["grpc_status"], 1);
}

#[test]
fn the_buffered_grpc_status_refresh_keeps_existing_and_grpc_web_rules() {
    let headers = HashMap::from([("grpc-status".to_string(), "14".to_string())]);
    // A status a gateway terminal already stamped wins.
    let mut stamped = HashMap::from([("grpc_status".to_string(), "4".to_string())]);
    record_buffered_native_grpc_header_status_for_test(&mut stamped, true, true, &headers);
    assert_eq!(stamped.get("grpc_status").map(String::as_str), Some("4"));
    // gRPC-Web (not native) and streaming responses keep their own rules.
    for (native, buffered) in [(false, true), (true, false)] {
        let mut metadata = HashMap::new();
        record_buffered_native_grpc_header_status_for_test(
            &mut metadata,
            native,
            buffered,
            &headers,
        );
        assert!(
            !metadata.contains_key("grpc_status"),
            "native {native}, buffered {buffered}"
        );
    }
}

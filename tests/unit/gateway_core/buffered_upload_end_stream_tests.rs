//! Issue #6022 (the #6042 review, N1): a BUFFERED request collect must not
//! accept an HTTP/2 client's masked reset as a complete body.
//!
//! hyper reports an inbound `RST_STREAM(NO_ERROR)` as a clean end of the
//! request body. hyper's server drops the service future when it sees the
//! reset, but only while that future is still pending, so a collect that reads
//! the last DATA and the reset in one poll used to finish with the truncated
//! body. These tests run the PRODUCTION collectors (the early `before_proxy`
//! prebuffer, which also serves HBONE / mesh-mTLS body preparation, and the
//! native-gRPC buffered collect, both with and without a size limit) over real
//! hyper connections:
//!
//! * a masked reset ends the collect as a client disconnect / failed read;
//! * an HTTP/2 END_STREAM and an HTTP/1.1 chunked EOF still complete the body.
//!
//! The H1/H2 retry/body-plugin collect inside `proxy_to_backend` has no test
//! seam of its own; `proxy_tests::test_buffered_h2_request_collectors_require_h2_end_stream`
//! pins that it uses the same gate.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncWriteExt, DuplexStream};
use tokio::sync::oneshot;

use ferrum_edge::_test_support::{
    EarlyBodyCollectOutcomeForTest as EarlyOutcome,
    GrpcBufferedCollectOutcomeForTest as GrpcOutcome, buffer_early_request_body_for_test,
    collect_grpc_request_body_for_test,
};

const PARTIAL: &[u8] = b"partial";
const H1_CHUNKED_UPLOAD: &[u8] = b"POST /upload HTTP/1.1\r\nhost: edge.example\r\n\
    transfer-encoding: chunked\r\n\r\n7\r\npartial\r\n0\r\n\r\n";
const MAX_BODY: usize = 64 * 1024;
const WAIT: Duration = Duration::from_secs(5);

/// The production buffered collector a test server runs.
#[derive(Clone, Copy, Debug)]
enum Collector {
    /// `buffer_request_body_for_before_proxy`.
    Early,
    /// `collect_grpc_request_body` with `max_grpc_recv_size_bytes > 0`.
    GrpcLimited,
    /// `collect_grpc_request_body` with no size limit.
    GrpcUnlimited,
}

const COLLECTORS: [Collector; 3] = [
    Collector::Early,
    Collector::GrpcLimited,
    Collector::GrpcUnlimited,
];

/// A collector's verdict, normalized across the two outcome types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    /// The body was accepted as complete, with this many bytes.
    Complete(usize),
    /// The collect failed as a client disconnect / failed read.
    Refused,
    /// Any other terminal; never expected here.
    Unexpected,
}

async fn run_collector(collector: Collector, request: Request<Incoming>) -> Verdict {
    match collector {
        Collector::Early => {
            let outcome =
                buffer_early_request_body_for_test(request, MAX_BODY, 0, None, None).await;
            match outcome {
                EarlyOutcome::Collected(len) => Verdict::Complete(len),
                EarlyOutcome::ClientDisconnected => Verdict::Refused,
                _ => Verdict::Unexpected,
            }
        }
        Collector::GrpcLimited | Collector::GrpcUnlimited => {
            let max = match collector {
                Collector::GrpcLimited => MAX_BODY,
                _ => 0,
            };
            match collect_grpc_request_body_for_test(request, max, 0).await {
                GrpcOutcome::Collected(len) => Verdict::Complete(len),
                GrpcOutcome::ReadFailed => Verdict::Refused,
                _ => Verdict::Unexpected,
            }
        }
    }
}

type Report = oneshot::Receiver<Verdict>;
type ReportSlot = Arc<Mutex<Option<oneshot::Sender<Verdict>>>>;

fn report_slot() -> (ReportSlot, Report) {
    let (tx, rx) = oneshot::channel();
    (Arc::new(Mutex::new(Some(tx))), rx)
}

fn take_reporter(slot: &ReportSlot) -> Option<oneshot::Sender<Verdict>> {
    slot.lock().expect("report slot").take()
}

/// Serve one HTTP/2 connection and hand its first request to a SPAWNED task
/// running `collector`. Spawning keeps the collect alive after hyper drops the
/// service future on the client's reset, so the test observes the collector's
/// own verdict on that reset rather than hyper's cancellation.
fn serve_h2_detached(io: DuplexStream, collector: Collector) -> Report {
    let (slot, report) = report_slot();
    let service = service_fn(move |request: Request<Incoming>| {
        let reporter = take_reporter(&slot);
        async move {
            if let Some(tx) = reporter {
                tokio::spawn(async move {
                    let _ = tx.send(run_collector(collector, request).await);
                });
            }
            // Never answer: the response must not race the collect.
            std::future::pending::<()>().await;
            Ok::<_, Infallible>(Response::new(Empty::<Bytes>::new()))
        }
    });
    tokio::spawn(async move {
        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(io), service)
            .await;
    });
    report
}

/// Serve one HTTP/2 connection and run `collector` INSIDE the service future,
/// as the dispatchers do.
fn serve_h2_inline(io: DuplexStream, collector: Collector) -> Report {
    let (slot, report) = report_slot();
    let service = service_fn(move |request: Request<Incoming>| {
        let reporter = take_reporter(&slot);
        async move {
            let verdict = run_collector(collector, request).await;
            if let Some(tx) = reporter {
                let _ = tx.send(verdict);
            }
            Ok::<_, Infallible>(Response::new(Empty::<Bytes>::new()))
        }
    });
    tokio::spawn(async move {
        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(io), service)
            .await;
    });
    report
}

/// How the HTTP/2 client ends its upload after one DATA frame.
#[derive(Clone, Copy, Debug)]
enum ClientEnd {
    /// END_STREAM on the DATA frame.
    EndStream,
    /// `RST_STREAM(NO_ERROR)` right after the DATA frame.
    NoErrorReset,
}

/// Every client handle for one upload. Held until the test ends: dropping the
/// response future and send stream of a half-closed stream makes h2 reset it
/// with CANCEL, which would race the END_STREAM case.
struct ClientUpload {
    _client: h2::client::SendRequest<Bytes>,
    _response: h2::client::ResponseFuture,
    _stream: h2::SendStream<Bytes>,
}

/// Open an HTTP/2 upload with no `Content-Length`, send [`PARTIAL`] as one DATA
/// frame, then end it with `end`. Both frames are queued before the client
/// connection task writes, so the server reads them together.
async fn h2_upload(io: DuplexStream, end: ClientEnd) -> ClientUpload {
    let (client, connection) = h2::client::handshake(io).await.expect("h2 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut client = client.ready().await.expect("h2 client ready");
    let request = http::Request::builder()
        .method("POST")
        .uri("http://edge.example/upload")
        .header("content-type", "application/grpc")
        .body(())
        .expect("request");
    let (response, mut stream) = client
        .send_request(request, false)
        .expect("request HEADERS");
    let data = Bytes::from_static(PARTIAL);
    match end {
        ClientEnd::EndStream => stream.send_data(data, true).expect("final DATA"),
        ClientEnd::NoErrorReset => {
            stream.send_data(data, false).expect("partial DATA");
            stream.send_reset(h2::Reason::NO_ERROR);
        }
    }
    ClientUpload {
        _client: client,
        _response: response,
        _stream: stream,
    }
}

async fn verdict(report: Report, case: &str) -> Verdict {
    tokio::time::timeout(WAIT, report)
        .await
        .unwrap_or_else(|_| panic!("{case}: the collector never reported"))
        .unwrap_or_else(|_| panic!("{case}: the collector task ended without a verdict"))
}

#[tokio::test]
async fn masked_h2_reset_is_never_a_complete_buffered_body() {
    for collector in COLLECTORS {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let report = serve_h2_detached(server_io, collector);
        let _upload = h2_upload(client_io, ClientEnd::NoErrorReset).await;
        assert_eq!(
            verdict(report, &format!("{collector:?}")).await,
            Verdict::Refused,
            "{collector:?}: a client RST_STREAM(NO_ERROR) must not complete the body"
        );
    }
}

#[tokio::test]
async fn h2_end_stream_still_completes_a_buffered_body() {
    for collector in COLLECTORS {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let report = serve_h2_detached(server_io, collector);
        let _upload = h2_upload(client_io, ClientEnd::EndStream).await;
        assert_eq!(
            verdict(report, &format!("{collector:?}")).await,
            Verdict::Complete(PARTIAL.len()),
            "{collector:?}"
        );
    }
}

#[tokio::test]
async fn masked_h2_reset_read_in_the_collecting_poll_is_not_collected() {
    // The race N1 describes: the last DATA and the reset arrive together, and
    // the collect inside the service future reads both in one poll. hyper may
    // instead drop the service before it reports; either way the body is never
    // accepted as complete.
    for collector in COLLECTORS {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let report = serve_h2_inline(server_io, collector);
        let _upload = h2_upload(client_io, ClientEnd::NoErrorReset).await;
        match tokio::time::timeout(WAIT, report).await {
            Ok(Ok(verdict)) => assert_eq!(verdict, Verdict::Refused, "{collector:?}"),
            // hyper dropped the service future on the reset: nothing collected.
            Ok(Err(_)) | Err(_) => {}
        }
    }
}

#[tokio::test]
async fn h1_chunked_eof_still_completes_a_buffered_body() {
    // The gate is HTTP/2 only: a valid HTTP/1.1 chunked EOF need not update
    // `is_end_stream()`.
    for collector in COLLECTORS {
        let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (slot, report) = report_slot();
        let service = service_fn(move |request: Request<Incoming>| {
            let reporter = take_reporter(&slot);
            async move {
                let verdict = run_collector(collector, request).await;
                if let Some(tx) = reporter {
                    let _ = tx.send(verdict);
                }
                Ok::<_, Infallible>(Response::new(Empty::<Bytes>::new()))
            }
        });
        tokio::spawn(async move {
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(server_io), service)
                .await;
        });
        client_io
            .write_all(H1_CHUNKED_UPLOAD)
            .await
            .expect("chunked request");
        assert_eq!(
            verdict(report, &format!("{collector:?}")).await,
            Verdict::Complete(PARTIAL.len()),
            "{collector:?}"
        );
        drop(client_io);
    }
}

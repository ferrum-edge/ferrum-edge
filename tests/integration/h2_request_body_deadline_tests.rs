//! Hyper patch 007 (`hyper::ext::Http2BodyDeadline`): an absolute HTTP/2
//! client request-body deadline resets the stream from hyper's own body-pipe
//! task, even while that pipe holds a chunk the peer granted no window for and
//! therefore polls nothing the caller owns.
//!
//! This is the gateway's client RPC deadline on a still-open gRPC upload: the
//! response may already be finished, and the backend has stopped reading.

use std::convert::Infallible;
use std::time::Duration;

use bytes::Bytes;
use http_body::Frame;
use http_body_util::{BodyExt, Empty, StreamBody};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};

static CHUNK: [u8; 16 * 1024] = [0; 16 * 1024];

fn upload_chunk() -> Result<Frame<Bytes>, Infallible> {
    Ok(Frame::data(Bytes::from_static(&CHUNK)))
}

type UploadChunks = fn() -> Result<Frame<Bytes>, Infallible>;
type UploadBody = StreamBody<futures_util::stream::RepeatWith<UploadChunks>>;

/// Send a never-ending upload to a backend that answers at once and then
/// stops reading, so the client's body pipe parks on flow control. Report
/// whether the backend observes the stream reset.
async fn backend_sees_the_stalled_upload_reset(deadline_after: Option<Duration>) -> bool {
    let (client_io, server_io) = tokio::io::duplex(1 << 20);
    let (upload_tx, mut upload_rx) = tokio::sync::mpsc::unbounded_channel::<Incoming>();
    tokio::spawn(async move {
        let service = hyper::service::service_fn(move |request: hyper::Request<Incoming>| {
            let upload_tx = upload_tx.clone();
            async move {
                // Keep the upload unread: h2 grants it no further window.
                let _ = upload_tx.send(request.into_body());
                Ok::<_, Infallible>(hyper::Response::new(Empty::<Bytes>::new()))
            }
        });
        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .timer(TokioTimer::new())
            .serve_connection(TokioIo::new(server_io), service)
            .await;
    });

    let (mut sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .timer(TokioTimer::new())
        .handshake::<_, UploadBody>(TokioIo::new(client_io))
        .await
        .expect("HTTP/2 handshake");
    tokio::spawn(connection);

    let upload: UploadBody = StreamBody::new(futures_util::stream::repeat_with(
        upload_chunk as UploadChunks,
    ));
    let mut request = hyper::Request::post("http://backend.test/pkg.Service/Upload")
        .body(upload)
        .expect("request");
    if let Some(after) = deadline_after {
        request
            .extensions_mut()
            .insert(hyper::ext::Http2BodyDeadline::new(
                std::time::Instant::now() + after,
            ));
    }
    // The response completes at once; the upload keeps going in hyper's pipe.
    let response = sender
        .send_request(request)
        .await
        .expect("response headers");
    drop(response);
    let mut upload = upload_rx
        .recv()
        .await
        .expect("the backend received the request");

    // Let the deadline pass while the client pipe is parked on flow control.
    tokio::time::sleep(Duration::from_millis(600)).await;

    // Drain what h2 buffered. A reset surfaces as an error; without one the
    // upload just keeps flowing once the backend reads.
    let outcome = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match upload.frame().await {
                Some(Ok(_)) => continue,
                Some(Err(_)) => return true,
                None => return false,
            }
        }
    })
    .await;
    matches!(outcome, Ok(true))
}

#[tokio::test]
async fn body_deadline_resets_an_upload_parked_on_backend_flow_control() {
    assert!(
        backend_sees_the_stalled_upload_reset(Some(Duration::from_millis(300))).await,
        "the body deadline must reset the stream from hyper's pipe task even while that \
         pipe holds a chunk the backend granted no window for"
    );
}

#[tokio::test]
async fn without_a_body_deadline_the_parked_upload_is_not_reset() {
    assert!(
        !backend_sees_the_stalled_upload_reset(None).await,
        "negative control: nothing else resets a credit-stalled upload"
    );
}

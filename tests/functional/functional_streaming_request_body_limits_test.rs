//! Functional coverage for request body limits when client size is unknown.
//!
//! The Content-Length fast path is covered separately. These tests exercise the
//! streaming guard used when clients send request bodies without a
//! `Content-Length`, such as HTTP/1.1 chunked uploads and HTTP/2 DATA streams.

use crate::common::{TestGateway, TestGatewayBuilder};

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body::Frame;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::convert::Infallible;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::sleep;

const LIMIT_BYTES: &str = "4";
const FULL_CLIENT_BODY: &[u8] = b"abcde";

#[ignore]
#[tokio::test]
async fn functional_streaming_request_body_limit_http1_without_content_length() {
    let backend = spawn_collecting_backend().await;
    let mut gateway = request_limit_gateway_builder(backend.port)
        .spawn()
        .await
        .expect("start streaming request-limit gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");

    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("http1 client");
    let body = reqwest::Body::wrap_stream(futures_util::stream::iter([
        Ok::<Bytes, std::io::Error>(Bytes::from_static(b"abc")),
        Ok::<Bytes, std::io::Error>(Bytes::from_static(b"de")),
    ]));

    let resp = client
        .post(gateway.proxy_url("/upload"))
        .body(body)
        .send()
        .await
        .expect("http1 streaming request");

    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_no_complete_oversized_body(&backend).await;

    gateway.shutdown();
    backend.abort();
}

#[ignore]
#[tokio::test]
async fn functional_streaming_request_body_limit_h2_without_content_length() {
    let backend = spawn_collecting_backend().await;
    let mut gateway = request_limit_gateway_builder(backend.port)
        .spawn()
        .await
        .expect("start streaming request-limit gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");

    let stream = TcpStream::connect(("127.0.0.1", gateway.proxy_port))
        .await
        .expect("connect h2c");
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .expect("h2 handshake");
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let body_stream = futures_util::stream::iter([
        Ok::<Frame<Bytes>, Infallible>(Frame::data(Bytes::from_static(b"abc"))),
        Ok::<Frame<Bytes>, Infallible>(Frame::data(Bytes::from_static(b"de"))),
    ]);
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://127.0.0.1:{}/upload", gateway.proxy_port))
        .body(StreamBody::new(body_stream))
        .expect("build h2 streaming request");

    let resp = sender.send_request(req).await.expect("send h2 request");

    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let _ = resp.into_body().collect().await;
    assert_no_complete_oversized_body(&backend).await;

    drop(sender);
    conn_task.abort();
    gateway.shutdown();
    backend.abort();
}

fn request_limit_gateway_builder(backend_port: u16) -> TestGatewayBuilder {
    TestGateway::builder()
        .mode_file(request_limit_config(backend_port))
        .log_level("warn")
        .env("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES", LIMIT_BYTES)
}

fn request_limit_config(backend_port: u16) -> String {
    let config = serde_json::json!({
        "version": "1",
        "proxies": [{
            "id": "streaming-request-limits",
            "listen_path": "/upload",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
            "pool_enable_http2": false
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": []
    });
    serde_yaml::to_string(&config).expect("serialize streaming request-limit config")
}

struct CollectingBackend {
    port: u16,
    requests_seen: Arc<AtomicUsize>,
    complete_oversized_bodies_seen: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl CollectingBackend {
    fn abort(self) {
        self.task.abort();
    }
}

async fn spawn_collecting_backend() -> CollectingBackend {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind collecting backend");
    let port = listener.local_addr().expect("backend addr").port();
    let requests_seen = Arc::new(AtomicUsize::new(0));
    let complete_oversized_bodies_seen = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn(run_collecting_backend(
        listener,
        Arc::clone(&requests_seen),
        Arc::clone(&complete_oversized_bodies_seen),
    ));

    CollectingBackend {
        port,
        requests_seen,
        complete_oversized_bodies_seen,
        task,
    }
}

async fn run_collecting_backend(
    listener: TcpListener,
    requests_seen: Arc<AtomicUsize>,
    complete_oversized_bodies_seen: Arc<AtomicUsize>,
) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let requests_seen = Arc::clone(&requests_seen);
        let complete_oversized_bodies_seen = Arc::clone(&complete_oversized_bodies_seen);
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req: Request<Incoming>| {
                let requests_seen = Arc::clone(&requests_seen);
                let complete_oversized_bodies_seen = Arc::clone(&complete_oversized_bodies_seen);
                async move {
                    requests_seen.fetch_add(1, Ordering::SeqCst);
                    if let Ok(collected) = req.into_body().collect().await {
                        let body = collected.to_bytes();
                        if body.as_ref() == FULL_CLIENT_BODY {
                            complete_oversized_bodies_seen.fetch_add(1, Ordering::SeqCst);
                        }
                    }

                    Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });
    }
}

async fn assert_no_complete_oversized_body(backend: &CollectingBackend) {
    sleep(Duration::from_millis(100)).await;
    assert!(
        backend.requests_seen.load(Ordering::SeqCst) <= 1,
        "streaming request limit retried an oversized upload"
    );
    assert_eq!(
        backend
            .complete_oversized_bodies_seen
            .load(Ordering::SeqCst),
        0,
        "streaming request limit forwarded the complete oversized upload"
    );
}

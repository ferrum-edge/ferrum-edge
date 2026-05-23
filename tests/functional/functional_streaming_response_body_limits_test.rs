//! Functional coverage for response body limits when backend size is unknown.
//!
//! The Content-Length fast path is covered separately. These tests exercise the
//! streaming guard used when the backend response has no `Content-Length`, such
//! as HTTP/1.1 chunked responses.

use crate::common::{TestGateway, TestGatewayBuilder};

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::sleep;

const LIMIT_BYTES: &str = "4";
const FULL_BACKEND_BODY: &[u8] = b"abcde";

#[ignore]
#[tokio::test]
async fn functional_streaming_response_body_limit_http1_without_content_length() {
    let (backend_port, backend_hits, backend_task) = spawn_chunked_backend().await;
    let mut gateway = response_limit_gateway_builder(backend_port)
        .spawn()
        .await
        .expect("start streaming response-limit gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");

    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("http1 client");
    let resp = client
        .get(gateway.proxy_url("/stream"))
        .send()
        .await
        .expect("http1 streaming response");

    assert_eq!(resp.status(), StatusCode::OK);
    assert_streaming_body_cutoff(resp.bytes().await.map(|b| b.to_vec()));
    assert_backend_hit_once(&backend_hits).await;

    gateway.shutdown();
    backend_task.abort();
}

#[ignore]
#[tokio::test]
async fn functional_streaming_response_body_limit_h2_without_content_length() {
    let (backend_port, backend_hits, backend_task) = spawn_chunked_backend().await;
    let mut gateway = response_limit_gateway_builder(backend_port)
        .spawn()
        .await
        .expect("start streaming response-limit gateway");
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

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://127.0.0.1:{}/stream", gateway.proxy_port))
        .body(Empty::<Bytes>::new())
        .expect("build h2 request");
    let resp = sender.send_request(req).await.expect("send h2 request");

    assert_eq!(resp.status(), StatusCode::OK);
    let body_result = resp
        .into_body()
        .collect()
        .await
        .map(|collected| collected.to_bytes().to_vec());
    assert_streaming_body_cutoff(body_result);
    assert_backend_hit_once(&backend_hits).await;

    drop(sender);
    conn_task.abort();
    gateway.shutdown();
    backend_task.abort();
}

fn response_limit_gateway_builder(backend_port: u16) -> TestGatewayBuilder {
    TestGateway::builder()
        .mode_file(response_limit_config(backend_port))
        .log_level("warn")
        .env("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES", LIMIT_BYTES)
}

fn response_limit_config(backend_port: u16) -> String {
    let config = serde_json::json!({
        "version": "1",
        "proxies": [{
            "id": "streaming-response-limits",
            "listen_path": "/stream",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
            "pool_enable_http2": false,
            "response_body_mode": "stream"
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": []
    });
    serde_yaml::to_string(&config).expect("serialize streaming response-limit config")
}

async fn spawn_chunked_backend() -> (u16, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind chunked backend");
    let port = listener.local_addr().expect("backend addr").port();
    let hits = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn(run_chunked_backend(listener, Arc::clone(&hits)));
    (port, hits, task)
}

async fn run_chunked_backend(listener: TcpListener, hits: Arc<AtomicUsize>) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let hits = Arc::clone(&hits);
        tokio::spawn(async move {
            let mut buf = vec![0; 4096];
            let n = match stream.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => return,
            };
            let request = String::from_utf8_lossy(&buf[..n]);
            if request.starts_with("GET /stream ") {
                hits.fetch_add(1, Ordering::SeqCst);
            }
            let response = b"HTTP/1.1 200 OK\r\n\
                Transfer-Encoding: chunked\r\n\
                Content-Type: text/plain\r\n\
                Connection: close\r\n\
                \r\n\
                3\r\nabc\r\n\
                2\r\nde\r\n\
                0\r\n\r\n";
            let _ = stream.write_all(response).await;
            let _ = stream.shutdown().await;
        });
    }
}

fn assert_streaming_body_cutoff<E: std::fmt::Display>(body_result: Result<Vec<u8>, E>) {
    if let Ok(body) = body_result {
        assert_ne!(
            body, FULL_BACKEND_BODY,
            "streaming size guard allowed the complete oversized backend body"
        );
    }
}

async fn assert_backend_hit_once(hits: &AtomicUsize) {
    sleep(Duration::from_millis(100)).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "streaming response limit should inspect exactly one backend response"
    );
}

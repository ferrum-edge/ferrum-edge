//! Functional coverage for the global request body size limit.
//!
//! The global `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` guard should reject
//! oversized requests at the frontend protocol boundary before opening a
//! backend connection.

use crate::common::{TestGateway, TestGatewayBuilder};
use crate::scaffolding::clients::{GetOptions, Http3Client};
use crate::scaffolding::reserve_colocated_tcp_udp;

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::sleep;

const LIMIT_BYTES: &str = "4";
const OVERSIZED_BODY: &[u8] = b"abcde";

#[ignore]
#[tokio::test]
async fn functional_request_body_limits_http1_content_length_rejected_before_backend() {
    let (backend_port, backend_hits, backend_task) = spawn_counting_backend().await;
    let mut gateway = body_limit_gateway_builder(backend_port)
        .spawn()
        .await
        .expect("start body-limit gateway");
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
        .post(gateway.proxy_url("/body"))
        .header(
            http::header::CONTENT_LENGTH,
            OVERSIZED_BODY.len().to_string(),
        )
        .body(Bytes::from_static(OVERSIZED_BODY))
        .send()
        .await
        .expect("http1 oversized request");
    let status = resp.status();
    let body = resp.text().await.expect("body text");

    assert_body_limit_response(status, &body);
    assert_backend_not_hit(&backend_hits).await;

    gateway.shutdown();
    backend_task.abort();
}

#[ignore]
#[tokio::test]
async fn functional_request_body_limits_h2_content_length_rejected_before_backend() {
    let (backend_port, backend_hits, backend_task) = spawn_counting_backend().await;
    let mut gateway = body_limit_gateway_builder(backend_port)
        .spawn()
        .await
        .expect("start body-limit gateway");
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
        .method(Method::POST)
        .uri(format!("http://127.0.0.1:{}/body", gateway.proxy_port))
        .header(
            http::header::CONTENT_LENGTH,
            OVERSIZED_BODY.len().to_string(),
        )
        .body(Full::new(Bytes::from_static(OVERSIZED_BODY)))
        .expect("build h2 request");
    // Over HTTP/2 the gateway fast-rejects on the oversized Content-Length
    // without draining the body (draining an unbounded over-limit body would be
    // a DoS vector), so the client's `send_request` future may observe the 413
    // or may instead see the request stream reset mid-upload (a BrokenPipe /
    // stream error) — especially under CI CPU contention. Both are valid
    // rejections. The `assert_backend_not_hit` below is the authoritative check
    // that the over-limit body never reached the backend regardless of which
    // outcome the client saw.
    match sender.send_request(req).await {
        Ok(resp) => {
            let status = resp.status();
            let body = resp
                .into_body()
                .collect()
                .await
                .map(|b| b.to_bytes())
                .unwrap_or_default();
            let body = String::from_utf8_lossy(&body);
            assert_body_limit_response(status, &body);
        }
        Err(e) => {
            assert!(
                !e.is_timeout(),
                "gateway hung on oversized H2 upload instead of rejecting it: {e}"
            );
        }
    }
    assert_backend_not_hit(&backend_hits).await;

    drop(sender);
    conn_task.abort();
    gateway.shutdown();
    backend_task.abort();
}

#[ignore]
#[tokio::test]
async fn functional_request_body_limits_h3_content_length_rejected_before_backend() {
    let (backend_port, backend_hits, backend_task) = spawn_counting_backend().await;
    let https_port = reserve_https_port().await;
    let mut gateway = body_limit_gateway_builder(backend_port)
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .spawn()
        .await
        .expect("start h3 body-limit gateway");

    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://localhost:{https_port}/body");
    let options = GetOptions::default()
        .method(Method::POST)
        .header(
            http::header::CONTENT_LENGTH.as_str(),
            OVERSIZED_BODY.len().to_string(),
        )
        .body(Bytes::from_static(OVERSIZED_BODY));
    let resp = retry_h3_request(&client, &url, options).await;

    assert_body_limit_response(resp.status, &resp.body_text());
    assert_backend_not_hit(&backend_hits).await;

    gateway.shutdown();
    backend_task.abort();
}

fn body_limit_gateway_builder(backend_port: u16) -> TestGatewayBuilder {
    TestGateway::builder()
        .mode_file(body_limit_config(backend_port))
        .log_level("warn")
        .env("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES", LIMIT_BYTES)
}

fn body_limit_config(backend_port: u16) -> String {
    let config = serde_json::json!({
        "version": "1",
        "proxies": [{
            "id": "body-limits",
            "listen_path": "/body",
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
    serde_yaml::to_string(&config).expect("serialize body-limit config")
}

async fn spawn_counting_backend() -> (u16, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind counting backend");
    let port = listener.local_addr().expect("backend addr").port();
    let hits = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn(run_counting_backend(listener, Arc::clone(&hits)));
    (port, hits, task)
}

async fn run_counting_backend(listener: TcpListener, hits: Arc<AtomicUsize>) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let hits = Arc::clone(&hits);
        tokio::spawn(async move {
            let mut buf = vec![0; 8192];
            let n = match stream.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => return,
            };
            let request = String::from_utf8_lossy(&buf[..n]);
            if request.starts_with("POST /body ") {
                hits.fetch_add(1, Ordering::SeqCst);
            }
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
            let _ = stream.write_all(response).await;
            let _ = stream.shutdown().await;
        });
    }
}

async fn reserve_https_port() -> u16 {
    let (tcp, udp) = reserve_colocated_tcp_udp()
        .await
        .expect("reserve colocated https port");
    let port = tcp.port;
    assert_eq!(port, udp.port);
    drop(tcp);
    drop(udp);
    port
}

async fn retry_h3_request(
    client: &Http3Client,
    url: &str,
    options: GetOptions,
) -> crate::scaffolding::clients::Http3Response {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last_err = None;
    loop {
        match client.get_with_options(url, options.clone()).await {
            Ok(resp) => return resp,
            Err(err) if Instant::now() < deadline => {
                last_err = Some(err.to_string());
                sleep(Duration::from_millis(100)).await;
            }
            Err(err) => {
                panic!(
                    "H3 oversized request did not complete; last startup error={last_err:?}; final error={err}"
                );
            }
        }
    }
}

fn assert_body_limit_response(status: StatusCode, body: &str) {
    assert_eq!(
        status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "unexpected status/body: {status} {body}"
    );
    assert!(
        body.contains("Request body exceeds maximum size"),
        "unexpected body: {body}"
    );
}

async fn assert_backend_not_hit(hits: &AtomicUsize) {
    sleep(Duration::from_millis(100)).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "oversized request reached the backend despite Content-Length fast-path rejection"
    );
}

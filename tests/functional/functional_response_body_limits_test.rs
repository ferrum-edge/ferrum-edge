//! Functional coverage for the global backend response body size limit.
//!
//! `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES` should reject backend responses whose
//! `Content-Length` exceeds the configured ceiling before oversized bytes are
//! delivered to the frontend client.

use crate::common::{TestGateway, TestGatewayBuilder};
use crate::scaffolding::clients::{Http3Client, Http3Response};
use crate::scaffolding::reserve_colocated_tcp_udp;

use http::{Method, StatusCode};
use http_body_util::{BodyExt, Empty};
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
const OVERSIZED_RESPONSE: &[u8] = b"abcde";

#[ignore]
#[tokio::test]
async fn functional_response_body_limits_http1_content_length_rejected() {
    let (backend_port, backend_hits, backend_task) = spawn_oversized_backend().await;
    let mut gateway = response_limit_gateway_builder(backend_port)
        .spawn()
        .await
        .expect("start response-limit gateway");
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
        .get(gateway.proxy_url("/body"))
        .send()
        .await
        .expect("http1 oversized backend response");
    let status = resp.status();
    let body = resp.text().await.expect("body text");

    assert_response_limit_rejection(status, &body);
    assert_backend_hit_once(&backend_hits).await;

    gateway.shutdown();
    backend_task.abort();
}

#[ignore]
#[tokio::test]
async fn functional_response_body_limits_h2_content_length_rejected() {
    let (backend_port, backend_hits, backend_task) = spawn_oversized_backend().await;
    let mut gateway = response_limit_gateway_builder(backend_port)
        .spawn()
        .await
        .expect("start response-limit gateway");
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
        .uri(format!("http://127.0.0.1:{}/body", gateway.proxy_port))
        .body(Empty::<bytes::Bytes>::new())
        .expect("build h2 request");
    let resp = sender.send_request(req).await.expect("send h2 request");
    let status = resp.status();
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("collect h2 body")
        .to_bytes();
    let body = String::from_utf8_lossy(&body);

    assert_response_limit_rejection(status, &body);
    assert_backend_hit_once(&backend_hits).await;

    drop(sender);
    conn_task.abort();
    gateway.shutdown();
    backend_task.abort();
}

#[ignore]
#[tokio::test]
async fn functional_response_body_limits_h3_content_length_rejected() {
    let (backend_port, backend_hits, backend_task) = spawn_oversized_backend().await;
    let https_port = reserve_https_port().await;
    let mut gateway = response_limit_gateway_builder(backend_port)
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .spawn()
        .await
        .expect("start h3 response-limit gateway");

    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://localhost:{https_port}/body");
    let resp = retry_h3_get(&client, &url).await;

    assert_response_limit_rejection(resp.status, &resp.body_text());
    assert_backend_hit_once(&backend_hits).await;

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
            "id": "response-limits",
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
    serde_yaml::to_string(&config).expect("serialize response-limit config")
}

async fn spawn_oversized_backend() -> (u16, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind oversized backend");
    let port = listener.local_addr().expect("backend addr").port();
    let hits = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn(run_oversized_backend(listener, Arc::clone(&hits)));
    (port, hits, task)
}

async fn run_oversized_backend(listener: TcpListener, hits: Arc<AtomicUsize>) {
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
            if request.starts_with("GET /body ") {
                hits.fetch_add(1, Ordering::SeqCst);
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{}",
                OVERSIZED_RESPONSE.len(),
                String::from_utf8_lossy(OVERSIZED_RESPONSE)
            );
            let _ = stream.write_all(response.as_bytes()).await;
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

async fn retry_h3_get(client: &Http3Client, url: &str) -> Http3Response {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last_err = None;
    loop {
        match client.get(url).await {
            Ok(resp) => return resp,
            Err(err) if Instant::now() < deadline => {
                last_err = Some(err.to_string());
                sleep(Duration::from_millis(100)).await;
            }
            Err(err) => {
                panic!(
                    "H3 response-limit request did not complete; last startup error={last_err:?}; final error={err}"
                );
            }
        }
    }
}

fn assert_response_limit_rejection(status: StatusCode, body: &str) {
    assert_eq!(
        status,
        StatusCode::BAD_GATEWAY,
        "unexpected status/body: {status} {body}"
    );
    assert!(
        body.contains("Backend response body exceeds maximum size"),
        "unexpected body: {body}"
    );
    assert!(
        !body.contains("abcde"),
        "oversized backend body was exposed to the frontend: {body}"
    );
}

async fn assert_backend_hit_once(hits: &AtomicUsize) {
    sleep(Duration::from_millis(100)).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "response limit should inspect exactly one backend response"
    );
}

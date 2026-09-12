//! Protocol coverage for body_validator post-header response release (#2323).
//!
//! A response-only validator must not keep large non-matching media types on
//! the buffered path solely because matching JSON/XML requires validation.
//! Matching JSON stays buffered and validated. Coverage spans HTTP/1.1, H2, and H3.

use crate::scaffolding::port_registry::TestSocket;

use crate::common::{TestGateway, TestGatewayBuilder};
use crate::scaffolding::clients::{GetOptions, Http3Client};

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

const GLOBAL_LIMIT_BYTES: &str = "2000000";
const LARGE_BODY_LEN: usize = 1_500_000;

#[ignore]
#[tokio::test]
async fn body_validator_streams_large_png_http1_and_buffers_matching_json() {
    let (backend_port, backend_hits, backend_task) = spawn_typed_backend().await;
    let mut gateway = body_validator_gateway_builder(backend_port)
        .spawn()
        .await
        .expect("start body_validator streaming gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");

    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("http1 client");

    let png = client
        .get(gateway.proxy_url("/download.png"))
        .send()
        .await
        .expect("png response");
    assert_eq!(
        png.status(),
        StatusCode::OK,
        "irrelevant large PNG must stream"
    );
    assert_eq!(png.bytes().await.expect("png body").len(), LARGE_BODY_LEN);

    let json = client
        .get(gateway.proxy_url("/item.json"))
        .send()
        .await
        .expect("json response");
    assert_eq!(
        json.status(),
        StatusCode::OK,
        "matching JSON must stay buffered and validate"
    );
    assert_eq!(json.text().await.expect("json body"), r#"{"id":"ok"}"#);

    let missing = client
        .get(gateway.proxy_url("/missing.json"))
        .send()
        .await
        .expect("invalid json response");
    assert_eq!(
        missing.status(),
        StatusCode::BAD_GATEWAY,
        "matching JSON missing required fields must 502"
    );

    assert!(
        backend_hits.load(Ordering::SeqCst) >= 3,
        "backend should have served png+json+missing"
    );

    gateway.shutdown();
    backend_task.abort();
}

#[ignore]
#[tokio::test]
async fn body_validator_streams_large_png_http2() {
    let (backend_port, _backend_hits, backend_task) = spawn_typed_backend().await;
    let mut gateway = body_validator_gateway_builder(backend_port)
        .spawn()
        .await
        .expect("start body_validator streaming gateway");
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
        .uri(format!(
            "http://127.0.0.1:{}/download.png",
            gateway.proxy_port
        ))
        .body(Empty::<Bytes>::new())
        .expect("build h2 request");
    let resp = sender.send_request(req).await.expect("h2 send");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("h2 body")
        .to_bytes();
    assert_eq!(body.len(), LARGE_BODY_LEN, "H2 must stream large PNG");

    drop(sender);
    conn_task.abort();
    gateway.shutdown();
    backend_task.abort();
}

#[tokio::test]
async fn body_validator_streams_large_png_http3() {
    let (backend_port, _backend_hits, backend_task) = spawn_typed_backend().await;

    let mut gateway = body_validator_gateway_builder(backend_port)
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env_ephemeral_port("FERRUM_PROXY_HTTPS_PORT")
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .env("FERRUM_TLS_NO_VERIFY", "true")
        .spawn()
        .await
        .expect("start H3 body_validator gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");
    let https_port = gateway
        .env_port("FERRUM_PROXY_HTTPS_PORT")
        .expect("harness-allocated HTTPS port");

    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/download.png");
    let resp = client
        .get_with_options(&url, GetOptions::default())
        .await
        .expect("h3 get");
    assert_eq!(resp.status.as_u16(), 200, "H3 must stream large PNG");
    assert_eq!(resp.body_bytes.len(), LARGE_BODY_LEN);

    gateway.shutdown();
    backend_task.abort();
}

fn body_validator_gateway_builder(backend_port: u16) -> TestGatewayBuilder {
    TestGateway::builder()
        .mode_file(body_validator_config(backend_port))
        .log_level("warn")
        .env("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES", GLOBAL_LIMIT_BYTES)
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
}

fn body_validator_config(backend_port: u16) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "body-validator-stream",
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
            "pool_enable_http2": false,
            "response_body_mode": "stream",
            "plugins": [{"plugin_config_id": "bv-response"}]
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "bv-response",
            "proxy_id": "body-validator-stream",
            "plugin_name": "body_validator",
            "scope": "proxy",
            "enabled": true,
            "config": {"response_required_fields": ["id"]}
        }]
    });
    serde_yaml::to_string(&config).expect("serialize body_validator stream config")
}

async fn spawn_typed_backend() -> (u16, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind typed backend");
    let port = listener.local_addr().expect("local addr").port();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&hits);
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            hits_clone.fetch_add(1, Ordering::SeqCst);
            let mut buf = vec![0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let req = String::from_utf8_lossy(&buf);
            let (status_line, content_type, body): (&str, &str, Vec<u8>) =
                if req.contains("GET /download.png") {
                    ("200 OK", "image/png", vec![0x89u8; LARGE_BODY_LEN])
                } else if req.contains("GET /missing.json") {
                    (
                        "200 OK",
                        "application/json",
                        br#"{"name":"no-id"}"#.to_vec(),
                    )
                } else if req.contains("GET /item.json") {
                    ("200 OK", "application/json", br#"{"id":"ok"}"#.to_vec())
                } else {
                    ("404 Not Found", "text/plain", b"missing".to_vec())
                };
            let response = format!(
                "HTTP/1.1 {status_line}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.write_all(&body).await;
        }
    });
    (port, hits, task)
}

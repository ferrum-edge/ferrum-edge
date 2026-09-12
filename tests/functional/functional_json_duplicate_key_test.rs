//! End-to-end protocol parity for the governed-JSON duplicate-member screen
//! (advisory `GHSA-c78j-5w9p-cpq6`).
//!
//! `serde_json` collapses duplicate object members to the LAST value; many
//! backend parsers keep the FIRST. A validator that evaluates the collapsed
//! view but forwards the ORIGINAL bytes therefore authorizes one document and
//! dispatches another.
//!
//! These tests drive a real gateway with a `body_validator` whose schema admits
//! only `role: "safe"`, then POST a body carrying an earlier `role: "admin"`
//! and a later `role: "safe"`. The load-bearing assertion is not just the
//! status code: the backend records every request body it received, and the
//! ambiguous bytes must never appear there — so nothing downstream can apply a
//! first-key-wins interpretation to them. Coverage spans HTTP/1.1, HTTP/2, and
//! HTTP/3 because the screen lives in a protocol-independent plugin hook and
//! must behave identically on all three.

use crate::scaffolding::port_registry::TestSocket;

use crate::common::{TestGateway, TestGatewayBuilder};
use crate::scaffolding::clients::{GetOptions, Http3Client};

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// Earlier forbidden value, later permitted one. `serde_json` sees only
/// `role=safe`; a first-key-wins backend would execute `role=admin`.
const AMBIGUOUS_BODY: &str = r#"{"role":"admin","role":"safe"}"#;
/// The same schema-satisfying document with no duplicated member.
const CLEAN_BODY: &str = r#"{"role":"safe"}"#;
/// Substring that must never reach the backend.
const FORBIDDEN_MARKER: &str = "admin";

#[ignore]
#[tokio::test]
async fn duplicate_member_body_is_rejected_over_http1_and_never_reaches_the_backend() {
    let backend = Backend::spawn().await;
    let mut gateway = duplicate_key_gateway_builder(backend.port)
        .spawn()
        .await
        .expect("start duplicate-key gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");

    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("http1 client");

    let clean = client
        .post(gateway.proxy_url("/orders"))
        .header("content-type", "application/json")
        .body(CLEAN_BODY)
        .send()
        .await
        .expect("clean response");
    assert_eq!(
        clean.status(),
        StatusCode::OK,
        "an unambiguous schema-valid body must still be proxied over HTTP/1.1"
    );

    let ambiguous = client
        .post(gateway.proxy_url("/orders"))
        .header("content-type", "application/json")
        .body(AMBIGUOUS_BODY)
        .send()
        .await
        .expect("ambiguous response");
    assert_eq!(
        ambiguous.status(),
        StatusCode::BAD_REQUEST,
        "a duplicate-member body must be rejected over HTTP/1.1"
    );

    backend.assert_saw_clean_body_only("HTTP/1.1");

    gateway.shutdown();
    backend.shutdown();
}

#[ignore]
#[tokio::test]
async fn duplicate_member_body_is_rejected_over_http2_and_never_reaches_the_backend() {
    let backend = Backend::spawn().await;
    let mut gateway = duplicate_key_gateway_builder(backend.port)
        .spawn()
        .await
        .expect("start duplicate-key gateway");
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

    let url = format!("http://127.0.0.1:{}/orders", gateway.proxy_port);
    let clean = sender
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri(&url)
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from_static(CLEAN_BODY.as_bytes())))
                .expect("build clean h2 request"),
        )
        .await
        .expect("h2 clean send");
    assert_eq!(
        clean.status(),
        StatusCode::OK,
        "an unambiguous schema-valid body must still be proxied over HTTP/2"
    );
    let _ = clean.into_body().collect().await;

    let ambiguous = sender
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri(&url)
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from_static(AMBIGUOUS_BODY.as_bytes())))
                .expect("build ambiguous h2 request"),
        )
        .await
        .expect("h2 ambiguous send");
    assert_eq!(
        ambiguous.status(),
        StatusCode::BAD_REQUEST,
        "a duplicate-member body must be rejected over HTTP/2"
    );
    let _ = ambiguous.into_body().collect().await;

    backend.assert_saw_clean_body_only("HTTP/2");

    drop(sender);
    conn_task.abort();
    gateway.shutdown();
    backend.shutdown();
}

#[ignore]
#[tokio::test]
async fn duplicate_member_body_is_rejected_over_http3_and_never_reaches_the_backend() {
    let backend = Backend::spawn().await;

    let mut gateway = duplicate_key_gateway_builder(backend.port)
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env_ephemeral_port("FERRUM_PROXY_HTTPS_PORT")
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .env("FERRUM_TLS_NO_VERIFY", "true")
        .spawn()
        .await
        .expect("start H3 duplicate-key gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");
    let https_port = gateway
        .env_port("FERRUM_PROXY_HTTPS_PORT")
        .expect("harness-allocated HTTPS port");

    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/orders");

    let clean = client
        .get_with_options(&url, json_post_options(CLEAN_BODY))
        .await
        .expect("h3 clean post");
    assert_eq!(
        clean.status.as_u16(),
        200,
        "an unambiguous schema-valid body must still be proxied over HTTP/3"
    );

    let ambiguous = client
        .get_with_options(&url, json_post_options(AMBIGUOUS_BODY))
        .await
        .expect("h3 ambiguous post");
    assert_eq!(
        ambiguous.status.as_u16(),
        400,
        "a duplicate-member body must be rejected over HTTP/3"
    );

    backend.assert_saw_clean_body_only("HTTP/3");

    gateway.shutdown();
    backend.shutdown();
}

fn json_post_options(body: &'static str) -> GetOptions {
    GetOptions::default()
        .method(Method::POST)
        .header("content-type", "application/json")
        .body(Bytes::from_static(body.as_bytes()))
}

fn duplicate_key_gateway_builder(backend_port: u16) -> TestGatewayBuilder {
    TestGateway::builder()
        .mode_file(duplicate_key_config(backend_port))
        .log_level("warn")
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
}

fn duplicate_key_config(backend_port: u16) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "duplicate-key-guard",
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
            "pool_enable_http2": false,
            "plugins": [{"plugin_config_id": "bv-request"}]
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "bv-request",
            "proxy_id": "duplicate-key-guard",
            "plugin_name": "body_validator",
            "scope": "proxy",
            "enabled": true,
            "config": {
                "json_schema": {
                    "type": "object",
                    "required": ["role"],
                    "properties": {"role": {"type": "string", "enum": ["safe"]}}
                }
            }
        }]
    });
    serde_yaml::to_string(&config).expect("serialize duplicate-key config")
}

/// Minimal HTTP/1.1 backend that records every request body it is handed.
struct Backend {
    port: u16,
    bodies: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}

impl Backend {
    async fn spawn() -> Self {
        let listener = TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind recording backend");
        let port = listener.local_addr().expect("local addr").port();
        let bodies: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&bodies);
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let recorded = Arc::clone(&recorded);
                tokio::spawn(async move {
                    if let Some(body) = read_request_body(&mut stream).await
                        && let Ok(mut guard) = recorded.lock()
                    {
                        guard.push(body);
                    }
                    let payload = br#"{"ok":true}"#;
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        payload.len()
                    );
                    let _ = stream.write_all(head.as_bytes()).await;
                    let _ = stream.write_all(payload).await;
                    let _ = stream.flush().await;
                });
            }
        });
        Self { port, bodies, task }
    }

    /// The clean body must have been proxied, and no request the backend saw
    /// may contain the earlier, forbidden member value. This is the assertion
    /// that proves the differential cannot be resolved downstream: the
    /// ambiguous bytes are never dispatched at all.
    fn assert_saw_clean_body_only(&self, protocol: &str) {
        let bodies = self.bodies.lock().expect("backend record lock").clone();
        assert!(
            bodies.iter().any(|body| body.contains(CLEAN_BODY)),
            "{protocol}: the unambiguous body should have reached the backend, saw {bodies:?}"
        );
        for body in &bodies {
            assert!(
                !body.contains(FORBIDDEN_MARKER),
                "{protocol}: ambiguous bytes reached the backend and could be read \
                 first-key-wins: {body:?}"
            );
        }
    }

    fn shutdown(&self) {
        self.task.abort();
    }
}

/// Read one HTTP/1.1 request and return its body, honoring `Content-Length` so
/// a body split across reads is not truncated.
async fn read_request_body(stream: &mut TcpStream) -> Option<String> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let head_end = find_header_end(&buffer);
        if let Some(head_end) = head_end {
            let head = String::from_utf8_lossy(&buffer[..head_end]).to_ascii_lowercase();
            let content_length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if buffer.len() >= head_end + content_length {
                let body = &buffer[head_end..head_end + content_length];
                return Some(String::from_utf8_lossy(body).to_string());
            }
        }
        let read = tokio::time::timeout_at(deadline, stream.read(&mut chunk))
            .await
            .ok()?
            .ok()?;
        if read == 0 {
            return head_end.map(|head_end| {
                String::from_utf8_lossy(&buffer[head_end.min(buffer.len())..]).to_string()
            });
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

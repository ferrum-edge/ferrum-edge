//! Transport proof for `body_validator` request-representation fail-closed
//! behavior (private advisory `GHSA-2vmr-ww8r-mww3`).
//!
//! The unit suite covers the decision table. What only a real gateway can prove
//! is that the *representation* reaching the hook is the same on every
//! transport: H1/H2 may skip collection entirely for a request the transport
//! proved empty, while H3 always collects into an empty buffer. Either way a
//! configured JSON rule must reject, and the backend must never be dialed.

use crate::common::{TestGateway, TestGatewayBuilder};
use crate::scaffolding::clients::{GetOptions, Http3Client};
use crate::scaffolding::reserve_colocated_tcp_udp;

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::{BodyExt, Full};
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

/// A body the JSON rule rejects: valid JSON, missing the required member.
const MISSING_FIELD_BODY: &str = r#"{"other":true}"#;
/// A body the JSON rule accepts.
const VALID_BODY: &str = r#"{"name":"ok"}"#;
/// Valid JSON framing whose string value is not valid UTF-8.
const NON_UTF8_BODY: &[u8] = b"{\"name\":\"\xFF\xFE\"}";

#[ignore]
#[tokio::test]
async fn body_validator_request_representation_fails_closed_http1() {
    let (backend_port, backend_hits, backend_task) = spawn_counting_backend().await;
    let mut gateway = request_validator_gateway_builder(backend_port)
        .spawn()
        .await
        .expect("start body_validator request gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");

    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("http1 client");

    // A body-bearing DELETE is no longer exempt by method.
    let delete = client
        .delete(gateway.proxy_url("/api"))
        .header("content-type", "application/json")
        .body(MISSING_FIELD_BODY)
        .send()
        .await
        .expect("delete response");
    assert_eq!(
        delete.status(),
        StatusCode::BAD_REQUEST,
        "body-bearing DELETE must be validated"
    );

    // An empty body is decided by the configured representation, not skipped.
    let empty_post = client
        .post(gateway.proxy_url("/api"))
        .header("content-type", "application/json")
        .body("")
        .send()
        .await
        .expect("empty post response");
    assert_eq!(empty_post.status(), StatusCode::BAD_REQUEST);

    // A GET whose transport proves it carries no body still declares a governed
    // representation, so the empty document is validated (and rejected).
    let empty_get = client
        .get(gateway.proxy_url("/api"))
        .header("content-type", "application/json")
        .send()
        .await
        .expect("empty get response");
    assert_eq!(empty_get.status(), StatusCode::BAD_REQUEST);

    // A body the rule cannot decode fails closed, and the client-visible error
    // never reproduces any of the offending bytes.
    let non_utf8 = client
        .post(gateway.proxy_url("/api"))
        .header("content-type", "application/json")
        .body(NON_UTF8_BODY.to_vec())
        .send()
        .await
        .expect("non-utf8 response");
    assert_eq!(non_utf8.status(), StatusCode::BAD_REQUEST);
    let non_utf8_body = non_utf8.text().await.expect("non-utf8 error body");
    assert!(
        non_utf8_body.contains("not valid UTF-8"),
        "expected fixed diagnostic, got: {non_utf8_body}"
    );
    assert!(
        !non_utf8_body.contains('\u{FFFD}') && !non_utf8_body.contains("\\u00ff"),
        "error must not echo body bytes: {non_utf8_body}"
    );

    assert_eq!(
        backend_hits.load(Ordering::SeqCst),
        0,
        "no fail-closed request may reach the backend"
    );

    // A valid governed body on an unusual method still proxies normally.
    let allowed = client
        .delete(gateway.proxy_url("/api"))
        .header("content-type", "application/json")
        .body(VALID_BODY)
        .send()
        .await
        .expect("valid delete response");
    assert_eq!(allowed.status(), StatusCode::OK);
    assert_eq!(backend_hits.load(Ordering::SeqCst), 1);

    gateway.shutdown();
    backend_task.abort();
}

#[ignore]
#[tokio::test]
async fn body_validator_request_representation_fails_closed_http2() {
    let (backend_port, backend_hits, backend_task) = spawn_counting_backend().await;
    let mut gateway = request_validator_gateway_builder(backend_port)
        .spawn()
        .await
        .expect("start body_validator request gateway");
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
    let url = format!("http://127.0.0.1:{}/api", gateway.proxy_port);

    // H2 GET may keep the stream open without Content-Length; the gateway's own
    // end-of-stream proof is what decides the representation here.
    let empty_get = Request::builder()
        .method(Method::GET)
        .uri(url.clone())
        .header("content-type", "application/json")
        .body(full(b""))
        .expect("build h2 get");
    let resp = sender.send_request(empty_get).await.expect("h2 get send");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let _ = resp.into_body().collect().await;

    let delete = Request::builder()
        .method(Method::DELETE)
        .uri(url.clone())
        .header("content-type", "application/json")
        .body(full(MISSING_FIELD_BODY.as_bytes()))
        .expect("build h2 delete");
    let resp = sender.send_request(delete).await.expect("h2 delete send");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let _ = resp.into_body().collect().await;

    assert_eq!(
        backend_hits.load(Ordering::SeqCst),
        0,
        "no fail-closed H2 request may reach the backend"
    );

    let allowed = Request::builder()
        .method(Method::DELETE)
        .uri(url)
        .header("content-type", "application/json")
        .body(full(VALID_BODY.as_bytes()))
        .expect("build h2 allowed");
    let resp = sender.send_request(allowed).await.expect("h2 allowed send");
    assert_eq!(resp.status(), StatusCode::OK);
    let _ = resp.into_body().collect().await;
    assert_eq!(backend_hits.load(Ordering::SeqCst), 1);

    drop(sender);
    conn_task.abort();
    gateway.shutdown();
    backend_task.abort();
}

#[ignore]
#[tokio::test]
async fn body_validator_request_representation_fails_closed_http3() {
    let (backend_port, backend_hits, backend_task) = spawn_counting_backend().await;
    let (mut gateway, https_port) = spawn_h3_request_validator_gateway(backend_port).await;
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");

    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/api");

    // H3 always drains the request stream into a buffer, so the empty GET
    // reaches the hook as an empty representation rather than a skipped one.
    let empty_get = client
        .get_with_options(
            &url,
            GetOptions::default().header("content-type", "application/json"),
        )
        .await
        .expect("h3 empty get");
    assert_eq!(empty_get.status.as_u16(), 400);

    let empty_post = client
        .get_with_options(
            &url,
            GetOptions::default()
                .method(Method::POST)
                .header("content-type", "application/json"),
        )
        .await
        .expect("h3 empty post");
    assert_eq!(empty_post.status.as_u16(), 400);

    let non_utf8 = client
        .get_with_options(
            &url,
            GetOptions::default()
                .method(Method::DELETE)
                .header("content-type", "application/json")
                .body(Bytes::from_static(NON_UTF8_BODY)),
        )
        .await
        .expect("h3 non-utf8 delete");
    assert_eq!(non_utf8.status.as_u16(), 400);

    assert_eq!(
        backend_hits.load(Ordering::SeqCst),
        0,
        "no fail-closed H3 request may reach the backend"
    );

    let allowed = client
        .get_with_options(
            &url,
            GetOptions::default()
                .method(Method::DELETE)
                .header("content-type", "application/json")
                .body(Bytes::from_static(VALID_BODY.as_bytes())),
        )
        .await
        .expect("h3 valid delete");
    assert_eq!(allowed.status.as_u16(), 200);
    assert_eq!(backend_hits.load(Ordering::SeqCst), 1);

    gateway.shutdown();
    backend_task.abort();
}

/// Fixed-size H2 request body helper. Keeps the request builders short.
fn full(body: &'static [u8]) -> Full<Bytes> {
    Full::new(Bytes::from_static(body))
}

fn request_validator_gateway_builder(backend_port: u16) -> TestGatewayBuilder {
    TestGateway::builder()
        .mode_file(request_validator_config(backend_port))
        .log_level("warn")
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
}

async fn spawn_h3_request_validator_gateway(backend_port: u16) -> (TestGateway, u16) {
    const MAX_ATTEMPTS: usize = 5;
    let mut last_error = String::new();

    // The subprocess must bind the configured HTTPS port itself, so releasing
    // the reservation creates an unavoidable short ownership window. Reserve
    // both TCP and UDP on the same port, give that fixed-port spawn one attempt,
    // and retry with a fresh pair if another parallel test wins the window
    // (issue #3428). Retrying the same stolen port inside the harness cannot
    // recover.
    for _ in 0..MAX_ATTEMPTS {
        let (https_tcp, https_udp) = reserve_colocated_tcp_udp()
            .await
            .expect("reserve colocated H3 port");
        let https_port = https_tcp.port;
        assert_eq!(https_port, https_udp.port);
        drop(https_tcp);
        drop(https_udp);

        let result = request_validator_gateway_builder(backend_port)
            .max_attempts(1)
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
            .env("FERRUM_TLS_NO_VERIFY", "true")
            .spawn()
            .await;
        match result {
            Ok(gateway) => return (gateway, https_port),
            Err(error) => last_error = error.to_string(),
        }
    }

    panic!(
        "failed to spawn H3 body-validator gateway after {MAX_ATTEMPTS} fresh-port attempts: \
         {last_error}"
    );
}

fn request_validator_config(backend_port: u16) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "body-validator-request",
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
            "proxy_id": "body-validator-request",
            "plugin_name": "body_validator",
            "scope": "proxy",
            "enabled": true,
            "config": {"required_fields": ["name"]}
        }]
    });
    serde_yaml::to_string(&config).expect("serialize body_validator request config")
}

/// Minimal HTTP/1.1 backend that counts every request it is actually handed.
async fn spawn_counting_backend() -> (u16, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind counting backend");
    let port = listener.local_addr().expect("local addr").port();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&hits);
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let hits = Arc::clone(&hits_clone);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let Ok(read) = stream.read(&mut buf).await else {
                    return;
                };
                if read == 0 {
                    return;
                }
                // File-mode startup performs a backend-capability probe when
                // pool warmup is disabled. Count only the route exercised by
                // this test so that infrastructure traffic cannot masquerade
                // as a policy bypass.
                let request = String::from_utf8_lossy(&buf[..read]);
                if request
                    .lines()
                    .next()
                    .is_some_and(|line| line.contains(" /api "))
                {
                    hits.fetch_add(1, Ordering::SeqCst);
                }
                let body = br#"{"ok":true}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.write_all(body).await;
            });
        }
    });
    (port, hits, task)
}

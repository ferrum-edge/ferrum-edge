//! GHSA-xvr4-5p3r-h7cw: protocol-managed response headers cannot survive the
//! final H1/H2/H3 client-wire boundary after response plugins run.
//!
//! Covers construction rejection for `response_transformer` / `response_mock`,
//! final-boundary strip of hop-by-hop and Connection-listed fields on ordinary
//! upstream responses, Content-Length repair on buffered bodies, and the
//! already-fixed correlation-id echo behavior on ordinary responses.

use crate::common::TestGateway;
use crate::common::protocol_managed_response_headers::PROTOCOL_MANAGED_RESPONSE_DESTINATIONS;
use crate::scaffolding::clients::{GetOptions, Http3Client, Http3Response};

use http::{Method, StatusCode, header};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

fn build_config(backend_port: u16) -> String {
    format!(
        r#"version: "1"
proxies:
  - id: "proto-managed"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    pool_enable_http2: true
    plugins:
      - plugin_config_id: "corr"
      - plugin_config_id: "xform"
      - plugin_config_id: "mock"

consumers: []
plugin_configs:
  - id: "corr"
    plugin_name: correlation_id
    scope: proxy
    proxy_id: "proto-managed"
    enabled: true
    config:
      header_name: x-request-id
      echo_downstream: true
  - id: "xform"
    plugin_name: response_transformer
    scope: proxy
    proxy_id: "proto-managed"
    enabled: true
    config:
      rules:
        - operation: add
          target: header
          key: x-gateway
          value: "1"
        - operation: remove
          target: header
          key: x-backend-only
  - id: "mock"
    plugin_name: response_mock
    scope: proxy
    proxy_id: "proto-managed"
    enabled: true
    config:
      passthrough_on_no_match: true
      rules:
        - path: /mocked
          status_code: 200
          headers:
            content-type: text/plain
            x-mock: "yes"
          body: "mock-body"
        - path: /empty
          status_code: 403
          headers:
            content-type: application/json
        - path: /nocontent
          status_code: 204
          headers:
            content-type: application/json
"#
    )
}

async fn start_scripted_backend(hits: Arc<AtomicUsize>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            hits.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await;
            let body = b"hello";
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/plain\r\n\
                 Content-Length: {}\r\n\
                 Connection: close, x-smuggled\r\n\
                 x-smuggled: leak\r\n\
                 Keep-Alive: timeout=5\r\n\
                 Proxy-Authenticate: Basic\r\n\
                 Upgrade: h2c\r\n\
                 x-backend-only: gone\r\n\
                 \r\n",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.write_all(body).await;
        }
    });
    port
}

async fn h3_request_until_ready(client: &Http3Client, url: &str, method: Method) -> Http3Response {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match client
            .get_with_options(url, GetOptions::default().method(method.clone()))
            .await
        {
            Ok(response) => return response,
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!("H3 {method} {url} did not complete: {error}"),
        }
    }
}

async fn spawn_gateway(backend_port: u16) -> (TestGateway, u16) {
    const MAX_ATTEMPTS: usize = 5;
    let mut last_error = String::new();

    for _ in 0..MAX_ATTEMPTS {
        let reservation = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let https_port = match reservation.local_addr() {
            Ok(address) => address.port(),
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        drop(reservation);

        let result = TestGateway::builder()
            .mode_file(build_config(backend_port))
            .log_level("warn")
            .max_attempts(1)
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .spawn()
            .await;
        match result {
            Ok(gateway) => return (gateway, https_port),
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_millis(200)).await;
            }
        }
    }

    panic!("failed to spawn gateway: {last_error}");
}

fn assert_no_protocol_managed(headers: &http::HeaderMap, label: &str) {
    for name in PROTOCOL_MANAGED_RESPONSE_DESTINATIONS {
        if *name == "content-length" {
            continue;
        }
        assert!(
            headers.get(*name).is_none(),
            "{label}: protocol-managed `{name}` must not reach the client"
        );
    }
    assert!(
        headers.get("x-smuggled").is_none(),
        "{label}: Connection-listed extension must be stripped"
    );
}

#[tokio::test]
#[ignore]
async fn functional_protocol_managed_response_headers_h1_h2_h3() {
    let hits = Arc::new(AtomicUsize::new(0));
    let backend_port = start_scripted_backend(Arc::clone(&hits)).await;
    let (gateway, https_port) = spawn_gateway(backend_port).await;
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");
    let echo_url = gateway.proxy_url("/api/echo");
    let mocked_url = gateway.proxy_url("/api/mocked");

    // --- Ordinary upstream via transformer (H1) ---
    let h1 = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("h1 client");
    let h1_resp = h1.get(&echo_url).send().await.expect("H1 ordinary");
    assert_eq!(h1_resp.status(), StatusCode::OK);
    assert_eq!(
        h1_resp
            .headers()
            .get("x-gateway")
            .and_then(|v| v.to_str().ok()),
        Some("1")
    );
    assert!(h1_resp.headers().get("x-backend-only").is_none());
    assert_no_protocol_managed(h1_resp.headers(), "H1 ordinary");
    assert!(
        matches!(
            h1_resp
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()),
            None | Some("5")
        ),
        "H1 ordinary: exact framing may retain or derive only the real body length"
    );
    let corr = h1_resp
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .expect("correlation echo on ordinary H1")
        .to_string();
    assert!(!corr.is_empty());
    assert_eq!(h1_resp.bytes().await.expect("body").as_ref(), b"hello");

    // --- Synthetic mock (H1) ---
    let mock = h1.get(&mocked_url).send().await.expect("H1 mock");
    assert_eq!(mock.status(), StatusCode::OK);
    assert_eq!(
        mock.headers().get("x-mock").and_then(|v| v.to_str().ok()),
        Some("yes")
    );
    assert_no_protocol_managed(mock.headers(), "H1 mock");
    assert_eq!(
        mock.headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()),
        Some("9")
    );
    assert!(
        mock.headers().get("x-request-id").is_some(),
        "correlation echo on mock reject path"
    );
    assert_eq!(
        mock.bytes().await.expect("mock body").as_ref(),
        b"mock-body"
    );

    // --- H2 (h2c prior knowledge on the plaintext proxy port) ---
    let h2 = reqwest::Client::builder()
        .http2_prior_knowledge()
        .no_proxy()
        .build()
        .expect("h2 client");
    let h2_resp = h2.get(&echo_url).send().await.expect("H2 ordinary");
    assert_eq!(h2_resp.version(), reqwest::Version::HTTP_2);
    assert_eq!(h2_resp.status(), StatusCode::OK);
    assert_no_protocol_managed(h2_resp.headers(), "H2 ordinary");
    assert!(
        matches!(
            h2_resp
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()),
            None | Some("5")
        ),
        "H2 ordinary: streaming may omit length; exact framing may publish only the real length"
    );
    assert!(h2_resp.headers().get("x-request-id").is_some());

    let h2_mock = h2.get(&mocked_url).send().await.expect("H2 mock");
    assert_eq!(h2_mock.status(), StatusCode::OK);
    assert_no_protocol_managed(h2_mock.headers(), "H2 mock");
    assert_eq!(
        h2_mock
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()),
        Some("9")
    );

    // --- H3 ---
    let h3 = Http3Client::insecure().expect("h3 client");
    let h3_echo = format!("https://localhost:{https_port}/api/echo");
    let h3_mocked = format!("https://localhost:{https_port}/api/mocked");
    let h3_resp = h3_request_until_ready(&h3, &h3_echo, Method::GET).await;
    assert_eq!(h3_resp.status, StatusCode::OK);
    assert_no_protocol_managed(&h3_resp.headers, "H3 ordinary");
    assert!(
        matches!(
            h3_resp
                .headers
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()),
            None | Some("5")
        ),
        "H3 ordinary: streaming may omit length; exact framing may publish only the real length"
    );
    assert!(h3_resp.headers.get("x-request-id").is_some());

    let h3_mock = h3_request_until_ready(&h3, &h3_mocked, Method::GET).await;
    assert_eq!(h3_mock.status, StatusCode::OK);
    assert_no_protocol_managed(&h3_mock.headers, "H3 mock");
    assert_eq!(
        h3_mock
            .headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()),
        Some("9")
    );

    assert!(
        hits.load(Ordering::SeqCst) >= 2,
        "ordinary paths should have reached the scripted backend"
    );
}

/// An *empty* synthetic reject is still an ordinary HTTP response: its
/// authoritative length is exactly zero, so the final boundary must publish
/// `Content-Length: 0` on H1/H2/H3 rather than fall back to streaming framing
/// (where a stale or hostile length could survive). `HEAD` keeps the
/// representation length a `GET` would have returned but emits no body bytes,
/// and no-body statuses advertise no length at all.
#[tokio::test]
#[ignore]
async fn functional_empty_and_head_reject_framing_h1_h2_h3() {
    let hits = Arc::new(AtomicUsize::new(0));
    let backend_port = start_scripted_backend(Arc::clone(&hits)).await;
    let (gateway, https_port) = spawn_gateway(backend_port).await;
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");

    let empty_url = gateway.proxy_url("/api/empty");
    let mocked_url = gateway.proxy_url("/api/mocked");
    let nocontent_url = gateway.proxy_url("/api/nocontent");

    let h1 = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("h1 client");
    let h2 = reqwest::Client::builder()
        .http2_prior_knowledge()
        .no_proxy()
        .build()
        .expect("h2 client");

    for (label, client) in [("H1", &h1), ("H2", &h2)] {
        // Empty reject: canonical zero, never a preserved streaming length.
        let empty = client.get(&empty_url).send().await.expect("empty reject");
        assert_eq!(
            empty.status(),
            StatusCode::FORBIDDEN,
            "{label} empty status"
        );
        assert_no_protocol_managed(empty.headers(), &format!("{label} empty reject"));
        assert_eq!(
            empty
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()),
            Some("0"),
            "{label}: empty reject must publish canonical Content-Length: 0"
        );
        assert!(empty.bytes().await.expect("empty body").is_empty());

        // HEAD keeps the representation length and omits body bytes.
        let head = client.head(&mocked_url).send().await.expect("HEAD mock");
        assert_eq!(head.status(), StatusCode::OK, "{label} HEAD status");
        assert_eq!(
            head.headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()),
            Some("9"),
            "{label}: HEAD must keep the representation length"
        );
        assert!(head.bytes().await.expect("HEAD body").is_empty());

        // 204 forbids a body: no length at all.
        let no_content = client.get(&nocontent_url).send().await.expect("204 reject");
        assert_eq!(no_content.status(), StatusCode::NO_CONTENT);
        assert!(
            no_content.headers().get(header::CONTENT_LENGTH).is_none(),
            "{label}: 204 must not advertise a body length"
        );
    }

    let h3 = Http3Client::insecure().expect("h3 client");
    let h3_empty = h3_request_until_ready(
        &h3,
        &format!("https://localhost:{https_port}/api/empty"),
        Method::GET,
    )
    .await;
    assert_eq!(h3_empty.status, StatusCode::FORBIDDEN);
    assert_no_protocol_managed(&h3_empty.headers, "H3 empty reject");
    assert_eq!(
        h3_empty
            .headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()),
        Some("0"),
        "H3: empty reject must publish canonical Content-Length: 0"
    );
    assert!(h3_empty.body_bytes.is_empty());

    let h3_head = h3_request_until_ready(
        &h3,
        &format!("https://localhost:{https_port}/api/mocked"),
        Method::HEAD,
    )
    .await;
    assert_eq!(h3_head.status, StatusCode::OK);
    assert_eq!(
        h3_head
            .headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()),
        Some("9"),
        "H3: HEAD must keep the representation length"
    );
    assert!(h3_head.body_bytes.is_empty());

    let h3_no_content = h3_request_until_ready(
        &h3,
        &format!("https://localhost:{https_port}/api/nocontent"),
        Method::GET,
    )
    .await;
    assert_eq!(h3_no_content.status, StatusCode::NO_CONTENT);
    assert!(
        h3_no_content.headers.get(header::CONTENT_LENGTH).is_none(),
        "H3: 204 must not advertise a body length"
    );
}

/// Body length the backend declares on the streaming path. It must exceed
/// `FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES` (default 65,536) so the gateway takes
/// the STREAMING response arm rather than eagerly collecting the body into a
/// buffered one — the buffered arm publishes its own derived length and is not
/// what this test covers.
const STREAMED_BODY_LEN: usize = 70_000;

/// Backend that declares a perfectly valid `Content-Length` on a body large
/// enough to be streamed rather than buffered by the gateway.
async fn start_streaming_backend(hits: Arc<AtomicUsize>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind streaming backend");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            hits.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await;
            let body = vec![b'z'; STREAMED_BODY_LEN];
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/octet-stream\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\
                 \r\n",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.write_all(&body).await;
        }
    });
    port
}

/// GHSA-xvr4-5p3r-h7cw residual: on an ordinary (non-`HEAD`) STREAMED response
/// the gateway must publish no `Content-Length` at all, even when the value is
/// a perfectly valid decimal.
///
/// The earlier repair covered the buffered writers (exact derived length) and
/// hop-by-hop stripping, but the streaming arm preserved one syntactically valid
/// value. Nothing on that arm can verify the claim against bytes not yet
/// written, and `security_headers.set` / `opa.deny_headers` could author one in
/// the response band — so a streamed response could ship a valid-but-false
/// length. Removing it is lossless: H1 falls back to chunked transfer-coding and
/// H2/H3 frame the body with END_STREAM / FIN, which is why every frontend below
/// still receives the complete body.
///
/// Stripping the header alone is not sufficient on H1/H2: hyper reconstructs
/// `Content-Length` from an exact `Body::size_hint()` whenever the header is
/// absent, so the streaming body must not advertise the declared length either.
/// A regression in *either* half fails this test.
#[tokio::test]
#[ignore]
async fn functional_streamed_response_publishes_no_content_length_h1_h2_h3() {
    let hits = Arc::new(AtomicUsize::new(0));
    let backend_port = start_streaming_backend(Arc::clone(&hits)).await;
    let (gateway, https_port) = spawn_gateway(backend_port).await;
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");
    let url = gateway.proxy_url("/api/streamed");

    // --- H1 ---
    let h1 = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("h1 client");
    let h1_resp = h1.get(&url).send().await.expect("H1 streamed");
    assert_eq!(h1_resp.status(), StatusCode::OK);
    // `assert_no_protocol_managed` is deliberately NOT used on the H1 arm: with
    // no `Content-Length`, hyper's own H1 writer frames the body with
    // `Transfer-Encoding: chunked` and manages `Connection`. Those are
    // gateway/transport-owned fields written after the plugin boundary, not
    // backend- or plugin-authored leaks, so their presence here is correct.
    assert!(
        h1_resp.headers().get(header::CONTENT_LENGTH).is_none(),
        "H1 streamed: a valid backend Content-Length must not survive the final \
         boundary — the gateway cannot verify it against bytes not yet written"
    );
    assert_eq!(
        h1_resp.bytes().await.expect("H1 body").len(),
        STREAMED_BODY_LEN,
        "H1 streamed: chunked framing must still deliver the complete body"
    );

    // --- H2 (h2c prior knowledge on the plaintext proxy port) ---
    let h2 = reqwest::Client::builder()
        .http2_prior_knowledge()
        .no_proxy()
        .build()
        .expect("h2 client");
    let h2_resp = h2.get(&url).send().await.expect("H2 streamed");
    assert_eq!(h2_resp.version(), reqwest::Version::HTTP_2);
    assert_eq!(h2_resp.status(), StatusCode::OK);
    assert_no_protocol_managed(h2_resp.headers(), "H2 streamed");
    assert!(
        h2_resp.headers().get(header::CONTENT_LENGTH).is_none(),
        "H2 streamed: no Content-Length may reach the client; END_STREAM frames \
         the body"
    );
    assert_eq!(
        h2_resp.bytes().await.expect("H2 body").len(),
        STREAMED_BODY_LEN,
        "H2 streamed: END_STREAM framing must still deliver the complete body"
    );

    // --- H3 ---
    let h3 = Http3Client::insecure().expect("h3 client");
    let h3_url = format!("https://localhost:{https_port}/api/streamed");
    let h3_resp = h3_request_until_ready(&h3, &h3_url, Method::GET).await;
    assert_eq!(h3_resp.status, StatusCode::OK);
    assert_no_protocol_managed(&h3_resp.headers, "H3 streamed");
    assert!(
        h3_resp.headers.get(header::CONTENT_LENGTH).is_none(),
        "H3 streamed: no Content-Length may reach the client; FIN frames the body"
    );
    assert_eq!(
        h3_resp.body_bytes.len(),
        STREAMED_BODY_LEN,
        "H3 streamed: FIN framing must still deliver the complete body"
    );
    assert!(h3_resp.body_error.is_none(), "H3 streamed: clean body");

    assert!(
        hits.load(Ordering::SeqCst) >= 3,
        "each frontend must have reached the streaming backend"
    );
}

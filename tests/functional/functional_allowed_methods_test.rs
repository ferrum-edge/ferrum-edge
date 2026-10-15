//! Functional tests for route-level admission that runs before any plugin:
//! `allowed_methods`, and the refusal of a client-selected native-gRPC or
//! WebSocket flavor whose plugin view omits the route's admission policy.
//!
//! These tests exercise the live gateway frontend paths, not just config
//! validation, so both gates are checked on HTTP/1.1, h2c HTTP/2, and HTTP/3
//! requests before backend dispatch.

use crate::scaffolding::port_registry::TestSocket;
use crate::scaffolding::ports::{
    REFUSED_TCP_PORT_REFUSES_CONNECT_IMMEDIATELY, reserve_refused_tcp_port,
};

use crate::common::TestGateway;
use crate::scaffolding::clients::{GetOptions, Http3Client};

use http::{HeaderMap, Method};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

async fn start_counting_http1_backend(
    listener: TcpListener,
    target_path: &'static str,
    target_hits: Arc<AtomicUsize>,
) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let hits = Arc::clone(&target_hits);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await
            {
                Ok(Ok(n)) if n > 0 => n,
                _ => return,
            };
            let request = String::from_utf8_lossy(&buf[..n]);
            // HEAD counts too, so a HEAD that wrongly reached the backend is
            // visible to the "no backend request" assertions.
            let is_target = ["GET", "HEAD"]
                .iter()
                .any(|method| request.starts_with(&format!("{method} {target_path} ")));
            if !is_target {
                let _ = stream.shutdown().await;
                return;
            }

            hits.fetch_add(1, Ordering::SeqCst);
            let response = "HTTP/1.1 200 OK\r\n\
                            Content-Length: 2\r\n\
                            Content-Type: text/plain\r\n\
                            Connection: close\r\n\
                            \r\n\
                            ok";
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

fn build_config(backend_port: u16, allowed_methods: &[&str]) -> String {
    let allowed_methods_yaml = allowed_methods
        .iter()
        .map(|method| format!("      - \"{method}\"\n"))
        .collect::<String>();
    format!(
        r#"version: "1"
proxies:
  - id: "allowed-methods"
    listen_path: "/allowed"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false
    pool_enable_http2: false
    allowed_methods:
{allowed_methods_yaml}

consumers: []
plugin_configs:
  - id: "allowed-methods-security"
    plugin_name: security_headers
    scope: global
    enabled: true
    config:
      set:
        X-Synthetic-Policy: "enforced"
        Allow: "DELETE"
      remove: ["Content-Type"]
"#
    )
}

struct CountingBackend {
    port: u16,
    hits: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl CountingBackend {
    async fn start() -> Self {
        let listener = TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind backend");
        let port = listener.local_addr().expect("backend addr").port();
        let hits = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(start_counting_http1_backend(
            listener,
            "/allowed",
            Arc::clone(&hits),
        ));
        sleep(Duration::from_millis(100)).await;

        Self { port, hits, task }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

impl Drop for CountingBackend {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct AllowedMethodsHarness {
    gateway: TestGateway,
    backend: CountingBackend,
}

impl AllowedMethodsHarness {
    async fn new(config_allowed_methods: &[&str]) -> Self {
        let backend = CountingBackend::start().await;
        let gateway = TestGateway::builder()
            .mode_file(build_config(backend.port, config_allowed_methods))
            .log_level("warn")
            .spawn()
            .await
            .expect("start gateway");
        gateway
            .wait_for_proxy_port(Duration::from_secs(10))
            .await
            .expect("proxy port ready");

        Self { gateway, backend }
    }

    fn hits(&self) -> usize {
        self.backend.hits()
    }
}

fn assert_allow_header(headers: &HeaderMap, expected: &[&str]) {
    assert_eq!(
        headers.get_all(http::header::ALLOW).iter().count(),
        1,
        "405 response must carry exactly one authoritative Allow field"
    );
    let actual = headers
        .get(http::header::ALLOW)
        .and_then(|v| v.to_str().ok())
        .expect("Allow header");
    let actual_methods = actual
        .split(',')
        .map(|method| method.trim().to_ascii_uppercase())
        .collect::<Vec<_>>();
    let expected_methods = expected
        .iter()
        .map(|method| method.to_ascii_uppercase())
        .collect::<Vec<_>>();
    assert_eq!(actual_methods, expected_methods, "Allow header: {actual}");
}

#[ignore]
#[tokio::test]
async fn functional_allowed_methods_http1_and_h2_enforced_before_backend() {
    // Lowercase config value verifies route-level matching is case-insensitive.
    let h = AllowedMethodsHarness::new(&["get", "HEAD"]).await;

    let h1 = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("h1 client");
    let url = h.gateway.proxy_url("/allowed");

    let h1_allowed = h1.get(&url).send().await.expect("h1 allowed GET");
    assert_eq!(h1_allowed.status(), reqwest::StatusCode::OK);
    assert_eq!(h1_allowed.text().await.expect("h1 body"), "ok");
    assert_eq!(h.hits(), 1, "allowed HTTP/1.1 GET should reach backend");

    let h1_blocked = h1.post(&url).send().await.expect("h1 blocked POST");
    assert_eq!(h1_blocked.status(), reqwest::StatusCode::METHOD_NOT_ALLOWED);
    assert_allow_header(h1_blocked.headers(), &["GET", "HEAD"]);
    assert!(
        !h1_blocked
            .headers()
            .contains_key(http::header::CONTENT_TYPE)
    );
    assert_eq!(
        h1_blocked
            .headers()
            .get("x-synthetic-policy")
            .and_then(|value| value.to_str().ok()),
        Some("enforced")
    );
    let h1_body = h1_blocked.text().await.expect("h1 blocked body");
    assert!(
        h1_body.contains("Method Not Allowed"),
        "unexpected H1 body: {h1_body}"
    );
    assert_eq!(h.hits(), 1, "blocked HTTP/1.1 POST must not reach backend");

    let h2 = reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("h2c client");
    let h2_allowed = h2.get(&url).send().await.expect("h2 allowed GET");
    assert_eq!(h2_allowed.version(), reqwest::Version::HTTP_2);
    assert_eq!(h2_allowed.status(), reqwest::StatusCode::OK);
    assert_eq!(h2_allowed.text().await.expect("h2 body"), "ok");
    assert_eq!(h.hits(), 2, "allowed HTTP/2 GET should reach backend");

    let h2_blocked = h2.delete(&url).send().await.expect("h2 blocked DELETE");
    assert_eq!(h2_blocked.version(), reqwest::Version::HTTP_2);
    assert_eq!(h2_blocked.status(), reqwest::StatusCode::METHOD_NOT_ALLOWED);
    assert_allow_header(h2_blocked.headers(), &["GET", "HEAD"]);
    assert!(
        !h2_blocked
            .headers()
            .contains_key(http::header::CONTENT_TYPE)
    );
    assert_eq!(
        h2_blocked
            .headers()
            .get("x-synthetic-policy")
            .and_then(|value| value.to_str().ok()),
        Some("enforced")
    );
    let h2_body = h2_blocked.text().await.expect("h2 blocked body");
    assert!(
        h2_body.contains("Method Not Allowed"),
        "unexpected H2 body: {h2_body}"
    );
    assert_eq!(h.hits(), 2, "blocked HTTP/2 DELETE must not reach backend");
}

#[ignore]
#[tokio::test]
async fn functional_allowed_methods_http3_rejects_before_backend() {
    let backend = CountingBackend::start().await;

    let gateway = TestGateway::builder()
        .mode_file(build_config(backend.port, &["GET", "HEAD"]))
        .log_level("warn")
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env_ephemeral_port("FERRUM_PROXY_HTTPS_PORT")
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .spawn()
        .await
        .expect("start h3 gateway");
    let https_port = gateway
        .env_port("FERRUM_PROXY_HTTPS_PORT")
        .expect("harness-allocated HTTPS port");

    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://localhost:{https_port}/allowed");
    let options = GetOptions::default().method(Method::POST);
    let deadline = Instant::now() + Duration::from_secs(10);
    let response = loop {
        match client.get_with_options(&url, options.clone()).await {
            Ok(response) => break response,
            Err(err) if Instant::now() < deadline => {
                let _ = err;
                sleep(Duration::from_millis(100)).await;
            }
            Err(err) => panic!("H3 POST did not complete: {err}"),
        }
    };

    assert_eq!(response.status, http::StatusCode::METHOD_NOT_ALLOWED);
    assert_allow_header(&response.headers, &["GET", "HEAD"]);
    assert!(!response.headers.contains_key(http::header::CONTENT_TYPE));
    assert_eq!(
        response
            .headers
            .get("x-synthetic-policy")
            .and_then(|value| value.to_str().ok()),
        Some("enforced")
    );
    let body = response.body_text();
    assert!(
        body.contains("Method Not Allowed"),
        "unexpected H3 body: {body}"
    );
    assert_eq!(
        backend.hits(),
        0,
        "blocked HTTP/3 POST must not reach backend"
    );
}

/// A refused `HEAD` keeps its representation `Content-Length` but carries no
/// body bytes, whichever gateway path answered it: `allowed_methods` (JSON
/// and gRPC-Web shapes), a route miss, a path-parameter refusal, or a
/// backend-dispatch error. Hyper drops
/// a HEAD body on HTTP/1.1 itself, so HTTP/2 and HTTP/3 are the protocols that
/// would otherwise send DATA.
#[ignore]
#[tokio::test]
async fn functional_head_refusals_carry_no_body_on_h2_and_h3() {
    let backend = CountingBackend::start().await;
    // `/down` admits HEAD but its backend port is closed, so the gateway
    // answers with its own backend-dispatch error.
    // Held for the whole scenario so no other process can take the port.
    let refused = reserve_refused_tcp_port().expect("reserve refused backend port");
    let closed_port = refused.port;
    let config = build_config(backend.port, &["GET"]).replacen(
        "proxies:\n",
        &format!(
            "proxies:\n  - id: \"down\"\n    listen_path: \"/down\"\n    backend_scheme: http\n    backend_host: \"127.0.0.1\"\n    backend_port: {closed_port}\n    backend_connect_timeout_ms: 1000\n    strip_listen_path: false\n    pool_enable_http2: false\n"
        ),
        1,
    ) + "  - id: \"head-stdout-log\"\n    plugin_name: stdout_logging\n    scope: global\n    enabled: true\n    config: {}\n";
    let mut gateway = TestGateway::builder()
        .mode_file(config)
        .log_level("warn")
        .capture_output()
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env_ephemeral_port("FERRUM_PROXY_HTTPS_PORT")
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .spawn()
        .await
        .expect("start gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");
    let https_port = gateway
        .env_port("FERRUM_PROXY_HTTPS_PORT")
        .expect("harness-allocated HTTPS port");

    // (path, content-type, exact expected status). gRPC-Web refusals are
    // answered `200` with the status in a trailer frame; a path-parameter
    // spelling is refused `400`, or `404` if no route claims it. Either way the
    // body must be absent.
    let cases: &[(&str, Option<&str>, Option<u16>)] = &[
        ("/allowed", None, Some(405)),
        ("/allowed", Some("application/grpc-web"), None),
        ("/allowed", Some("application/grpc-web-text"), None),
        ("/no-such-route", None, Some(404)),
        ("/allowed;v=1", None, None),
        // Linux refuses the reserved port at once (502); other hosts drop the
        // SYN until the connect timeout, so only the body is checked there.
        (
            "/down",
            None,
            if REFUSED_TCP_PORT_REFUSES_CONNECT_IMMEDIATELY {
                Some(502)
            } else {
                None
            },
        ),
    ];

    let h2 = reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("h2c client");
    for (path, content_type, status) in cases {
        let mut request = h2.head(gateway.proxy_url(path));
        if let Some(content_type) = content_type {
            request = request.header("content-type", *content_type);
        }
        let response = request.send().await.expect("h2 HEAD");
        assert_eq!(response.version(), reqwest::Version::HTTP_2);
        let got = response.status().as_u16();
        match status {
            Some(expected) => assert_eq!(got, *expected, "{path} {content_type:?}"),
            None => assert!(got >= 200, "{path} {content_type:?}: unexpected {got}"),
        }
        if *status == Some(405) {
            assert_allow_header(response.headers(), &["GET"]);
        }
        if matches!(status, Some(404 | 405)) {
            assert_representation_length(response.headers(), path);
        }
        assert!(
            response.bytes().await.expect("h2 HEAD body").is_empty(),
            "an HTTP/2 HEAD refusal must carry no DATA: {path} {content_type:?}"
        );
    }

    let client = Http3Client::insecure().expect("h3 client");
    for (path, content_type, status) in cases {
        let url = format!("https://localhost:{https_port}{path}");
        let mut options = GetOptions::default()
            .method(Method::HEAD)
            .header("user-agent", H3_HEAD_TEST_AGENT);
        if let Some(content_type) = content_type {
            options = options.header("content-type", *content_type);
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        let response = loop {
            match client.get_with_options(&url, options.clone()).await {
                Ok(response) => break response,
                Err(_) if Instant::now() < deadline => sleep(Duration::from_millis(100)).await,
                Err(err) => panic!("H3 HEAD {path} did not complete: {err}"),
            }
        };
        let got = response.status.as_u16();
        match status {
            Some(expected) => assert_eq!(got, *expected, "{path} {content_type:?}"),
            None => assert!(got >= 200, "{path} {content_type:?}: unexpected {got}"),
        }
        if *status == Some(405) {
            assert_allow_header(&response.headers, &["GET"]);
        }
        if matches!(status, Some(404 | 405)) {
            assert_representation_length(&response.headers, path);
        }
        assert!(
            response.body_bytes.is_empty(),
            "an HTTP/3 HEAD refusal must carry no DATA: {path} {content_type:?}"
        );
        assert!(
            response.body_error.is_none(),
            "an HTTP/3 HEAD refusal must complete cleanly: {path} {content_type:?}: {:?}",
            response.body_error
        );
    }
    assert_eq!(
        backend.hits(),
        0,
        "a refused HEAD must not reach the backend"
    );

    // Positive control: the counter sees an admitted request.
    let admitted = h2
        .get(gateway.proxy_url("/allowed"))
        .send()
        .await
        .expect("h2 GET");
    assert_eq!(admitted.status(), reqwest::StatusCode::OK);
    assert_eq!(
        backend.hits(),
        1,
        "the backend counter must see admitted requests"
    );

    // Accounting: a HEAD backend-dispatch error delivers no body bytes, so its
    // transaction summary reports none on HTTP/2 and HTTP/3, while a GET to
    // the same route (the body-bearing control) reports its error body.
    // Methods are case-sensitive: the extension method `head` is not HEAD, so
    // its body is delivered and accounted.
    let lowercase_head = reqwest::Method::from_bytes(b"head").expect("extension method");
    for method in [
        reqwest::Method::HEAD,
        reqwest::Method::GET,
        lowercase_head.clone(),
    ] {
        let response = h2
            .request(method.clone(), gateway.proxy_url("/down"))
            .header("user-agent", H2_HEAD_TEST_AGENT)
            .send()
            .await
            .expect("h2 /down");
        let body = response.bytes().await.expect("h2 /down body");
        assert_eq!(
            body.is_empty(),
            method == reqwest::Method::HEAD,
            "h2 {method}"
        );
    }
    let lower_h3 = client
        .get_with_options(
            &format!("https://localhost:{https_port}/down"),
            GetOptions::default()
                .method(Method::from_bytes(b"head").expect("extension method"))
                .header("user-agent", H3_HEAD_TEST_AGENT),
        )
        .await
        .expect("H3 head /down");
    assert!(
        !lower_h3.body_bytes.is_empty(),
        "the extension method `head` keeps its body on HTTP/3"
    );
    let get_down = client
        .get_with_options(
            &format!("https://localhost:{https_port}/down"),
            GetOptions::default().header("user-agent", H3_HEAD_TEST_AGENT),
        )
        .await
        .expect("H3 GET /down");
    assert!(!get_down.body_bytes.is_empty());
    let down_entries = |raw: &str, agent: &str| -> Vec<serde_json::Value> {
        raw.lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|entry| {
                entry.get("request_path").and_then(|v| v.as_str()) == Some("/down")
                    && entry.get("request_user_agent").and_then(|v| v.as_str()) == Some(agent)
            })
            .collect()
    };
    let stdout = gateway
        .wait_for_captured_output(
            |raw| {
                down_entries(raw, H2_HEAD_TEST_AGENT).len() >= 3
                    && down_entries(raw, H3_HEAD_TEST_AGENT).len() >= 3
            },
            Duration::from_secs(10),
        )
        .await
        .expect("read stdout capture");
    for agent in [H2_HEAD_TEST_AGENT, H3_HEAD_TEST_AGENT] {
        let entries = down_entries(&stdout, agent);
        let bytes_for = |method: &str| {
            let entry = entries
                .iter()
                .find(|entry| entry.get("http_method").and_then(|v| v.as_str()) == Some(method))
                .unwrap_or_else(|| panic!("missing {agent} {method} /down summary in {entries:?}"));
            entry
                .get("bytes_received")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
        };
        assert_eq!(
            bytes_for("HEAD"),
            0,
            "{agent}: a suppressed HEAD body is not delivered"
        );
        assert!(
            bytes_for("head") > 0,
            "{agent}: the extension method `head` reports its delivered body"
        );
        assert!(
            bytes_for("GET") > 0,
            "{agent}: the control GET reports its error body"
        );
    }
    drop(refused);
    gateway.shutdown();
}

/// A refused HEAD keeps a non-zero representation `Content-Length`.
fn assert_representation_length(headers: &HeaderMap, path: &str) {
    let length = headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_else(|| panic!("{path}: HEAD refusal must keep Content-Length: {headers:?}"));
    assert!(length > 0, "{path}: representation length must not be zero");
}

const H2_HEAD_TEST_AGENT: &str = "ferrum-h2-head-test";
const H3_HEAD_TEST_AGENT: &str = "ferrum-h3-head-test";

// ---------------------------------------------------------------------------
// Client-selected flavors that cannot run the route's admission policy
// ---------------------------------------------------------------------------

/// A route whose only plugin is an HTTP-only admission policy (a
/// timestamp-only `soap_ws_security`), so its native-gRPC and WebSocket plugin
/// views omit it and the gateway must refuse those flavors before any plugin
/// runs.
fn build_route_protocol_admission_config(backend_port: u16) -> String {
    format!(
        r#"version: "1"
proxies:
  - id: "protocol-admission"
    listen_path: "/allowed"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false
    pool_enable_http2: false
    plugins:
      - plugin_config_id: "freshness"

consumers: []
plugin_configs:
  - id: "freshness"
    plugin_name: soap_ws_security
    scope: proxy
    proxy_id: "protocol-admission"
    enabled: true
    config:
      timestamp:
        require: true
        max_age_seconds: 300
        clock_skew_seconds: 300
      reject_missing_security_header: true
"#
    )
}

const ROUTE_PROTOCOL_REFUSAL_BODY: &str = "Request protocol not permitted on this route";

/// One length-prefixed, uncompressed gRPC message.
fn grpc_message_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(0);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Send an HTTP/1.1 WebSocket upgrade and return everything the gateway wrote
/// until the refusal body arrived, the connection closed, or 10s elapsed.
async fn http1_websocket_upgrade(port: u16, path: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect to gateway");
    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write upgrade request");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut received = Vec::new();
    let mut buf = [0u8; 4096];
    while Instant::now() < deadline
        && !String::from_utf8_lossy(&received).contains(ROUTE_PROTOCOL_REFUSAL_BODY)
    {
        match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => received.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&received).into_owned()
}

#[ignore]
#[tokio::test]
async fn functional_route_protocol_admission_refuses_h1_websocket_and_h2_grpc() {
    let backend = CountingBackend::start().await;
    let gateway = TestGateway::builder()
        .mode_file(build_route_protocol_admission_config(backend.port))
        .log_level("warn")
        .spawn()
        .await
        .expect("start gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");

    let upgrade = http1_websocket_upgrade(gateway.proxy_port, "/allowed").await;
    assert!(
        upgrade.starts_with("HTTP/1.1 403"),
        "a WebSocket upgrade the route's policy cannot run on must be refused: {upgrade}"
    );
    assert!(
        upgrade.contains(ROUTE_PROTOCOL_REFUSAL_BODY),
        "unexpected refusal: {upgrade}"
    );

    let h2 = reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("h2c client");
    let grpc = h2
        .post(gateway.proxy_url("/allowed/pkg.Service/Method"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(grpc_message_frame(b"ping"))
        .send()
        .await
        .expect("h2 gRPC request");
    assert_eq!(grpc.version(), reqwest::Version::HTTP_2);
    assert_eq!(grpc.status(), reqwest::StatusCode::OK);
    assert_eq!(
        grpc.headers()
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("7"),
        "native gRPC is refused trailers-only with PERMISSION_DENIED"
    );

    assert_eq!(
        backend.hits(),
        0,
        "a refused flavor must not reach the backend"
    );
}

#[ignore]
#[tokio::test]
async fn functional_route_protocol_admission_refuses_h3_grpc() {
    let backend = CountingBackend::start().await;
    let gateway = TestGateway::builder()
        .mode_file(build_route_protocol_admission_config(backend.port))
        .log_level("warn")
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env_ephemeral_port("FERRUM_PROXY_HTTPS_PORT")
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .spawn()
        .await
        .expect("start h3 gateway");
    let https_port = gateway
        .env_port("FERRUM_PROXY_HTTPS_PORT")
        .expect("harness-allocated HTTPS port");

    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://localhost:{https_port}/allowed/pkg.Service/Method");
    let options = GetOptions::default()
        .method(Method::POST)
        .header("content-type", "application/grpc")
        .body(bytes::Bytes::from(grpc_message_frame(b"ping")));
    let deadline = Instant::now() + Duration::from_secs(10);
    let response = loop {
        match client.get_with_options(&url, options.clone()).await {
            Ok(response) => break response,
            Err(err) if Instant::now() < deadline => {
                let _ = err;
                sleep(Duration::from_millis(100)).await;
            }
            Err(err) => panic!("H3 gRPC request did not complete: {err}"),
        }
    };

    assert_eq!(response.status, http::StatusCode::OK);
    assert_eq!(
        response.grpc_status(),
        Some(7),
        "native gRPC over HTTP/3 is refused with PERMISSION_DENIED"
    );
    assert!(response.body_bytes.is_empty());
    assert_eq!(
        backend.hits(),
        0,
        "a refused flavor must not reach the backend"
    );
}

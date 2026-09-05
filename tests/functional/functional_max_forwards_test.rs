//! RFC 9110 §7.6.2 `Max-Forwards` processing on proxied OPTIONS requests
//! (issue #4647), asserted from outside the process over real HTTP/1.1,
//! HTTP/2, and HTTP/3 frontends against an origin that records every request
//! it receives and echoes the hop budget it saw.
//!
//! Every case uses a path unique to its frontend, so "the origin was never
//! contacted" is an exact count of zero for that path rather than a race
//! against another case.

use crate::common::TestGateway;
use crate::scaffolding::clients::{GetOptions, Http3Client};
use crate::scaffolding::ports::reserve_port;

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

const ORIGIN: &str = "https://app.example";
const API_KEY: &str = "hop-budget-key";
const PROTOCOL_LEVEL_ALLOW: &str = "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS";
const MAX_REQUEST_HEAD_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
struct RecordedRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

impl RecordedRequest {
    fn header_values(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .collect()
    }
}

#[derive(Debug)]
struct CapturedResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

/// Loopback HTTP/1.1 origin that records every request head it receives and
/// answers `200` with the `Max-Forwards` value(s) it saw.
struct RecordingOrigin {
    port: u16,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    handle: Option<JoinHandle<()>>,
}

impl RecordingOrigin {
    async fn spawn() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&requests);
        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        tokio::spawn(serve_origin_connection(stream, Arc::clone(&recorder)));
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        });
        Ok(Self {
            port,
            requests,
            handle: Some(handle),
        })
    }

    async fn requests_for(&self, path: &str) -> Vec<RecordedRequest> {
        self.requests
            .lock()
            .await
            .iter()
            .filter(|request| request.path == path)
            .cloned()
            .collect()
    }

    fn abort(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

impl Drop for RecordingOrigin {
    fn drop(&mut self) {
        self.abort();
    }
}

async fn serve_origin_connection(
    mut stream: TcpStream,
    recorder: Arc<Mutex<Vec<RecordedRequest>>>,
) {
    let Some(head) = read_request_head(&mut stream).await else {
        return;
    };
    let Some(request) = parse_request_head(&head) else {
        return;
    };
    let echoed = request.header_values("max-forwards").join("|");
    recorder.lock().await.push(request);
    let body = format!(r#"{{"max_forwards":"{echoed}"}}"#);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nX-Origin: recording\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

async fn read_request_head(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut request = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    while request.len() < MAX_REQUEST_HEAD_BYTES {
        let remaining = MAX_REQUEST_HEAD_BYTES - request.len();
        let read_len = remaining.min(chunk.len());
        match stream.read(&mut chunk[..read_len]).await {
            Ok(0) => break,
            Ok(size) => request.extend_from_slice(&chunk[..size]),
            Err(_) => return None,
        }
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return Some(request);
        }
    }
    None
}

fn parse_request_head(head: &[u8]) -> Option<RecordedRequest> {
    let head = String::from_utf8_lossy(head);
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
    }
    Some(RecordedRequest {
        method,
        path,
        headers,
    })
}

struct MaxForwardsHarness {
    gateway: TestGateway,
    origin: RecordingOrigin,
    https_port: u16,
}

impl MaxForwardsHarness {
    async fn spawn() -> Self {
        let mut origin = RecordingOrigin::spawn()
            .await
            .expect("spawn recording origin");
        let config = gateway_config(origin.port);
        let mut last_error = String::new();
        for _ in 0..5 {
            let reservation = reserve_port().await.expect("reserve HTTPS port");
            let https_port = reservation.drop_and_take_port();
            let spawn = TestGateway::builder()
                .mode_file(config.clone())
                .log_level("warn")
                // The pinned HTTPS/QUIC port must change between attempts, so
                // this outer loop owns startup retries.
                .max_attempts(1)
                .capture_output()
                .env("FERRUM_ENABLE_HTTP3", "true")
                .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
                .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
                .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
                // Pool warmup would open a connection to the origin before the
                // first case runs; the origin-count assertions must see only
                // request-driven traffic.
                .env("FERRUM_POOL_WARMUP_ENABLED", "false")
                .spawn()
                .await;
            match spawn {
                Ok(mut gateway) => {
                    match gateway.wait_for_proxy_port(Duration::from_secs(5)).await {
                        Ok(()) => {
                            return Self {
                                gateway,
                                origin,
                                https_port,
                            };
                        }
                        Err(error) => {
                            last_error = error.to_string();
                            gateway.shutdown();
                        }
                    }
                }
                Err(error) => last_error = error.to_string(),
            }
        }
        origin.abort();
        panic!("start Max-Forwards gateway after retries: {last_error}");
    }

    fn h1_h2_url(&self, path: &str) -> String {
        self.gateway.proxy_url(path)
    }

    fn h3_url(&self, path: &str) -> String {
        format!("https://localhost:{}{path}", self.https_port)
    }

    fn shutdown(&mut self) {
        self.gateway.shutdown();
        self.origin.abort();
    }
}

fn gateway_config(backend_port: u16) -> String {
    let config = serde_json::json!({
        "version": "1",
        "proxies": [
            proxy("hop", "/hop", backend_port, &[], None),
            proxy("methods", "/methods", backend_port, &[], Some(&["GET", "OPTIONS"])),
            proxy("protected", "/protected", backend_port, &["hop-key-auth"], None),
            proxy("cors", "/cors", backend_port, &["hop-cors"], None),
        ],
        "consumers": [{
            "id": "hop-consumer",
            "username": "hop-user",
            "credentials": {"keyauth": [{"key": API_KEY}]}
        }],
        "upstreams": [],
        "plugin_configs": [
            {
                "id": "hop-key-auth",
                "plugin_name": "key_auth",
                "scope": "proxy",
                "proxy_id": "protected",
                "enabled": true,
                "config": {"key_location": "header:X-API-Key"}
            },
            {
                "id": "hop-cors",
                "plugin_name": "cors",
                "scope": "proxy",
                "proxy_id": "cors",
                "enabled": true,
                "config": {
                    "allowed_origins": [ORIGIN],
                    "allowed_methods": ["PUT"],
                    "allowed_headers": ["X-Custom"],
                    "max_age": 600
                }
            }
        ]
    });
    serde_yaml::to_string(&config).expect("serialize Max-Forwards config")
}

fn proxy(
    id: &str,
    listen_path: &str,
    backend_port: u16,
    plugin_ids: &[&str],
    allowed_methods: Option<&[&str]>,
) -> serde_json::Value {
    let plugins = plugin_ids
        .iter()
        .map(|plugin_config_id| serde_json::json!({"plugin_config_id": plugin_config_id}))
        .collect::<Vec<_>>();
    let mut proxy = serde_json::json!({
        "id": id,
        "listen_path": listen_path,
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": backend_port,
        "strip_listen_path": false,
        "pool_enable_http2": false,
        "plugins": plugins
    });
    if let Some(methods) = allowed_methods {
        proxy["allowed_methods"] = serde_json::json!(methods);
    }
    proxy
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Frontend {
    H1,
    H2,
    H3,
}

impl Frontend {
    const ALL: [Frontend; 3] = [Frontend::H1, Frontend::H2, Frontend::H3];

    fn label(self) -> &'static str {
        match self {
            Self::H1 => "h1",
            Self::H2 => "h2",
            Self::H3 => "h3",
        }
    }
}

async fn send(
    harness: &MaxForwardsHarness,
    frontend: Frontend,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
) -> CapturedResponse {
    match frontend {
        Frontend::H1 => {
            let builder = reqwest::Client::builder().http1_only();
            send_reqwest(harness, builder, None, method, path, headers).await
        }
        Frontend::H2 => {
            let builder = reqwest::Client::builder().http2_prior_knowledge();
            let expected = Some(reqwest::Version::HTTP_2);
            send_reqwest(harness, builder, expected, method, path, headers).await
        }
        Frontend::H3 => send_h3(harness, method, path, headers).await,
    }
}

async fn send_reqwest(
    harness: &MaxForwardsHarness,
    builder: reqwest::ClientBuilder,
    expected_version: Option<reqwest::Version>,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
) -> CapturedResponse {
    let client = builder
        .timeout(Duration::from_secs(5))
        .build()
        .expect("HTTP client");
    let mut request = client.request(method, harness.h1_h2_url(path));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = request.send().await.expect("proxied request");
    if let Some(version) = expected_version {
        assert_eq!(response.version(), version);
    }
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.bytes().await.expect("response body");
    CapturedResponse {
        status,
        headers,
        body,
    }
}

async fn send_h3(
    harness: &MaxForwardsHarness,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
) -> CapturedResponse {
    let client = Http3Client::insecure().expect("H3 client");
    let mut options = GetOptions::default().method(method);
    for (name, value) in headers {
        options = options.header(*name, *value);
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match client
            .get_with_options(&harness.h3_url(path), options.clone())
            .await
        {
            Ok(response) => {
                return CapturedResponse {
                    status: response.status,
                    headers: response.headers,
                    body: response.body_bytes,
                };
            }
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!("H3 request did not complete: {error}"),
        }
    }
}

fn header<'a>(response: &'a CapturedResponse, name: &str) -> &'a str {
    response
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| panic!("missing {name}: {response:?}"))
}

fn assert_local_answer(response: &CapturedResponse, status: StatusCode, case: &str) {
    assert_eq!(response.status, status, "{case}: {response:?}");
    assert!(
        response.headers.get("x-origin").is_none(),
        "{case}: a gateway-local answer must not carry origin headers: {response:?}"
    );
}

fn assert_origin_answer(response: &CapturedResponse, case: &str) {
    assert_eq!(response.status, StatusCode::OK, "{case}: {response:?}");
    assert_eq!(header(response, "x-origin"), "recording", "{case}");
}

async fn assert_no_origin_request(harness: &MaxForwardsHarness, path: &str, case: &str) {
    let requests = harness.origin.requests_for(path).await;
    assert!(
        requests.is_empty(),
        "{case}: the origin must never be contacted for {path}: {requests:?}"
    );
}

async fn assert_origin_saw(
    harness: &MaxForwardsHarness,
    path: &str,
    method: &str,
    expected_max_forwards: &[&str],
    case: &str,
) {
    let requests = harness.origin.requests_for(path).await;
    assert!(!requests.is_empty(), "{case}: the origin must be contacted for {path}");
    for request in &requests {
        assert_eq!(request.method, method, "{case}: {request:?}");
        assert_eq!(
            request.header_values("max-forwards"),
            expected_max_forwards,
            "{case}: {request:?}"
        );
    }
}

async fn assert_frontend(harness: &MaxForwardsHarness, frontend: Frontend) {
    let label = frontend.label();
    let zero = [("max-forwards", "0")];
    let one = [("max-forwards", "1")];
    let ten = [("max-forwards", "10")];
    let malformed = [("max-forwards", "abc")];

    // Zero: the gateway is the final recipient.
    let case = format!("{label} OPTIONS Max-Forwards: 0");
    let path = format!("/hop/{label}/zero");
    let response = send(harness, frontend, Method::OPTIONS, &path, &zero).await;
    assert_local_answer(&response, StatusCode::NO_CONTENT, &case);
    assert_eq!(header(&response, "allow"), PROTOCOL_LEVEL_ALLOW, "{case}");
    assert!(response.body.is_empty(), "{case}: {response:?}");
    assert_no_origin_request(harness, &path, &case).await;

    // One: forwarded as zero.
    let case = format!("{label} OPTIONS Max-Forwards: 1");
    let path = format!("/hop/{label}/one");
    let response = send(harness, frontend, Method::OPTIONS, &path, &one).await;
    assert_origin_answer(&response, &case);
    assert_eq!(response.body.as_ref(), br#"{"max_forwards":"0"}"#, "{case}");
    assert_origin_saw(harness, &path, "OPTIONS", &["0"], &case).await;

    // Ten: forwarded as nine.
    let case = format!("{label} OPTIONS Max-Forwards: 10");
    let path = format!("/hop/{label}/ten");
    let response = send(harness, frontend, Method::OPTIONS, &path, &ten).await;
    assert_origin_answer(&response, &case);
    assert_eq!(response.body.as_ref(), br#"{"max_forwards":"9"}"#, "{case}");
    assert_origin_saw(harness, &path, "OPTIONS", &["9"], &case).await;

    // Oversized: saturates to the documented recipient maximum, minus one.
    let case = format!("{label} OPTIONS oversized Max-Forwards");
    let path = format!("/hop/{label}/oversized");
    let oversized = [("max-forwards", "99999999999999999999")];
    let response = send(harness, frontend, Method::OPTIONS, &path, &oversized).await;
    assert_origin_answer(&response, &case);
    assert_origin_saw(harness, &path, "OPTIONS", &["4294967294"], &case).await;

    // Absent: existing behaviour, nothing is added.
    let case = format!("{label} OPTIONS without Max-Forwards");
    let path = format!("/hop/{label}/absent");
    let response = send(harness, frontend, Method::OPTIONS, &path, &[]).await;
    assert_origin_answer(&response, &case);
    assert_eq!(response.body.as_ref(), br#"{"max_forwards":""}"#, "{case}");
    assert_origin_saw(harness, &path, "OPTIONS", &[], &case).await;

    // Malformed: refused, never forwarded, never reset.
    let case = format!("{label} OPTIONS malformed Max-Forwards");
    let path = format!("/hop/{label}/malformed");
    let response = send(harness, frontend, Method::OPTIONS, &path, &malformed).await;
    assert_local_answer(&response, StatusCode::BAD_REQUEST, &case);
    assert_eq!(response.body.as_ref(), br#"{"error":"Invalid Max-Forwards header"}"#, "{case}");
    assert_no_origin_request(harness, &path, &case).await;

    // Repeated field lines: not a list field, refused even when they agree.
    let case = format!("{label} OPTIONS repeated Max-Forwards");
    let path = format!("/hop/{label}/repeated");
    let repeated = [("max-forwards", "1"), ("max-forwards", "1")];
    let response = send(harness, frontend, Method::OPTIONS, &path, &repeated).await;
    assert_local_answer(&response, StatusCode::BAD_REQUEST, &case);
    assert_no_origin_request(harness, &path, &case).await;

    // Other methods are untouched: the field travels as sent.
    let case = format!("{label} GET Max-Forwards: 0");
    let path = format!("/hop/{label}/get-zero");
    let response = send(harness, frontend, Method::GET, &path, &zero).await;
    assert_origin_answer(&response, &case);
    assert_origin_saw(harness, &path, "GET", &["0"], &case).await;

    // Protected routes enforce their access policy before the hop budget.
    let case = format!("{label} protected OPTIONS Max-Forwards: 0 without credentials");
    let path = format!("/protected/{label}/zero-anonymous");
    let response = send(harness, frontend, Method::OPTIONS, &path, &zero).await;
    assert_local_answer(&response, StatusCode::UNAUTHORIZED, &case);
    assert_no_origin_request(harness, &path, &case).await;

    let case = format!("{label} protected OPTIONS Max-Forwards: 0 with credentials");
    let path = format!("/protected/{label}/zero-authenticated");
    let authenticated = [("max-forwards", "0"), ("x-api-key", API_KEY)];
    let response = send(harness, frontend, Method::OPTIONS, &path, &authenticated).await;
    assert_local_answer(&response, StatusCode::NO_CONTENT, &case);
    assert_eq!(header(&response, "allow"), PROTOCOL_LEVEL_ALLOW, "{case}");
    assert_no_origin_request(harness, &path, &case).await;

    let case = format!("{label} protected OPTIONS Max-Forwards: 1 with credentials");
    let path = format!("/protected/{label}/one-authenticated");
    let authenticated = [("max-forwards", "1"), ("x-api-key", API_KEY)];
    let response = send(harness, frontend, Method::OPTIONS, &path, &authenticated).await;
    assert_origin_answer(&response, &case);
    assert_origin_saw(harness, &path, "OPTIONS", &["0"], &case).await;

    // A CORS preflight stays a local `cors` answer, whatever the budget says.
    let case = format!("{label} CORS preflight Max-Forwards: 0");
    let path = format!("/cors/{label}/preflight");
    let preflight = [
        ("max-forwards", "0"),
        ("origin", ORIGIN),
        ("access-control-request-method", "PUT"),
    ];
    let response = send(harness, frontend, Method::OPTIONS, &path, &preflight).await;
    assert_local_answer(&response, StatusCode::NO_CONTENT, &case);
    assert_eq!(header(&response, "access-control-allow-origin"), ORIGIN, "{case}");
    assert_eq!(header(&response, "access-control-allow-methods"), "PUT", "{case}");
    assert_no_origin_request(harness, &path, &case).await;

    // `Allow` on the final-recipient answer reflects the route's methods.
    let case = format!("{label} allowed_methods OPTIONS Max-Forwards: 0");
    let path = format!("/methods/{label}/zero");
    let response = send(harness, frontend, Method::OPTIONS, &path, &zero).await;
    assert_local_answer(&response, StatusCode::NO_CONTENT, &case);
    assert_eq!(header(&response, "allow"), "GET, OPTIONS", "{case}");
    assert_no_origin_request(harness, &path, &case).await;
}

#[ignore]
#[tokio::test]
async fn functional_options_max_forwards_is_processed_on_h1_h2_h3() {
    let mut harness = MaxForwardsHarness::spawn().await;
    for frontend in Frontend::ALL {
        assert_frontend(&harness, frontend).await;
    }
    harness.shutdown();
}

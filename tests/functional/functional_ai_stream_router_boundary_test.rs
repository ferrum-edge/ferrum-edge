//! Backend-observed `ai_stream_router` provider-boundary enforcement on H1/H2/H3.
//!
//! GHSA-xhp5-hqj8-3mwg. `ai_stream_router` runs at priority 2984 and the generic
//! `request_transformer` runs at 3000, so every assertion here is made at the
//! ACTUAL third-party provider socket, after a hostile later transformer had its
//! turn on the same request. Source-text wiring assertions cannot show this; only
//! the bytes the provider receives can.
//!
//! Proven at the provider boundary, on all three frontends:
//!
//!   * a later `update` / `add` / `rename` of `Authorization` or a provider
//!     credential header cannot replace or duplicate the selected provider
//!     credential, and cannot smuggle a normal-backend static secret or a
//!     client-controlled token across the boundary;
//!   * a later final-body `model` rewrite is rejected BEFORE any backend request
//!     is admitted (the provider socket sees nothing at all);
//!   * a later query rule cannot append or relocate a normal-backend secret onto
//!     the provider target;
//!   * every retry attempt carries the same exact provider credential, committed
//!     model, and committed query, with no hostile value.
//!
//! Run with: cargo build --bin ferrum-edge && cargo test --test functional_tests \
//!   functional_ai_stream_router_boundary -- --ignored --nocapture

use crate::common::TestGateway;
use crate::scaffolding::clients::{GetOptions, Http3Client};

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

/// The provider's own credential. Only this value may cross the boundary.
const PROVIDER_KEY: &str = "sk-provider-only-secret";
/// A static secret an operator configured for the NORMAL backend. A generic
/// header/query rule must never be able to relocate it onto the provider.
const NORMAL_BACKEND_SECRET: &str = "NORMAL-BACKEND-STATIC-SECRET";
/// A client-supplied token a later `rename` rule tries to promote into
/// `Authorization`.
const CLIENT_TOKEN: &str = "CLIENT-SUPPLIED-TOKEN";
/// A hostile provider-credential-shaped header value.
const HOSTILE_API_KEY: &str = "HOSTILE-X-API-KEY";

/// The model the client sends; it selects the provider.
const COMMITTED_MODEL: &str = "gpt-4o-mini";
/// The model a later body rule tries to substitute after selection.
const HOSTILE_MODEL: &str = "hostile-substituted-model";

const PROVIDER_PATH: &str = "/v1/chat/completions";
/// Client query at claim time. This exact string is the committed query.
const CLIENT_QUERY: &str = "client_flag=1";
/// Query pair a later rule tries to append to the provider URL.
const HOSTILE_QUERY_KEY: &str = "normal_secret";

const PROVIDER_SSE: &str = concat!(
    "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":null}]}\n\n",
    "data: [DONE]\n\n",
);

// ---------------------------------------------------------------------------
// 1. Credential + query boundary, observed at the provider socket
// ---------------------------------------------------------------------------

#[ignore]
#[tokio::test]
async fn ai_stream_router_provider_boundary_survives_a_hostile_transformer_on_h1_h2_h3() {
    let mut harness = BoundaryHarness::spawn(BoundaryMode::HostileHeadersAndQuery).await;

    for protocol in ["HTTP/1.1", "HTTP/2", "HTTP/3"] {
        harness.reset_captures();
        let body = streaming_body(COMMITTED_MODEL);
        let status = harness.send(protocol, &body).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{protocol}: claimed streaming request should reach the provider"
        );

        let captured = harness
            .wait_for_provider_requests(1, Duration::from_secs(5))
            .await
            .unwrap_or_else(|| panic!("{protocol}: provider never saw the request"));
        assert_eq!(
            captured.len(),
            1,
            "{protocol}: expected exactly one provider request: {:?}",
            targets_of(&captured)
        );
        assert_provider_boundary(protocol, "single attempt", &captured[0]);

        // The NORMAL backend must never be contacted for a claimed request; a
        // hit there would mean the route override was undone rather than that
        // the credential was protected.
        assert!(
            harness.normal_backend.requests().is_empty(),
            "{protocol}: a claimed request must not reach the normal backend"
        );
    }

    harness.shutdown();
}

// ---------------------------------------------------------------------------
// 2. Late model rewrite is rejected before ANY backend request is admitted
// ---------------------------------------------------------------------------

#[ignore]
#[tokio::test]
async fn ai_stream_router_rejects_a_late_model_rewrite_before_backend_admission_on_h1_h2_h3() {
    let mut harness = BoundaryHarness::spawn(BoundaryMode::HostileModelRewrite).await;

    for protocol in ["HTTP/1.1", "HTTP/2", "HTTP/3"] {
        harness.reset_captures();
        let body = streaming_body(COMMITTED_MODEL);
        let status = harness.send(protocol, &body).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{protocol}: a rewritten final model must fail closed with 400"
        );

        // Fail-closed means no egress at all. Give the gateway a real window to
        // have dispatched, then assert the provider socket stayed silent.
        tokio::time::sleep(Duration::from_millis(400)).await;
        let provider = harness.provider.requests();
        assert!(
            provider.is_empty(),
            "{protocol}: no backend request may be admitted after a model-policy \
             rejection, saw: {:?}",
            targets_of(&provider)
        );
        assert!(
            harness.normal_backend.requests().is_empty(),
            "{protocol}: the normal backend must not be contacted either"
        );
    }

    harness.shutdown();
}

// ---------------------------------------------------------------------------
// 3. Every retry attempt repeats the committed boundary
// ---------------------------------------------------------------------------

#[ignore]
#[tokio::test]
async fn ai_stream_router_retry_attempts_each_repeat_the_committed_provider_boundary() {
    let mut harness = BoundaryHarness::spawn(BoundaryMode::FailingProviderWithRetries).await;

    let body = streaming_body(COMMITTED_MODEL);
    let status = harness.send("HTTP/1.1", &body).await;
    assert_eq!(
        status.as_u16(),
        500,
        "the retry budget should exhaust against a always-500 provider"
    );

    let captured = harness
        .wait_for_provider_requests(3, Duration::from_secs(10))
        .await
        .expect("timed out waiting for the original attempt plus two retries");
    assert_eq!(
        captured.len(),
        3,
        "expected 1 original + 2 retries: {:?}",
        targets_of(&captured)
    );
    for (idx, attempt) in captured.iter().enumerate() {
        assert_provider_boundary("HTTP/1.1", &format!("retry attempt {idx}"), attempt);
    }

    harness.shutdown();
}

// ---------------------------------------------------------------------------
// Shared assertion: what the provider socket is allowed to observe
// ---------------------------------------------------------------------------

/// Every property the advisory fix must hold at the real provider boundary.
fn assert_provider_boundary(protocol: &str, attempt: &str, request: &CapturedRequest) {
    let raw = &request.raw;
    let lower = raw.to_ascii_lowercase();
    let ctx = format!("{protocol} / {attempt}");

    // --- exactly one Authorization, and it is the provider's own -------------
    let authorization_lines: Vec<&str> = lower
        .lines()
        .filter(|line| line.starts_with("authorization:"))
        .collect();
    assert_eq!(
        authorization_lines.len(),
        1,
        "{ctx}: the provider must see exactly one Authorization header, got {authorization_lines:?}"
    );
    assert_eq!(
        authorization_lines[0].trim(),
        format!("authorization: bearer {PROVIDER_KEY}"),
        "{ctx}: the provider credential must be the selected provider's own"
    );

    // --- no hostile credential material anywhere in the request --------------
    for forbidden in [NORMAL_BACKEND_SECRET, CLIENT_TOKEN, HOSTILE_API_KEY] {
        assert!(
            !raw.contains(forbidden),
            "{ctx}: '{forbidden}' must never cross the provider boundary:\n{raw}"
        );
    }
    for forbidden_header in [
        "x-api-key:",
        "x-client-token:",
        "x-consumer-username:",
        "cookie:",
    ] {
        assert!(
            !lower.contains(forbidden_header),
            "{ctx}: '{forbidden_header}' must be stripped at the provider boundary:\n{raw}"
        );
    }

    // --- committed query only: nothing appended, nothing relocated ----------
    assert_eq!(
        request.target,
        format!("{PROVIDER_PATH}?{CLIENT_QUERY}"),
        "{ctx}: the provider target must be exactly the committed destination and query"
    );
    assert!(
        !raw.contains(HOSTILE_QUERY_KEY),
        "{ctx}: a later query rule must not reach the provider URL:\n{raw}"
    );

    // --- committed model only ------------------------------------------------
    let committed_model_field = format!("\"model\":\"{COMMITTED_MODEL}\"");
    assert!(
        request.body.contains(&committed_model_field),
        "{ctx}: the provider must receive the committed model: {}",
        request.body
    );
    assert!(
        !request.body.contains(HOSTILE_MODEL),
        "{ctx}: a substituted model must never reach the provider: {}",
        request.body
    );
}

fn streaming_body(model: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "model": model,
        "stream": true,
        "messages": [{"role": "user", "content": "hi"}]
    }))
    .expect("serialize streaming request body")
}

fn targets_of(requests: &[CapturedRequest]) -> Vec<String> {
    requests.iter().map(|r| r.target.clone()).collect()
}

// ---------------------------------------------------------------------------
// Capturing backend
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct CapturedRequest {
    method: String,
    target: String,
    raw: String,
    body: String,
}

struct CapturingBackend {
    port: u16,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    notify: Arc<Notify>,
    handle: Option<JoinHandle<()>>,
}

impl CapturingBackend {
    /// `fail_all` makes every response a retryable 500 so the retry ladder can
    /// be driven deterministically.
    async fn spawn(fail_all: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind capture backend");
        let port = listener.local_addr().expect("local addr").port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let notify = Arc::new(Notify::new());
        let requests_task = requests.clone();
        let notify_task = notify.clone();
        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut stream, _)) => {
                        let requests = requests_task.clone();
                        let notify = notify_task.clone();
                        tokio::spawn(async move {
                            let Some(captured) = read_request(&mut stream).await else {
                                return;
                            };
                            requests.lock().expect("requests lock").push(captured);
                            notify.notify_waiters();
                            let response = if fail_all {
                                "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: 16\r\nConnection: close\r\n\r\n{\"error\":\"down\"}".to_string()
                            } else {
                                format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{PROVIDER_SSE}",
                                    PROVIDER_SSE.len()
                                )
                            };
                            let _ = stream.write_all(response.as_bytes()).await;
                            let _ = stream.shutdown().await;
                        });
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        });
        Self {
            port,
            requests,
            notify,
            handle: Some(handle),
        }
    }

    /// Only the requests under test. Startup/warmup capability probes (which do
    /// not POST the provider path) are filtered so counts stay deterministic.
    fn requests(&self) -> Vec<CapturedRequest> {
        self.requests
            .lock()
            .expect("requests lock")
            .iter()
            .filter(|r| r.method == "POST" && r.target.starts_with(PROVIDER_PATH))
            .cloned()
            .collect()
    }

    fn clear(&self) {
        self.requests.lock().expect("requests lock").clear();
    }

    fn abort(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

impl Drop for CapturingBackend {
    fn drop(&mut self) {
        self.abort();
    }
}

/// Read one complete HTTP/1.1 request: head, then exactly `Content-Length`
/// body bytes (the gateway always sends a length-delimited buffered body here
/// because `ai_stream_router` is a deferred request-body transformer).
async fn read_request(stream: &mut TcpStream) -> Option<CapturedRequest> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        match stream.read(&mut chunk).await {
            Ok(0) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return None,
        }
    };

    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let content_length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);

    while buf.len() < head_end + content_length {
        match stream.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }

    let request_line = head.lines().next().unwrap_or("").to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let body = String::from_utf8_lossy(&buf[head_end.min(buf.len())..]).into_owned();
    Some(CapturedRequest {
        method,
        target,
        raw: String::from_utf8_lossy(&buf).into_owned(),
        body,
    })
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum BoundaryMode {
    HostileHeadersAndQuery,
    HostileModelRewrite,
    FailingProviderWithRetries,
}

struct BoundaryHarness {
    gateway: TestGateway,
    provider: CapturingBackend,
    normal_backend: CapturingBackend,
    https_port: u16,
}

impl BoundaryHarness {
    async fn spawn(mode: BoundaryMode) -> Self {
        let fail_all = mode == BoundaryMode::FailingProviderWithRetries;
        let provider = CapturingBackend::spawn(fail_all).await;
        let normal_backend = CapturingBackend::spawn(false).await;
        let https_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve https port");
        let https_port = https_listener.local_addr().expect("https addr").port();
        drop(https_listener);

        let gateway = TestGateway::builder()
            .mode_file(boundary_config(mode, provider.port, normal_backend.port))
            .log_level("warn")
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .spawn()
            .await
            .expect("start ai_stream_router boundary gateway");
        gateway
            .wait_for_proxy_port(Duration::from_secs(5))
            .await
            .expect("proxy port ready");

        Self {
            gateway,
            provider,
            normal_backend,
            https_port,
        }
    }

    fn reset_captures(&self) {
        self.provider.clear();
        self.normal_backend.clear();
    }

    async fn wait_for_provider_requests(
        &self,
        count: usize,
        timeout: Duration,
    ) -> Option<Vec<CapturedRequest>> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let requests = self.provider.requests();
            if requests.len() >= count {
                return Some(requests);
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::select! {
                _ = self.provider.notify.notified() => {}
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
    }

    async fn send(&self, protocol: &str, body: &[u8]) -> StatusCode {
        match protocol {
            "HTTP/1.1" => self.send_h1(body).await,
            "HTTP/2" => self.send_h2(body).await,
            "HTTP/3" => self.send_h3(body).await,
            other => panic!("unsupported protocol {other}"),
        }
    }

    async fn send_h1(&self, body: &[u8]) -> StatusCode {
        let client = reqwest::Client::builder()
            .http1_only()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("http1 client");
        let url = self
            .gateway
            .proxy_url(&format!("{PROVIDER_PATH}?{CLIENT_QUERY}"));
        client
            .post(url)
            .header("content-type", "application/json")
            .header("x-client-token", CLIENT_TOKEN)
            .header("cookie", format!("session={CLIENT_TOKEN}"))
            .body(body.to_vec())
            .send()
            .await
            .expect("http1 request")
            .status()
    }

    async fn send_h2(&self, body: &[u8]) -> StatusCode {
        let stream = TcpStream::connect(("127.0.0.1", self.gateway.proxy_port))
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
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!(
                "http://127.0.0.1:{}{PROVIDER_PATH}?{CLIENT_QUERY}",
                self.gateway.proxy_port
            ))
            .header("content-type", "application/json")
            .header("x-client-token", CLIENT_TOKEN)
            .header("cookie", format!("session={CLIENT_TOKEN}"))
            .body(Full::<Bytes>::new(Bytes::from(body.to_vec())))
            .expect("build h2 request");
        let response = sender.send_request(request).await.expect("send h2 request");
        let status = response.status();
        let _ = response.into_body().collect().await;
        drop(sender);
        conn_task.abort();
        status
    }

    async fn send_h3(&self, body: &[u8]) -> StatusCode {
        let client = Http3Client::insecure().expect("h3 client");
        let url = format!(
            "https://localhost:{}{PROVIDER_PATH}?{CLIENT_QUERY}",
            self.https_port
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            let options = GetOptions::default()
                .method(Method::POST)
                .header("content-type", "application/json")
                .header("x-client-token", CLIENT_TOKEN)
                .header("cookie", format!("session={CLIENT_TOKEN}"))
                .body(Bytes::from(body.to_vec()));
            match client.get_with_options(&url, options).await {
                Ok(response) => return response.status,
                Err(_) if std::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => panic!("H3 boundary request did not complete: {error}"),
            }
        }
    }

    fn shutdown(&mut self) {
        self.gateway.shutdown();
        self.provider.abort();
        self.normal_backend.abort();
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// The hostile later transformer. Header rules cover `update` (overwrite the
/// installed provider credential), `add` (introduce a provider-shaped
/// credential header the router had stripped), and `rename` (promote a
/// client-supplied token into `Authorization`), plus a forged gateway identity
/// assertion. The query rule tries to append a normal-backend secret to the
/// third-party URL.
fn hostile_header_and_query_rules() -> serde_json::Value {
    serde_json::json!([
        {"operation": "update", "target": "header", "key": "Authorization",
         "value": format!("Bearer {NORMAL_BACKEND_SECRET}")},
        {"operation": "add", "target": "header", "key": "X-Api-Key", "value": HOSTILE_API_KEY},
        {"operation": "update", "target": "header", "key": "X-Consumer-Username",
         "value": "forged-consumer"},
        {"operation": "rename", "target": "header", "key": "X-Client-Token",
         "new_key": "Authorization"},
        {"operation": "add", "target": "query", "key": HOSTILE_QUERY_KEY,
         "value": NORMAL_BACKEND_SECRET}
    ])
}

/// The hostile later body rule: substitute the already-selected model.
fn hostile_model_rule() -> serde_json::Value {
    serde_json::json!([
        {"operation": "update", "target": "body", "key": "model", "value": HOSTILE_MODEL}
    ])
}

fn boundary_config(mode: BoundaryMode, provider_port: u16, normal_backend_port: u16) -> String {
    let rules = match mode {
        BoundaryMode::HostileModelRewrite => hostile_model_rule(),
        // The retry lane keeps the hostile header/query rules so each replayed
        // attempt is re-checked against them, not just the first.
        BoundaryMode::HostileHeadersAndQuery | BoundaryMode::FailingProviderWithRetries => {
            hostile_header_and_query_rules()
        }
    };

    let mut proxy = serde_json::json!({
        "id": "asr-boundary",
        "listen_path": "/",
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": normal_backend_port,
        "strip_listen_path": false,
        "pool_enable_http2": false,
        "plugins": [
            {"plugin_config_id": "asr-boundary-router"},
            {"plugin_config_id": "asr-boundary-transformer"}
        ]
    });
    if mode == BoundaryMode::FailingProviderWithRetries {
        proxy["retry"] = serde_json::json!({
            "max_retries": 2,
            "retryable_status_codes": [500],
            "retryable_methods": ["POST"],
            "backoff_strategy": "fixed",
            "backoff_base_ms": 20
        });
    }

    let config = serde_json::json!({
        "version": "1",
        "proxies": [proxy],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [
            {
                "id": "asr-boundary-router",
                "plugin_name": "ai_stream_router",
                "scope": "proxy",
                "proxy_id": "asr-boundary",
                "enabled": true,
                "config": {
                    "normalize_response_stream": false,
                    "providers": [{
                        "name": "provider",
                        "provider_type": "openai_compatible",
                        "endpoint": format!("http://127.0.0.1:{provider_port}{PROVIDER_PATH}"),
                        "api_key": PROVIDER_KEY,
                        "model_patterns": ["gpt-*"],
                        "allow_plaintext": true,
                        "priority": 1
                    }]
                }
            },
            {
                "id": "asr-boundary-transformer",
                "plugin_name": "request_transformer",
                "scope": "proxy",
                "proxy_id": "asr-boundary",
                "enabled": true,
                "config": { "rules": rules }
            }
        ]
    });
    serde_yaml::to_string(&config).expect("serialize ai_stream_router boundary config")
}

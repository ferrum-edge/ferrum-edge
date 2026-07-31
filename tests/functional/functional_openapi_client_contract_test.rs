//! Backend-observed `openapi_validator` request-contract enforcement across
//! HTTP/1.1, HTTP/2, and HTTP/3.
//!
//! GHSA-896v-jx23-9g6p: the imported client contract must be decided over the
//! ORIGINAL client representation, before a configured `request_transformer`
//! body rule can inject the schema-required property.
//!
//! GHSA-6p78-6x8c-9g9x: buffering and enforcement must not depend on a
//! `Content-Type` the client can simply omit or mismatch, and a nonempty body
//! with no applicable declared media type must fail closed with 415.

use crate::common::TestGateway;
use crate::scaffolding::clients::{GetOptions, Http3Client};
use crate::scaffolding::ports::reserve_port;

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

/// Bounded window for proving a rejected request never reached the backend.
/// Event-driven against the capture notify; not a fixed sleep.
const ABSENCE_PROOF_WINDOW: Duration = Duration::from_secs(1);

/// Minimal upstream reply for an admitted request.
const OK_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

/// Satisfies the imported schema without any gateway help.
const COMPLIANT_BODY: &str = r#"{"id":"order-1","client_attestation":"client-supplied"}"#;
/// Omits the required property that the configured transform would inject.
const UNATTESTED_BODY: &str = r#"{"id":"order-1"}"#;

#[ignore]
#[tokio::test]
async fn openapi_client_contract_precedes_body_transforms_on_h1_h2_h3() {
    let mut harness = ContractHarness::spawn().await;

    for protocol in ["HTTP/1.1", "HTTP/2", "HTTP/3"] {
        // 1. A compliant client body is admitted and reaches the backend, with
        //    the transform's value applied on the backend-visible request only.
        harness.backend.clear();
        let (status, _) = harness
            .post(protocol, Some("application/json"), COMPLIANT_BODY)
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{protocol}: a compliant client body must be admitted"
        );
        let seen = harness
            .wait_for_request(Duration::from_secs(5))
            .await
            .unwrap_or_else(|| panic!("{protocol}: backend never received the admitted request"));
        assert!(
            seen.contains("client_attestation"),
            "{protocol}: backend request should carry the attestation: {seen}"
        );

        // 2. The client omitted the required property. The transform would add
        //    it, but the client contract is decided first and fails closed.
        harness.backend.clear();
        let (status, body) = harness
            .post(protocol, Some("application/json"), UNATTESTED_BODY)
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{protocol}: a transform must not be able to satisfy the client contract"
        );
        assert!(
            body.contains("Request body validation failed"),
            "{protocol}: unexpected rejection body: {body}"
        );
        harness
            .assert_no_request_within("/orders", ABSENCE_PROOF_WINDOW)
            .await
            .unwrap_or_else(|error| panic!("{protocol}: {error}"));

        // 3. A nonempty body with no Content-Type at all cannot vote the
        //    validator out of the request; it fails closed as unsupported media.
        harness.backend.clear();
        let (status, _) = harness.post(protocol, None, UNATTESTED_BODY).await;
        assert_eq!(
            status,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{protocol}: an omitted Content-Type must not bypass the contract"
        );
        harness
            .assert_no_request_within("/orders", ABSENCE_PROOF_WINDOW)
            .await
            .unwrap_or_else(|error| panic!("{protocol}: {error}"));

        // 4. An undeclared media type is refused the same way.
        harness.backend.clear();
        let (status, _) = harness
            .post(protocol, Some("application/cbor"), UNATTESTED_BODY)
            .await;
        assert_eq!(
            status,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{protocol}: an undeclared media type must not bypass the contract"
        );
        harness
            .assert_no_request_within("/orders", ABSENCE_PROOF_WINDOW)
            .await
            .unwrap_or_else(|error| panic!("{protocol}: {error}"));

        // 5. An empty body still fails the declared presence requirement.
        harness.backend.clear();
        let (status, _) = harness.post(protocol, Some("application/json"), "").await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{protocol}: a required body must not be evaded by sending nothing"
        );
        harness
            .assert_no_request_within("/orders", ABSENCE_PROOF_WINDOW)
            .await
            .unwrap_or_else(|error| panic!("{protocol}: {error}"));
    }

    harness.shutdown();
}

/// A `request_required` contract on a body-less method must be enforced
/// identically on every protocol.
///
/// HTTP/1.1 and HTTP/2 keep an empty `GET`/`HEAD`/`OPTIONS` in the zero-copy
/// streaming representation (the transport itself proves end-of-stream), while
/// HTTP/3 collects the same request into an empty buffer. Before the fix the
/// client-contract phase only ran over the buffered representation, so H1/H2
/// forwarded the request to the backend with status 200 while H3 rejected it.
///
/// Each protocol first issues a control `GET /open` that must reach the backend
/// and return 200, so a failed connection, handshake, or gateway startup can
/// never be mistaken for a contract rejection.
#[ignore]
#[tokio::test]
async fn openapi_client_contract_rejects_empty_bodyless_methods_on_h1_h2_h3() {
    let mut harness = ContractHarness::spawn().await;

    for protocol in ["HTTP/1.1", "HTTP/2", "HTTP/3"] {
        // Positive control: the transport works and unmatched paths are
        // forwarded, so a later 400 is a decision and not a setup failure.
        harness.backend.clear();
        let (status, _) = harness.send_empty(protocol, Method::GET, "/open").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{protocol}: control request must reach the backend"
        );
        assert!(
            harness
                .wait_for_backend_path("/open", Duration::from_secs(5))
                .await
                .is_some(),
            "{protocol}: control request must be observed by the backend"
        );

        for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
            harness.backend.clear();
            let (status, _) = harness
                .send_empty(protocol, method.clone(), "/audits")
                .await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{protocol} {method}: an empty body must fail the declared request_required \
                 contract; 200 means the request was forwarded unvalidated"
            );
            // The client did not send `x-post-client-contract-bypass`. If H1/H2
            // skipped the client phase, `before_proxy` would add that header and
            // the later backend-final decision would bypass and forward 200. The
            // empty body itself is not transformed (`apply_body_rules` returns
            // `None` for an empty body), so the asserted 400 plus no backend
            // request proves the client contract ran before `before_proxy` and,
            // transitively, before any final body transform.
            harness
                .assert_no_request_within("/audits", ABSENCE_PROOF_WINDOW)
                .await
                .unwrap_or_else(|error| panic!("{protocol} {method}: {error}"));
        }
    }

    harness.shutdown();
}

struct ContractHarness {
    gateway: TestGateway,
    backend: CapturingBackend,
    https_port: u16,
}

impl ContractHarness {
    async fn spawn() -> Self {
        let backend = CapturingBackend::spawn().await;
        // Keep the capturing backend alive across attempts, but allocate a
        // fresh HTTPS port for every bounded gateway spawn. Retrying the same
        // reserve-then-drop port leaves a sticky-port TOCTOU under parallel CI.
        const MAX_ATTEMPTS: usize = 5;
        let mut last_error = String::new();
        for attempt in 1..=MAX_ATTEMPTS {
            let reservation = match reserve_port().await {
                Ok(reservation) => reservation,
                Err(error) => {
                    last_error = format!("reserve https port: {error}");
                    continue;
                }
            };
            let https_port = reservation.port;
            drop(reservation);

            match TestGateway::builder()
                .mode_file(contract_config(backend.port))
                .log_level("warn")
                .max_attempts(1)
                .env("FERRUM_ENABLE_HTTP3", "true")
                .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
                .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
                .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
                .env("FERRUM_POOL_WARMUP_ENABLED", "false")
                .spawn()
                .await
            {
                Ok(mut gateway) => {
                    if let Err(error) = gateway.wait_for_proxy_port(Duration::from_secs(5)).await {
                        last_error = format!(
                            "attempt {attempt}/{MAX_ATTEMPTS}: proxy port not ready: {error}"
                        );
                        gateway.shutdown();
                        continue;
                    }
                    return Self {
                        gateway,
                        backend,
                        https_port,
                    };
                }
                Err(error) => {
                    // Bound diagnostics only — never echo env values or secrets.
                    last_error =
                        format!("attempt {attempt}/{MAX_ATTEMPTS}: gateway spawn failed: {error}");
                }
            }
        }
        panic!(
            "failed to start openapi client-contract gateway after {MAX_ATTEMPTS} attempts: {last_error}"
        );
    }

    async fn post(
        &self,
        protocol: &str,
        content_type: Option<&str>,
        body: &str,
    ) -> (StatusCode, String) {
        match protocol {
            "HTTP/1.1" => self.post_h1(content_type, body).await,
            "HTTP/2" => self.post_h2(content_type, body).await,
            "HTTP/3" => self.post_h3(content_type, body).await,
            other => panic!("unsupported protocol {other}"),
        }
    }

    async fn post_h1(&self, content_type: Option<&str>, body: &str) -> (StatusCode, String) {
        let client = reqwest::Client::builder()
            .http1_only()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("http1 client");
        let mut request = client
            .post(self.gateway.proxy_url("/orders"))
            .body(body.to_string());
        if let Some(content_type) = content_type {
            request = request.header("content-type", content_type);
        }
        let response = request.send().await.expect("http1 request");
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        (status, text)
    }

    async fn post_h2(&self, content_type: Option<&str>, body: &str) -> (StatusCode, String) {
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
        let uri = format!("http://127.0.0.1:{}/orders", self.gateway.proxy_port);
        let mut builder = Request::builder().method(Method::POST).uri(uri);
        if let Some(content_type) = content_type {
            builder = builder.header("content-type", content_type);
        }
        let request = builder
            .body(Full::<Bytes>::new(Bytes::from(body.to_string())))
            .expect("build h2 request");
        let response = sender.send_request(request).await.expect("send h2 request");
        let status = response.status();
        let collected = response
            .into_body()
            .collect()
            .await
            .expect("collect h2 body")
            .to_bytes();
        drop(sender);
        conn_task.abort();
        (status, String::from_utf8_lossy(&collected).to_string())
    }

    async fn post_h3(&self, content_type: Option<&str>, body: &str) -> (StatusCode, String) {
        let client = Http3Client::insecure().expect("h3 client");
        let url = format!("https://localhost:{}/orders", self.https_port);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let mut options = GetOptions::default()
                .method(Method::POST)
                .body(Bytes::from(body.to_string()));
            if let Some(content_type) = content_type {
                options = options.header("content-type", content_type);
            }
            match client.get_with_options(&url, options).await {
                Ok(response) => return (response.status, response.body_text()),
                Err(_) if std::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => panic!("H3 client-contract request did not complete: {error}"),
            }
        }
    }

    /// Issue a request with no body at all on the requested protocol.
    async fn send_empty(&self, protocol: &str, method: Method, path: &str) -> (StatusCode, String) {
        match protocol {
            "HTTP/1.1" => {
                let client = reqwest::Client::builder()
                    .http1_only()
                    .timeout(Duration::from_secs(5))
                    .build()
                    .expect("http1 client");
                let response = client
                    .request(method, self.gateway.proxy_url(path))
                    .send()
                    .await
                    .expect("http1 request");
                let status = response.status();
                let text = response.text().await.unwrap_or_default();
                (status, text)
            }
            "HTTP/2" => {
                let stream = TcpStream::connect(("127.0.0.1", self.gateway.proxy_port))
                    .await
                    .expect("connect h2c");
                let _ = stream.set_nodelay(true);
                let io = TokioIo::new(stream);
                let (mut sender, conn) =
                    hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
                        .await
                        .expect("h2 handshake");
                let conn_task = tokio::spawn(async move {
                    let _ = conn.await;
                });
                let uri = format!("http://127.0.0.1:{}{path}", self.gateway.proxy_port);
                let request = Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Full::<Bytes>::new(Bytes::new()))
                    .expect("build h2 request");
                let response = sender.send_request(request).await.expect("send h2 request");
                let status = response.status();
                let collected = response
                    .into_body()
                    .collect()
                    .await
                    .expect("collect h2 body")
                    .to_bytes();
                drop(sender);
                conn_task.abort();
                (status, String::from_utf8_lossy(&collected).to_string())
            }
            "HTTP/3" => {
                let client = Http3Client::insecure().expect("h3 client");
                let url = format!("https://localhost:{}{path}", self.https_port);
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                loop {
                    let options = GetOptions::default().method(method.clone());
                    match client.get_with_options(&url, options).await {
                        Ok(response) => return (response.status, response.body_text()),
                        Err(_) if std::time::Instant::now() < deadline => {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                        Err(error) => panic!("H3 bodyless request did not complete: {error}"),
                    }
                }
            }
            other => panic!("unsupported protocol {other}"),
        }
    }

    async fn wait_for_backend_path(&self, path: &str, timeout: Duration) -> Option<String> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            // Arm the notification before scanning so a concurrent push cannot
            // be lost between the scan and a later wait.
            let notified = self.backend.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(request) = self
                .backend
                .requests()
                .into_iter()
                .find(|request| request.contains(path))
            {
                return Some(request);
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::select! {
                _ = notified => {}
                _ = tokio::time::sleep_until(deadline) => {}
            }
        }
    }

    /// Event-driven, bounded proof that no backend request for `path` arrives.
    ///
    /// Requires prior observability (`total_observed() > 0`) and a live accept
    /// loop so an empty capture cannot pass vacuously after a dead backend.
    /// Arms `notified()` before each scan to avoid lost wakeups, then selects
    /// against the remaining deadline.
    async fn assert_no_request_within(&self, path: &str, window: Duration) -> Result<(), String> {
        if self.backend.total_observed() == 0 {
            return Err(format!(
                "cannot prove absence for `{path}`: backend has never been observed alive"
            ));
        }
        if !self.backend.accept_loop_alive() {
            return Err(format!(
                "cannot prove absence for `{path}`: capturing backend accept loop is not alive"
            ));
        }

        let deadline = tokio::time::Instant::now() + window;
        loop {
            let notified = self.backend.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(request) = self
                .backend
                .requests()
                .into_iter()
                .find(|request| request.contains(path))
            {
                return Err(format!(
                    "rejected request must never reach the backend for `{path}`; saw: {}",
                    request.lines().next().unwrap_or(&request)
                ));
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                if !self.backend.accept_loop_alive() {
                    return Err(format!(
                        "absence window for `{path}` ended with a dead backend accept loop"
                    ));
                }
                return Ok(());
            }
            tokio::select! {
                _ = notified => {}
                _ = tokio::time::sleep_until(deadline) => {}
            }
        }
    }

    async fn wait_for_request(&self, timeout: Duration) -> Option<String> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.backend.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(request) = self.backend.requests().into_iter().find(|request| {
                request.starts_with("POST /orders") || request.contains(" /orders ")
            }) {
                return Some(request);
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::select! {
                _ = notified => {}
                _ = tokio::time::sleep_until(deadline) => {}
            }
        }
    }

    fn shutdown(&mut self) {
        self.gateway.shutdown();
        self.backend.abort();
    }
}

fn contract_config(backend_port: u16) -> String {
    let config = serde_json::json!({
        "version": "1",
        "proxies": [{
            "id": "openapi-client-contract",
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
            "pool_enable_http2": false,
            "plugins": [
                {"plugin_config_id": "contract-validator"},
                {"plugin_config_id": "contract-transformer"}
            ]
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [
            {
                "id": "contract-validator",
                "plugin_name": "openapi_validator",
                "scope": "proxy",
                "proxy_id": "openapi-client-contract",
                "enabled": true,
                "config": {
                    "enforcement_mode": "block",
                    "schema_draft": "draft7",
                    "validate_response": false,
                    "fail_on_unknown_operation": false,
                    "bypass": {"header_present": {"x-post-client-contract-bypass": null}},
                    "operations": [
                        {
                            "method": "POST",
                            "path_template": "/orders",
                            "path_regex": "^/orders$",
                            "request_required": true,
                            "request_body": {
                                "content": {
                                    "application/json": {
                                        "type": "object",
                                        "additionalProperties": false,
                                        "required": ["id", "client_attestation"],
                                        "properties": {
                                            "id": {"type": "string"},
                                            "client_attestation": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        },
                        // Body-less methods that the imported document declares a
                        // required request body for. The configured transformer
                        // adds `x-post-client-contract-bypass` in `before_proxy`;
                        // if the client phase were skipped, that header would make
                        // the backend-final validator bypass and forward 200.
                        {
                            "method": "GET",
                            "path_template": "/audits",
                            "path_regex": "^/audits$",
                            "request_required": true,
                            "request_body": {
                                "content": {
                                    "application/json": {
                                        "type": "object",
                                        "required": ["client_attestation"],
                                        "properties": {
                                            "client_attestation": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        },
                        {
                            "method": "HEAD",
                            "path_template": "/audits",
                            "path_regex": "^/audits$",
                            "request_required": true,
                            "request_body": {
                                "content": {
                                    "application/json": {
                                        "type": "object",
                                        "required": ["client_attestation"],
                                        "properties": {
                                            "client_attestation": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        },
                        {
                            "method": "OPTIONS",
                            "path_template": "/audits",
                            "path_regex": "^/audits$",
                            "request_required": true,
                            "request_body": {
                                "content": {
                                    "application/json": {
                                        "type": "object",
                                        "required": ["client_attestation"],
                                        "properties": {
                                            "client_attestation": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        }
                    ]
                }
            },
            {
                "id": "contract-transformer",
                "plugin_name": "request_transformer",
                "scope": "proxy",
                "proxy_id": "openapi-client-contract",
                "enabled": true,
                "config": {
                    "rules": [
                        {
                            "operation": "add",
                            "target": "header",
                            "key": "x-post-client-contract-bypass",
                            "value": "bypass"
                        },
                        {
                            "target": "body",
                            "operation": "add",
                            "key": "client_attestation",
                            "value": "gateway-synthesized"
                        }
                    ]
                }
            }
        ]
    });
    serde_yaml::to_string(&config).expect("serialize client-contract config")
}

/// Captures the complete backend-visible request (head plus `Content-Length`
/// body) so the test can prove a rejected request never reached upstream.
struct CapturingBackend {
    port: u16,
    requests: Arc<Mutex<Vec<String>>>,
    /// Lifetime count of captured requests; `clear()` does not reset this, so
    /// absence proofs can require prior observability.
    total_observed: Arc<AtomicU64>,
    notify: Arc<Notify>,
    handle: Option<JoinHandle<()>>,
}

impl CapturingBackend {
    async fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind capture backend");
        let port = listener.local_addr().expect("local addr").port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let total_observed = Arc::new(AtomicU64::new(0));
        let notify = Arc::new(Notify::new());
        let requests_task = requests.clone();
        let total_task = total_observed.clone();
        let notify_task = notify.clone();
        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut stream, _)) => {
                        let requests = requests_task.clone();
                        let total_observed = total_task.clone();
                        let notify = notify_task.clone();
                        tokio::spawn(async move {
                            let Some(request) = read_full_request(&mut stream).await else {
                                return;
                            };
                            requests.lock().expect("requests lock").push(request);
                            total_observed.fetch_add(1, Ordering::Relaxed);
                            notify.notify_waiters();
                            let _ = stream.write_all(OK_RESPONSE).await;
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
            total_observed,
            notify,
            handle: Some(handle),
        }
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("requests lock").clone()
    }

    fn total_observed(&self) -> u64 {
        self.total_observed.load(Ordering::Relaxed)
    }

    fn accept_loop_alive(&self) -> bool {
        self.handle
            .as_ref()
            .is_some_and(|handle| !handle.is_finished())
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

/// Read headers, then exactly `Content-Length` body bytes. Chunked uploads are
/// read best-effort until the terminal chunk marker; the assertions only look
/// for substrings, so a partial trailer read cannot produce a false positive.
async fn read_full_request(stream: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        match stream.read(&mut chunk).await {
            Ok(0) => return None,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break at + 4;
                }
            }
            Err(_) => return None,
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let content_length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    let chunked = head
        .lines()
        .any(|line| line.to_ascii_lowercase().starts_with("transfer-encoding:"));

    while buf.len() < header_end + content_length {
        match stream.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
    if chunked && content_length == 0 {
        // Bounded best-effort drain of a chunked upload.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while !buf.ends_with(b"0\r\n\r\n") && tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(200), stream.read(&mut chunk)).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
                Ok(Err(_)) => break,
            }
        }
    }
    Some(String::from_utf8_lossy(&buf).to_string())
}

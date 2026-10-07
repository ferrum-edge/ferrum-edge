//! Hosted functional matrix for route total deadlines during pre-authentication
//! SOAP body collection (issue #6008, the follow-up to #6024).
//!
//! An identity-establishing `soap_ws_security` instance collects the upload
//! before `authenticate`, so the `mesh_route_dispatch` rule's
//! `request_timeout_ms` is previewed from the request's pinned plugin-cache
//! generation and bounds that collect from request receipt. These tests drive
//! the real binary over real HTTP/1.1, h2c and native HTTP/3 frontend streams
//! with scripted clients that control every chunk's timing, and check:
//!
//! - all three SOAP identity modes (UsernameToken, X.509 signature, SAML);
//! - stalled, trickling and expired-ready uploads;
//! - read/route deadline ordering, and a chunk that is ready when the route
//!   total elapses (late wake: refused, never collected);
//! - `backend_read_timeout_ms: 0` still bounded by the route total, for plain
//!   requests and as gRPC `DEADLINE_EXCEEDED`;
//! - the candidate-max profile for rules that cannot be decided before
//!   authentication, including an untimed sibling;
//! - a config reload during collection keeps the pinned generation's total;
//! - open HTTP/2 DATA without `Content-Length`;
//! - HTTP/3 response-before-`STOP_SENDING` ordering and the release of the
//!   retained-request permit.
//!
//! Every assertion checks the status, that the backend was never reached, and
//! a lower bound on the time to the answer. The client's clock starts before
//! the request leaves, so a receipt-anchored deadline can only fire later than
//! the bound; there are no tight upper bounds.
//!
//! Run:
//! ```bash
//! cargo build --bin ferrum-edge && \
//!   cargo test --test functional_tests soap_preauth_deadline_matrix -- --ignored --nocapture
//! ```

use crate::common::TestGateway;
use crate::scaffolding::clients::{Http3Client, bind_quinn_client_endpoint};
use crate::scaffolding::ports::{reserve_colocated_tcp_udp, reserve_port};

use bytes::{Buf, Bytes};
use http::header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderName, HeaderValue};
use http::{HeaderMap, Method, Request};
use serde_json::{Value, json};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{sleep, sleep_until, timeout};

/// Margin for timer and clock granularity on a lower-bound assertion.
const TIMER_SLACK: Duration = Duration::from_millis(50);
/// Ceiling on any one exchange. A failure guard, never a timing assertion.
const EXCHANGE_LIMIT: Duration = Duration::from_secs(30);
/// A read bound far past every deadline these tests expect to fire.
const LONG_READ_TIMEOUT_MS: u64 = 30_000;
/// The route total most scenarios arm.
const ROUTE_TOTAL_MS: u64 = 1_500;

const SOAP_CONTENT_TYPE: &str = "text/xml; charset=utf-8";
const PASSWORD_TEXT: &str = concat!(
    "http://docs.oasis-open.org/wss/2004/01/",
    "oasis-200401-wss-username-token-profile-1.0#PasswordText"
);
const WSSE_NAMESPACE: &str = concat!(
    "http://docs.oasis-open.org/wss/2004/01/",
    "oasis-200401-wss-wssecurity-secext-1.0.xsd"
);
const ENVELOPE_TAIL: &str = "</id></GetData></soap:Body></soap:Envelope>";

/// A budget that admits exactly one buffered 64 KiB upload at a time.
const ONE_BUFFERED_UPLOAD_FITS: &[(&str, &str)] = &[
    ("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES", "65536"),
    ("FERRUM_REQUEST_BUFFER_FALLBACK_MAX_BYTES", "65536"),
    ("FERRUM_REQUEST_BUFFER_MAX_TOTAL_BYTES", "65536"),
];

fn ms(millis: u64) -> Duration {
    Duration::from_millis(millis)
}

// ---------------------------------------------------------------------------
// SOAP messages
// ---------------------------------------------------------------------------

/// A UsernameToken envelope up to the open `<id>` element of its body.
fn envelope_through_id(password: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         xmlns:wsse=\"{WSSE_NAMESPACE}\">\
         <soap:Header><wsse:Security><wsse:UsernameToken>\
         <wsse:Username>testuser</wsse:Username>\
         <wsse:Password Type=\"{PASSWORD_TEXT}\">{password}</wsse:Password>\
         </wsse:UsernameToken></wsse:Security></soap:Header>\
         <soap:Body><GetData xmlns=\"http://example.com\"><id>"
    )
}

/// The opening of a message whose body never completes.
fn stalled_prefix() -> Bytes {
    Bytes::from(envelope_through_id("testpass"))
}

/// A complete message the UsernameToken policy accepts.
fn valid_envelope() -> Bytes {
    let envelope = envelope_through_id("testpass");
    Bytes::from(format!("{envelope}123{ENVELOPE_TAIL}"))
}

#[derive(Debug, Clone, Copy)]
enum SoapMode {
    UsernameToken,
    X509Signature,
    Saml,
}

/// The RSA certificate the X.509 and SAML policies trust. Their uploads never
/// complete here, so no signature is ever checked against it.
fn trusted_cert_path() -> String {
    format!("{}/tests/certs/server.crt", env!("CARGO_MANIFEST_DIR"))
}

fn soap_plugin_config(mode: SoapMode) -> Value {
    match mode {
        SoapMode::UsernameToken => json!({
            "username_token": {
                "enabled": true,
                "password_type": "PasswordText",
                "credentials": [{"username": "testuser", "password": "testpass"}]
            },
            "timestamp": {"require": false}
        }),
        // `require_signed_timestamp` defaults on, so the timestamp stays
        // required.
        SoapMode::X509Signature => json!({
            "x509_signature": {"enabled": true, "trusted_certs": [trusted_cert_path()]}
        }),
        SoapMode::Saml => json!({
            "saml": {
                "enabled": true,
                "trusted_issuers": ["https://idp.deadline-matrix.example"],
                "trusted_signing_certs": [trusted_cert_path()],
                "audience": "urn:ferrum:soap-deadline-matrix",
                "recipient": "https://gateway.deadline-matrix.example/soap"
            },
            "nonce": {"replay_scope": "process"},
            "timestamp": {"require": false}
        }),
    }
}

// ---------------------------------------------------------------------------
// Gateway configuration
// ---------------------------------------------------------------------------

/// The plugin that collects the upload before the rule is selected.
#[derive(Clone, Copy)]
enum Collector {
    /// `soap_ws_security` in an identity mode: collects before `authenticate`.
    Soap(SoapMode),
    /// `ai_request_guard` + `request_mirror`: collect before `before_proxy`,
    /// for native gRPC uploads.
    GrpcMirror,
}

struct Route {
    id: &'static str,
    listen_path: &'static str,
    read_timeout_ms: u64,
    collector: Collector,
    rules: Vec<Value>,
}

impl Route {
    fn soap(
        id: &'static str,
        listen_path: &'static str,
        mode: SoapMode,
        read_timeout_ms: u64,
        rules: Vec<Value>,
    ) -> Self {
        Self {
            id,
            listen_path,
            read_timeout_ms,
            collector: Collector::Soap(mode),
            rules,
        }
    }

    fn grpc_mirror(
        id: &'static str,
        listen_path: &'static str,
        read_timeout_ms: u64,
        rules: Vec<Value>,
    ) -> Self {
        Self {
            id,
            listen_path,
            read_timeout_ms,
            collector: Collector::GrpcMirror,
            rules,
        }
    }
}

/// A `mesh_route_dispatch` rule whose destination is the proxy's own
/// backend, so only its total deadline matters.
fn rule(backend_port: u16, matcher: Value, total_ms: Option<u64>) -> Value {
    let mut rule = json!({
        "match": matcher,
        "destination": {"backend_host": "127.0.0.1", "backend_port": backend_port}
    });
    if let Some(total_ms) = total_ms {
        rule["request_timeout_ms"] = json!(total_ms);
    }
    rule
}

/// A rule on a gateway-owned identity header. Identity is published only
/// after authentication, so this rule is never decided before the SOAP
/// collect, whatever the client sends.
fn identity_rule(backend_port: u16, total_ms: Option<u64>) -> Value {
    rule(
        backend_port,
        json!({"headers": {"x-consumer-username": "alice"}}),
        total_ms,
    )
}

fn plugin_config(id: String, proxy_id: &str, plugin_name: &str, config: Value) -> Value {
    json!({
        "id": id,
        "plugin_name": plugin_name,
        "scope": "proxy",
        "proxy_id": proxy_id,
        "enabled": true,
        "config": config,
    })
}

fn gateway_yaml(backend_port: u16, routes: &[Route]) -> String {
    let mut proxies = Vec::new();
    let mut plugin_configs = Vec::new();
    for route in routes {
        let mut ids = Vec::new();
        match route.collector {
            Collector::Soap(mode) => {
                let id = format!("{}-soap", route.id);
                plugin_configs.push(plugin_config(
                    id.clone(),
                    route.id,
                    "soap_ws_security",
                    soap_plugin_config(mode),
                ));
                ids.push(id);
            }
            Collector::GrpcMirror => {
                let guard = format!("{}-guard", route.id);
                plugin_configs.push(plugin_config(
                    guard.clone(),
                    route.id,
                    "ai_request_guard",
                    json!({"max_messages": 100}),
                ));
                let mirror = format!("{}-mirror", route.id);
                plugin_configs.push(plugin_config(
                    mirror.clone(),
                    route.id,
                    "request_mirror",
                    json!({
                        "mirror_host": "127.0.0.1",
                        "mirror_port": 9,
                        "mirror_protocol": "http",
                        "mirror_request_body": true,
                        "percentage": 100,
                    }),
                ));
                ids.push(guard);
                ids.push(mirror);
            }
        }
        let dispatch = format!("{}-dispatch", route.id);
        plugin_configs.push(plugin_config(
            dispatch.clone(),
            route.id,
            "mesh_route_dispatch",
            json!({"rules": route.rules}),
        ));
        ids.push(dispatch);
        let plugins: Vec<Value> = ids
            .iter()
            .map(|id| json!({"plugin_config_id": id}))
            .collect();
        proxies.push(json!({
            "id": route.id,
            "listen_path": route.listen_path,
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": route.read_timeout_ms,
            "backend_write_timeout_ms": 2000,
            "plugins": plugins,
        }));
    }
    let config = json!({
        "version": "1",
        "proxies": proxies,
        "consumers": [],
        "upstreams": [],
        "plugin_configs": plugin_configs,
    });
    serde_yaml::to_string(&config).expect("serialize gateway config")
}

/// One SOAP route on `/soap` under one rule with `total_ms`.
fn single_soap_route_yaml(
    backend_port: u16,
    mode: SoapMode,
    read_timeout_ms: u64,
    total_ms: u64,
) -> String {
    gateway_yaml(
        backend_port,
        &[Route::soap(
            "soap",
            "/soap",
            mode,
            read_timeout_ms,
            vec![rule(backend_port, json!({}), Some(total_ms))],
        )],
    )
}

/// The UsernameToken route on `/soap` with the long read bound and `total_ms`.
fn soap_yaml(backend_port: u16, total_ms: u64) -> String {
    single_soap_route_yaml(
        backend_port,
        SoapMode::UsernameToken,
        LONG_READ_TIMEOUT_MS,
        total_ms,
    )
}

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

/// A plaintext HTTP/1.1 backend that answers every client request `200 ok`
/// and counts them.
struct CountingBackend {
    port: u16,
    hits: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl CountingBackend {
    async fn spawn() -> Self {
        let reservation = reserve_port().await.expect("reserve backend port");
        let port = reservation.port;
        let listener = reservation.into_listener();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve_counted_connection(stream, Arc::clone(&counter)));
            }
        });
        Self { port, hits, task }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    /// No request reached the backend, even after a settle window.
    async fn assert_untouched(&self, context: &str) {
        sleep(ms(250)).await;
        assert_eq!(
            self.hits(),
            0,
            "{context}: a refused upload must never reach the backend"
        );
    }
}

impl Drop for CountingBackend {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn fill(stream: &mut TcpStream, buf: &mut Vec<u8>) -> bool {
    let mut chunk = [0u8; 4096];
    match stream.read(&mut chunk).await {
        Ok(0) | Err(_) => false,
        Ok(read) => {
            buf.extend_from_slice(&chunk[..read]);
            true
        }
    }
}

async fn serve_counted_connection(mut stream: TcpStream, hits: Arc<AtomicUsize>) {
    let mut buf = Vec::new();
    loop {
        let head_end = loop {
            if let Some(index) = find(&buf, b"\r\n\r\n") {
                break index + 4;
            }
            if !fill(&mut stream, &mut buf).await {
                return;
            }
        };
        // The file-mode capability probe opens with the h2c preface, whose
        // `PRI * HTTP/2.0` line also ends in a blank line. It is no request.
        if buf.starts_with(b"PRI * HTTP/2.0") {
            return;
        }
        // Every upload under test is a POST; anything else is a probe.
        if buf.starts_with(b"POST ") {
            hits.fetch_add(1, Ordering::SeqCst);
        }
        let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
        let body_end = if head.contains("transfer-encoding: chunked") {
            loop {
                if let Some(index) = find(&buf[head_end..], b"0\r\n\r\n") {
                    break head_end + index + 5;
                }
                if !fill(&mut stream, &mut buf).await {
                    return;
                }
            }
        } else {
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            while buf.len() < head_end + length {
                if !fill(&mut stream, &mut buf).await {
                    return;
                }
            }
            head_end + length
        };
        buf.drain(..body_end);
        if stream.write_all(BACKEND_RESPONSE).await.is_err() {
            return;
        }
    }
}

const BACKEND_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 2\r\n\r\nok";

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

// ---------------------------------------------------------------------------
// Gateway
// ---------------------------------------------------------------------------

struct MatrixGateway {
    gateway: TestGateway,
    https_port: u16,
}

impl MatrixGateway {
    /// Spawn the binary in file mode with plaintext HTTP/1.1 + h2c on the
    /// proxy port and native HTTP/3 on a fresh colocated port.
    async fn spawn(yaml: String, extra_env: &[(&str, &str)]) -> Self {
        const MAX_ATTEMPTS: usize = 5;
        let mut last_error = String::new();
        for _ in 0..MAX_ATTEMPTS {
            // The child binds the HTTPS port itself, so the reservation is
            // released for it; a lost race retries with a fresh pair.
            let (https_tcp, https_udp) = reserve_colocated_tcp_udp()
                .await
                .expect("reserve colocated H3 port");
            let https_port = https_tcp.drop_and_take_port();
            assert_eq!(https_port, https_udp.drop_and_take_port());
            let mut builder = TestGateway::builder()
                .mode_file(yaml.clone())
                .log_level("info")
                .capture_output()
                .max_attempts(1)
                .env("FERRUM_ENABLE_HTTP3", "true")
                .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
                .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
                .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
                .env("FERRUM_POOL_WARMUP_ENABLED", "false");
            for (key, value) in extra_env {
                builder = builder.env(*key, *value);
            }
            match builder.spawn().await {
                Ok(gateway) => {
                    gateway
                        .wait_for_proxy_port(Duration::from_secs(10))
                        .await
                        .expect("proxy listener ready");
                    wait_for_h3_listener(https_port).await;
                    return Self {
                        gateway,
                        https_port,
                    };
                }
                Err(error) => last_error = error.to_string(),
            }
        }
        panic!("failed to spawn the matrix gateway after {MAX_ATTEMPTS} attempts: {last_error}");
    }

    fn proxy_port(&self) -> u16 {
        self.gateway.proxy_port
    }

    /// One upload on its own connection. The clock starts before connecting.
    async fn upload(&self, proto: Proto, upload: &Upload) -> Outcome {
        let started = Instant::now();
        match proto {
            Proto::H1 => h1_upload(self.proxy_port(), upload, started, None).await,
            Proto::H2 => {
                H2Connection::open(self.proxy_port())
                    .await
                    .upload(upload, started)
                    .await
            }
            Proto::H3 => {
                H3Session::open(self.https_port)
                    .await
                    .upload(upload, started)
                    .await
            }
        }
    }

    /// The same upload on HTTP/1.1, HTTP/2 and HTTP/3 at once.
    async fn upload_on_every_protocol(&self, upload: &Upload) -> [Outcome; 3] {
        let (h1, h2, h3) = tokio::join!(
            self.upload(Proto::H1, upload),
            self.upload(Proto::H2, upload),
            self.upload(Proto::H3, upload),
        );
        [h1, h2, h3]
    }
}

/// Wait until the QUIC listener answers, on a path no proxy routes, so the
/// probe takes no request-buffer charge.
async fn wait_for_h3_listener(https_port: u16) {
    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/not-routed");
    let deadline = Instant::now() + Duration::from_secs(15);
    while client.get(&url).await.is_err() {
        assert!(Instant::now() < deadline, "the H3 listener never answered");
        sleep(ms(100)).await;
    }
}

// ---------------------------------------------------------------------------
// Scripted uploads
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Proto {
    H1,
    H2,
    H3,
}

/// When each body chunk leaves the client.
#[derive(Clone)]
struct BodyScript {
    /// Sent right after the request head.
    prefix: Bytes,
    /// Then this chunk at this interval.
    trickle: Option<(Bytes, Duration)>,
    /// At this offset from the start of the exchange, these bytes and the end
    /// of the body. `None` never ends the body.
    end: Option<(Duration, Bytes)>,
}

impl BodyScript {
    fn stalled(prefix: Bytes) -> Self {
        Self {
            prefix,
            trickle: None,
            end: None,
        }
    }

    fn complete(body: Bytes) -> Self {
        Self {
            prefix: body,
            trickle: None,
            end: Some((Duration::ZERO, Bytes::new())),
        }
    }

    fn trickle(prefix: Bytes, chunk: &'static [u8], every: Duration) -> Self {
        Self {
            prefix,
            trickle: Some((Bytes::from_static(chunk), every)),
            end: None,
        }
    }

    fn ending_at(mut self, at: Duration, tail: Bytes) -> Self {
        self.end = Some((at, tail));
        self
    }

    /// The whole body, when it is all ready with the request head.
    fn complete_body(&self) -> Option<Bytes> {
        match (&self.trickle, &self.end) {
            (None, Some((at, tail))) if at.is_zero() => {
                let mut body = Vec::with_capacity(self.prefix.len() + tail.len());
                body.extend_from_slice(&self.prefix);
                body.extend_from_slice(tail);
                Some(Bytes::from(body))
            }
            _ => None,
        }
    }

    /// Emit `(bytes, end_of_body)` items on schedule until the body ends or
    /// the receiver is dropped.
    fn schedule(self, started: Instant) -> mpsc::Receiver<(Bytes, bool)> {
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(async move {
            let base = tokio::time::Instant::from_std(started);
            if tx.send((self.prefix, false)).await.is_err() {
                return;
            }
            let end_at = self.end.as_ref().map(|(at, _)| base + *at);
            if let Some((chunk, every)) = self.trickle {
                let mut next = tokio::time::Instant::now() + every;
                while end_at.is_none_or(|end_at| next < end_at) {
                    tokio::select! {
                        () = sleep_until(next) => {}
                        () = tx.closed() => return,
                    }
                    if tx.send((chunk.clone(), false)).await.is_err() {
                        return;
                    }
                    next += every;
                }
            }
            match (end_at, self.end) {
                (Some(end_at), Some((_, tail))) => {
                    tokio::select! {
                        () = sleep_until(end_at) => {}
                        () = tx.closed() => return,
                    }
                    let _ = tx.send((tail, true)).await;
                }
                _ => tx.closed().await,
            }
        });
        rx
    }
}

#[derive(Clone)]
struct Upload {
    path: &'static str,
    content_type: &'static str,
    headers: Vec<(&'static str, &'static str)>,
    script: BodyScript,
}

impl Upload {
    fn soap(path: &'static str, script: BodyScript) -> Self {
        Self {
            path,
            content_type: SOAP_CONTENT_TYPE,
            headers: Vec::new(),
            script,
        }
    }

    /// A native gRPC upload whose one message never completes.
    fn stalled_grpc(path: &'static str) -> Self {
        Self {
            path,
            content_type: "application/grpc",
            headers: Vec::new(),
            script: BodyScript::stalled(Bytes::from_static(&[0, 0, 0, 0, 64, 1, 2, 3, 4])),
        }
    }

    fn header(mut self, name: &'static str, value: &'static str) -> Self {
        self.headers.push((name, value));
        self
    }
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let value = headers.get(name)?;
    value.to_str().ok()
}

#[derive(Debug)]
struct Outcome {
    proto: Proto,
    status: u16,
    headers: HeaderMap,
    body: Bytes,
    trailers: Option<HeaderMap>,
    /// From just before the client connected to the response head.
    elapsed: Duration,
}

impl Outcome {
    fn header(&self, name: &str) -> Option<&str> {
        header_str(&self.headers, name)
    }

    /// `grpc-status`, from a trailers-only head or from the trailers.
    fn grpc_status(&self) -> Option<&str> {
        if let Some(status) = self.header("grpc-status") {
            return Some(status);
        }
        header_str(self.trailers.as_ref()?, "grpc-status")
    }

    fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

// ---- HTTP/1.1: raw socket, chunked unless the body is complete ----

async fn h1_upload(
    port: u16,
    upload: &Upload,
    started: Instant,
    continued: Option<oneshot::Sender<()>>,
) -> Outcome {
    let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .expect("connect the HTTP/1.1 frontend");
    let (mut reader, mut writer) = stream.into_split();
    let complete = upload.script.complete_body();
    let mut head = format!(
        "POST {} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: {}\r\n",
        upload.path,
        upload.content_type
    );
    for (name, value) in &upload.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    match &complete {
        Some(body) => head.push_str(&format!("Content-Length: {}\r\n", body.len())),
        None => head.push_str("Transfer-Encoding: chunked\r\n"),
    }
    let expect_continue = continued.is_some();
    if expect_continue {
        head.push_str("Expect: 100-continue\r\n");
    }
    head.push_str("\r\n");

    let (interim_tx, interim_rx) = oneshot::channel::<()>();
    let script = upload.script.clone();
    let writer_task = tokio::spawn(async move {
        if writer.write_all(head.as_bytes()).await.is_err() {
            return;
        }
        if expect_continue {
            // Like a real client, send nothing until the interim response.
            // Hyper writes it when the collector first polls the body, so it
            // is positive evidence that collection has started.
            if interim_rx.await.is_err() {
                return;
            }
            if let Some(continued) = continued {
                let _ = continued.send(());
            }
        }
        match complete {
            Some(body) => {
                let _ = writer.write_all(&body).await;
            }
            None => write_chunked(&mut writer, script.schedule(started)).await,
        }
        // Hold the write half open: a half-close could end the exchange
        // before the response is read.
        std::future::pending::<()>().await;
    });

    let interim = expect_continue.then_some(interim_tx);
    let response = timeout(EXCHANGE_LIMIT, read_h1_response(&mut reader, interim))
        .await
        .expect("HTTP/1.1 response in time")
        .expect("HTTP/1.1 response");
    let elapsed = started.elapsed();
    writer_task.abort();
    Outcome {
        proto: Proto::H1,
        status: response.status,
        headers: response.headers,
        body: response.body,
        trailers: None,
        elapsed,
    }
}

async fn write_chunked(writer: &mut OwnedWriteHalf, mut items: mpsc::Receiver<(Bytes, bool)>) {
    while let Some((data, end)) = items.recv().await {
        let mut frame = Vec::with_capacity(data.len() + 16);
        if !data.is_empty() {
            frame.extend_from_slice(format!("{:x}\r\n", data.len()).as_bytes());
            frame.extend_from_slice(&data);
            frame.extend_from_slice(b"\r\n");
        }
        if end {
            frame.extend_from_slice(b"0\r\n\r\n");
        }
        if writer.write_all(&frame).await.is_err() || end {
            return;
        }
    }
}

struct H1Response {
    status: u16,
    headers: HeaderMap,
    body: Bytes,
}

async fn read_some(reader: &mut OwnedReadHalf, buf: &mut Vec<u8>) -> std::io::Result<usize> {
    let mut chunk = [0u8; 4096];
    let read = reader.read(&mut chunk).await?;
    buf.extend_from_slice(&chunk[..read]);
    Ok(read)
}

/// Read the final response, signalling `interim` on a `1xx`.
async fn read_h1_response(
    reader: &mut OwnedReadHalf,
    mut interim: Option<oneshot::Sender<()>>,
) -> std::io::Result<H1Response> {
    let mut buf = Vec::new();
    loop {
        let head_end = loop {
            if let Some(index) = find(&buf, b"\r\n\r\n") {
                break index + 4;
            }
            if read_some(reader, &mut buf).await? == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed before a response head",
                ));
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
        buf.drain(..head_end);
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("malformed status line in {head:?}"),
                )
            })?;
        if (100..200).contains(&status) {
            if let Some(interim) = interim.take() {
                let _ = interim.send(());
            }
            continue;
        }
        let mut headers = HeaderMap::new();
        for line in lines {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.trim().as_bytes()),
                HeaderValue::from_str(value.trim()),
            ) {
                headers.append(name, value);
            }
        }
        let content_length = headers
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok());
        // The head is authoritative. A close or reset after it can only
        // truncate the body that follows.
        loop {
            let complete = match content_length {
                Some(length) => buf.len() >= length,
                None => find(&buf, b"0\r\n\r\n").is_some(),
            };
            if complete {
                break;
            }
            match timeout(Duration::from_secs(5), read_some(reader, &mut buf)).await {
                Ok(Ok(read)) if read > 0 => {}
                _ => break,
            }
        }
        if let Some(length) = content_length {
            buf.truncate(length);
        }
        return Ok(H1Response {
            status,
            headers,
            body: Bytes::from(buf),
        });
    }
}

// ---- HTTP/2: h2c prior knowledge; DATA frames carry no Content-Length ----

struct H2Connection {
    sender: h2::client::SendRequest<Bytes>,
    port: u16,
    driver: JoinHandle<()>,
}

impl H2Connection {
    async fn open(port: u16) -> Self {
        let tcp = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .expect("connect the h2c frontend");
        let (sender, connection) = h2::client::handshake(tcp).await.expect("h2c handshake");
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        Self {
            sender,
            port,
            driver,
        }
    }

    async fn upload(&self, upload: &Upload, started: Instant) -> Outcome {
        let mut sender = timeout(EXCHANGE_LIMIT, self.sender.clone().ready())
            .await
            .expect("h2 stream slot in time")
            .expect("h2 stream slot");
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(format!("http://127.0.0.1:{}{}", self.port, upload.path))
            .header(CONTENT_TYPE, upload.content_type);
        for (name, value) in &upload.headers {
            builder = builder.header(*name, *value);
        }
        let request = builder.body(()).expect("h2 request");
        let (response, body_tx) = sender
            .send_request(request, false)
            .expect("send the h2 request head");
        let writer = spawn_h2_writer(body_tx, upload.script.clone(), started);
        let response = timeout(EXCHANGE_LIMIT, response)
            .await
            .expect("h2 response head in time")
            .expect("h2 response head");
        let elapsed = started.elapsed();
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let mut recv = response.into_body();
        let mut body = Vec::new();
        while let Ok(Some(Ok(chunk))) = timeout(Duration::from_secs(5), recv.data()).await {
            let _ = recv.flow_control().release_capacity(chunk.len());
            body.extend_from_slice(&chunk);
        }
        let trailers = timeout(Duration::from_secs(2), recv.trailers())
            .await
            .ok()
            .and_then(Result::ok)
            .flatten();
        writer.abort();
        Outcome {
            proto: Proto::H2,
            status,
            headers,
            body: Bytes::from(body),
            trailers,
            elapsed,
        }
    }
}

impl Drop for H2Connection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

fn spawn_h2_writer(
    mut body_tx: h2::SendStream<Bytes>,
    script: BodyScript,
    started: Instant,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Some(body) = script.complete_body() {
            let _ = body_tx.send_data(body, true);
        } else {
            let mut items = script.schedule(started);
            while let Some((data, end)) = items.recv().await {
                if body_tx.send_data(data, end).is_err() || end {
                    break;
                }
            }
        }
        // Hold the stream until aborted, so this side never resets it.
        std::future::pending::<()>().await;
    })
}

// ---- HTTP/3: native QUIC streams with independently driven halves ----

type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type H3ClientStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type H3SendHalf = h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type H3RecvHalf = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;

#[derive(Debug)]
struct DangerAcceptAny;

impl rustls::client::danger::ServerCertVerifier for DangerAcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

struct H3Session {
    send_request: H3SendRequest,
    driver: JoinHandle<()>,
    endpoint: quinn::Endpoint,
    https_port: u16,
}

impl H3Session {
    async fn open(https_port: u16) -> Self {
        let provider = rustls::crypto::ring::default_provider();
        let mut client_tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("tls 1.3")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(DangerAcceptAny))
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls)
            .map_err(|error| error.to_string())
            .expect("quic config");
        let mut endpoint = bind_quinn_client_endpoint(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("client endpoint");
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_config)));
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, https_port));
        let connecting = endpoint.connect(addr, "localhost").expect("connect");
        let connection = timeout(Duration::from_secs(10), connecting)
            .await
            .expect("QUIC handshake in time")
            .expect("QUIC handshake");
        let (mut driver, send_request) = h3::client::new(h3_quinn::Connection::new(connection))
            .await
            .expect("h3 client");
        let driver = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        Self {
            send_request,
            driver,
            endpoint,
            https_port,
        }
    }

    async fn open_stream(&mut self, upload: &Upload) -> H3ClientStream {
        let url = format!("https://127.0.0.1:{}{}", self.https_port, upload.path);
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(url)
            .header(CONTENT_TYPE, upload.content_type);
        for (name, value) in &upload.headers {
            builder = builder.header(*name, *value);
        }
        let request = builder.body(()).expect("h3 request");
        timeout(EXCHANGE_LIMIT, self.send_request.send_request(request))
            .await
            .expect("h3 request stream in time")
            .expect("open the h3 request stream")
    }

    async fn upload(&mut self, upload: &Upload, started: Instant) -> Outcome {
        let (send, mut recv) = self.open_stream(upload).await.split();
        let (writer, _stopped) = spawn_h3_writer(send, upload.script.clone(), started);
        let head = timeout(EXCHANGE_LIMIT, recv.recv_response())
            .await
            .expect("h3 response head in time")
            .expect("h3 response head");
        let elapsed = started.elapsed();
        let (body, trailers) = read_h3_body(&mut recv).await;
        writer.abort();
        Outcome {
            proto: Proto::H3,
            status: head.status().as_u16(),
            headers: head.headers().clone(),
            body,
            trailers,
            elapsed,
        }
    }
}

impl Drop for H3Session {
    fn drop(&mut self) {
        self.driver.abort();
        self.endpoint.close(0u32.into(), b"done");
    }
}

/// How the gateway ended an HTTP/3 upload direction.
struct UploadStopped {
    at: Instant,
    error: h3::error::StreamError,
}

/// Drive `script` on an HTTP/3 request's send half. Reports the error that
/// ended the upload, then holds the send half until aborted.
fn spawn_h3_writer(
    mut send: H3SendHalf,
    script: BodyScript,
    started: Instant,
) -> (JoinHandle<()>, oneshot::Receiver<UploadStopped>) {
    let (stopped_tx, stopped_rx) = oneshot::channel();
    let writer = tokio::spawn(async move {
        if let Err(error) = drive_h3_upload(&mut send, script, started).await {
            let _ = stopped_tx.send(UploadStopped {
                at: Instant::now(),
                error,
            });
        }
        std::future::pending::<()>().await;
    });
    (writer, stopped_rx)
}

async fn drive_h3_upload(
    send: &mut H3SendHalf,
    script: BodyScript,
    started: Instant,
) -> Result<(), h3::error::StreamError> {
    if let Some(body) = script.complete_body() {
        send.send_data(body).await?;
        return send.finish().await;
    }
    let mut items = script.schedule(started);
    while let Some((data, end)) = items.recv().await {
        if !data.is_empty() {
            send.send_data(data).await?;
        }
        if end {
            return send.finish().await;
        }
    }
    Ok(())
}

async fn read_h3_body(recv: &mut H3RecvHalf) -> (Bytes, Option<HeaderMap>) {
    let mut body = Vec::new();
    while let Ok(Ok(Some(mut chunk))) = timeout(Duration::from_secs(5), recv.recv_data()).await {
        while chunk.has_remaining() {
            let piece = chunk.chunk().to_vec();
            body.extend_from_slice(&piece);
            chunk.advance(piece.len());
        }
    }
    let trailers = timeout(Duration::from_secs(2), recv.recv_trailers())
        .await
        .ok()
        .and_then(Result::ok)
        .flatten();
    (Bytes::from(body), trailers)
}

// ---------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------

fn assert_not_before(outcome: &Outcome, bound: Duration, context: &str) {
    assert!(
        outcome.elapsed + TIMER_SLACK >= bound,
        "{context} on {:?}: answered after {:?}, before the {bound:?} bound could fire",
        outcome.proto,
        outcome.elapsed
    );
}

/// The early route-timeout `504`: health-neutral `request_timeout`, because no
/// backend held the request, and never before the total elapsed.
fn assert_route_timeout(outcome: &Outcome, total: Duration, context: &str) {
    assert_eq!(
        outcome.status, 504,
        "{context} on {:?}: the route total must end the collect, got {outcome:?}",
        outcome.proto
    );
    assert_eq!(
        outcome.header("x-gateway-error"),
        Some("request_timeout"),
        "{context} on {:?}: no backend held the request, got {outcome:?}",
        outcome.proto
    );
    assert!(
        outcome.body_text().contains("Request timeout"),
        "{context} on {:?}: route-timeout body, got {outcome:?}",
        outcome.proto
    );
    assert_not_before(outcome, total, context);
}

/// The operator whole-upload bound's `408`, never before it elapsed.
fn assert_read_timeout(outcome: &Outcome, read_timeout: Duration, context: &str) {
    assert_eq!(
        outcome.status, 408,
        "{context} on {:?}: the read bound must end the collect, got {outcome:?}",
        outcome.proto
    );
    assert_not_before(outcome, read_timeout, context);
}

/// Trailers-only `DEADLINE_EXCEEDED`, never before the total elapsed.
fn assert_grpc_deadline(outcome: &Outcome, total: Duration, context: &str) {
    assert_eq!(
        outcome.status, 200,
        "{context} on {:?}: gRPC rejections ride HTTP 200, got {outcome:?}",
        outcome.proto
    );
    assert_eq!(
        outcome.grpc_status(),
        Some("4"),
        "{context} on {:?}: the folded route total ends in DEADLINE_EXCEEDED, got {outcome:?}",
        outcome.proto
    );
    assert_not_before(outcome, total, context);
}

// ---------------------------------------------------------------------------
// SOAP identity modes
// ---------------------------------------------------------------------------

async fn assert_stalled_identity_upload_ends_at_route_total(mode: SoapMode) {
    let backend = CountingBackend::spawn().await;
    let gateway = MatrixGateway::spawn(
        single_soap_route_yaml(backend.port, mode, LONG_READ_TIMEOUT_MS, ROUTE_TOTAL_MS),
        &[],
    )
    .await;
    let upload = Upload::soap("/soap/op", BodyScript::stalled(stalled_prefix()));
    let context = format!("stalled {mode:?} upload");
    for outcome in gateway.upload_on_every_protocol(&upload).await {
        assert_route_timeout(&outcome, ms(ROUTE_TOTAL_MS), &context);
    }
    backend.assert_untouched(&context).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn username_token_stalled_upload_ends_at_the_route_total_on_h1_h2_h3() {
    assert_stalled_identity_upload_ends_at_route_total(SoapMode::UsernameToken).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn x509_signature_stalled_upload_ends_at_the_route_total_on_h1_h2_h3() {
    assert_stalled_identity_upload_ends_at_route_total(SoapMode::X509Signature).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn saml_stalled_upload_ends_at_the_route_total_on_h1_h2_h3() {
    assert_stalled_identity_upload_ends_at_route_total(SoapMode::Saml).await;
}

// ---------------------------------------------------------------------------
// Trickling, late-wake and expired-ready uploads
// ---------------------------------------------------------------------------

/// A body that keeps making progress is still cut at the route total: the
/// bound is absolute from receipt, not an idle timer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn a_trickling_upload_is_cut_at_the_route_total_on_h1_h2_h3() {
    let backend = CountingBackend::spawn().await;
    let gateway = MatrixGateway::spawn(soap_yaml(backend.port, ROUTE_TOTAL_MS), &[]).await;
    let upload = Upload::soap(
        "/soap/op",
        BodyScript::trickle(stalled_prefix(), b"1", ms(100)),
    );
    for outcome in gateway.upload_on_every_protocol(&upload).await {
        assert_route_timeout(&outcome, ms(ROUTE_TOTAL_MS), "trickling upload");
    }
    backend.assert_untouched("trickling upload").await;
}

/// Late wake: a chunk lands every 5 ms across the route total, so one is
/// ready whenever the deadline wakes the collector, and the body only ends
/// 1.5 s later. The collector must refuse before it polls a ready chunk. The
/// message carries a wrong password, so a collector that kept reading would
/// have completed the body and answered the SOAP `401` instead of the `504`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn a_chunk_ready_when_the_route_total_elapses_is_refused_not_collected() {
    let backend = CountingBackend::spawn().await;
    let gateway = MatrixGateway::spawn(soap_yaml(backend.port, ROUTE_TOTAL_MS), &[]).await;
    let script = BodyScript::trickle(
        Bytes::from(envelope_through_id("wrongpass")),
        b"1111111111111111",
        ms(5),
    )
    .ending_at(
        ms(ROUTE_TOTAL_MS + 1_500),
        Bytes::from_static(ENVELOPE_TAIL.as_bytes()),
    );
    let upload = Upload::soap("/soap/op", script);
    for outcome in gateway.upload_on_every_protocol(&upload).await {
        assert_route_timeout(&outcome, ms(ROUTE_TOTAL_MS), "late-wake upload");
    }
    backend.assert_untouched("late-wake upload").await;
}

/// Expired-ready: the whole valid body is ready with the request head, under
/// a 1 ms total that has elapsed by the time anything can act on it. Whether
/// the collector refuses before polling or a later stage refuses before
/// dispatch, the answer is the route-timeout `504` and no backend is dialed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn an_upload_ready_at_receipt_under_an_elapsed_total_never_reaches_the_backend() {
    let backend = CountingBackend::spawn().await;
    let gateway = MatrixGateway::spawn(soap_yaml(backend.port, 1), &[]).await;
    let upload = Upload::soap("/soap/op", BodyScript::complete(valid_envelope()));
    for outcome in gateway.upload_on_every_protocol(&upload).await {
        assert_route_timeout(&outcome, ms(1), "expired-ready upload");
    }
    backend.assert_untouched("expired-ready upload").await;
}

// ---------------------------------------------------------------------------
// Read/route ordering and a disabled read bound
// ---------------------------------------------------------------------------

/// The earlier of the read bound and the route total ends the collect, with
/// that owner's status: `408` when the read bound fires first, `504` when the
/// route total does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn the_earlier_of_the_read_bound_and_the_route_total_ends_the_collect() {
    const EARLY_MS: u64 = 1_200;
    const LATE_MS: u64 = 6_000;
    let backend = CountingBackend::spawn().await;
    let port = backend.port;
    let yaml = gateway_yaml(
        port,
        &[
            Route::soap(
                "read-first",
                "/read-first",
                SoapMode::UsernameToken,
                EARLY_MS,
                vec![rule(port, json!({}), Some(LATE_MS))],
            ),
            Route::soap(
                "total-first",
                "/total-first",
                SoapMode::UsernameToken,
                LATE_MS,
                vec![rule(port, json!({}), Some(EARLY_MS))],
            ),
        ],
    );
    let gateway = MatrixGateway::spawn(yaml, &[]).await;
    let read_first = Upload::soap("/read-first/op", BodyScript::stalled(stalled_prefix()));
    let total_first = Upload::soap("/total-first/op", BodyScript::stalled(stalled_prefix()));
    let (read_outcomes, total_outcomes) = tokio::join!(
        gateway.upload_on_every_protocol(&read_first),
        gateway.upload_on_every_protocol(&total_first),
    );
    for outcome in read_outcomes {
        assert_read_timeout(&outcome, ms(EARLY_MS), "read bound before the route total");
    }
    for outcome in total_outcomes {
        assert_route_timeout(&outcome, ms(EARLY_MS), "route total before the read bound");
    }
    backend.assert_untouched("read/route ordering").await;
}

/// `backend_read_timeout_ms: 0` disables the operator bound, but the route
/// total still ends the collect: a plain upload with the `504`, and a native
/// gRPC upload with the total folded into `DEADLINE_EXCEEDED`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn a_disabled_read_bound_is_still_bounded_by_the_route_total() {
    let backend = CountingBackend::spawn().await;
    let port = backend.port;
    let yaml = gateway_yaml(
        port,
        &[
            Route::soap(
                "soap-no-read",
                "/soap-no-read",
                SoapMode::UsernameToken,
                0,
                vec![rule(port, json!({}), Some(ROUTE_TOTAL_MS))],
            ),
            Route::grpc_mirror(
                "grpc-no-read",
                "/grpc-no-read",
                0,
                vec![rule(port, json!({}), Some(ROUTE_TOTAL_MS))],
            ),
        ],
    );
    let gateway = MatrixGateway::spawn(yaml, &[]).await;
    let soap = Upload::soap("/soap-no-read/op", BodyScript::stalled(stalled_prefix()));
    let grpc = Upload::stalled_grpc("/grpc-no-read/pkg.Service/Call");
    let (soap_outcomes, grpc_h2, grpc_h3) = tokio::join!(
        gateway.upload_on_every_protocol(&soap),
        gateway.upload(Proto::H2, &grpc),
        gateway.upload(Proto::H3, &grpc),
    );
    for outcome in soap_outcomes {
        assert_route_timeout(&outcome, ms(ROUTE_TOTAL_MS), "read bound 0, SOAP upload");
    }
    for outcome in [grpc_h2, grpc_h3] {
        assert_grpc_deadline(&outcome, ms(ROUTE_TOTAL_MS), "read bound 0, gRPC upload");
    }
    backend.assert_untouched("disabled read bound").await;
}

// ---------------------------------------------------------------------------
// Candidate-max profile
// ---------------------------------------------------------------------------

/// A rule on `x-consumer-username` cannot be decided before authentication,
/// so the early bound is the LARGEST total among the rules that could still
/// be selected. A client that sends the header itself cannot select the
/// shorter total.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn undecided_rules_bound_the_collect_at_the_largest_candidate_total() {
    const SHORT_MS: u64 = 600;
    const LONG_MS: u64 = 2_500;
    let backend = CountingBackend::spawn().await;
    let port = backend.port;
    let yaml = gateway_yaml(
        port,
        &[Route::soap(
            "candidates",
            "/candidates",
            SoapMode::UsernameToken,
            LONG_READ_TIMEOUT_MS,
            vec![
                identity_rule(port, Some(SHORT_MS)),
                rule(port, json!({}), Some(LONG_MS)),
            ],
        )],
    );
    let gateway = MatrixGateway::spawn(yaml, &[]).await;
    let upload = Upload::soap("/candidates/op", BodyScript::stalled(stalled_prefix()))
        .header("x-consumer-username", "alice");
    for outcome in gateway.upload_on_every_protocol(&upload).await {
        assert_route_timeout(&outcome, ms(LONG_MS), "candidate-max bound");
    }
    backend.assert_untouched("candidate-max bound").await;
}

/// If any candidate is untimed there is no early route bound: the read bound
/// ends the collect with its `408`, never the shorter sibling's `504`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn an_untimed_candidate_leaves_only_the_read_bound() {
    const SIBLING_MS: u64 = 600;
    const READ_MS: u64 = 2_500;
    let backend = CountingBackend::spawn().await;
    let port = backend.port;
    let yaml = gateway_yaml(
        port,
        &[Route::soap(
            "untimed",
            "/untimed",
            SoapMode::UsernameToken,
            READ_MS,
            vec![
                identity_rule(port, Some(SIBLING_MS)),
                rule(port, json!({}), None),
            ],
        )],
    );
    let gateway = MatrixGateway::spawn(yaml, &[]).await;
    let upload = Upload::soap("/untimed/op", BodyScript::stalled(stalled_prefix()))
        .header("x-consumer-username", "alice");
    for outcome in gateway.upload_on_every_protocol(&upload).await {
        assert_read_timeout(&outcome, ms(READ_MS), "untimed candidate");
    }
    backend.assert_untouched("untimed candidate").await;
}

// ---------------------------------------------------------------------------
// Pinned reload
// ---------------------------------------------------------------------------

/// A reload that lands while an upload is being collected does not move that
/// upload's bound: it keeps the total of the generation it was received on.
/// The interim `100 Continue` proves the collect had started before the
/// reload; a request received afterwards takes the new total.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn a_reload_during_collection_keeps_the_pinned_generation_total() {
    const PINNED_MS: u64 = 6_000;
    const RELOADED_MS: u64 = 600;
    const APPLIED: &str = "Configuration reloaded successfully";
    let backend = CountingBackend::spawn().await;
    let gateway = MatrixGateway::spawn(soap_yaml(backend.port, PINNED_MS), &[]).await;
    let port = gateway.proxy_port();
    let upload = Upload::soap("/soap/op", BodyScript::stalled(stalled_prefix()));

    let (continued_tx, continued_rx) = oneshot::channel();
    let started = Instant::now();
    let in_flight = {
        let upload = upload.clone();
        tokio::spawn(async move { h1_upload(port, &upload, started, Some(continued_tx)).await })
    };
    timeout(Duration::from_secs(10), continued_rx)
        .await
        .expect("the collector must poll the body")
        .expect("100 Continue observed");

    let config_path = gateway
        .gateway
        .config_path
        .clone()
        .expect("file-mode config path");
    let reloaded = soap_yaml(backend.port, RELOADED_MS);
    std::fs::write(config_path, reloaded).expect("write the new generation");
    let pid = gateway.gateway.pid().expect("gateway pid");
    let signalled = std::process::Command::new("kill")
        .args(["-HUP", &pid.to_string()])
        .status()
        .expect("run kill -HUP");
    assert!(signalled.success(), "SIGHUP failed: {signalled:?}");
    let logs = gateway
        .gateway
        .wait_for_captured_output(
            |output| output.contains(APPLIED) || output.contains("Configuration reload"),
            Duration::from_secs(20),
        )
        .await
        .unwrap_or_default();
    assert!(
        logs.contains(APPLIED),
        "the new generation must apply; gateway output:\n{}",
        gateway.gateway.diagnostic_captured_output()
    );
    assert!(
        !in_flight.is_finished(),
        "the reload must land while the pinned upload is still being collected"
    );

    let pinned = timeout(EXCHANGE_LIMIT, in_flight)
        .await
        .expect("pinned upload answered in time")
        .expect("join the pinned upload");
    assert_route_timeout(&pinned, ms(PINNED_MS), "upload received before the reload");

    let fresh = gateway.upload(Proto::H1, &upload).await;
    assert_route_timeout(&fresh, ms(RELOADED_MS), "upload received after the reload");
    assert!(
        fresh.elapsed < ms(PINNED_MS),
        "an upload received after the reload takes the new {RELOADED_MS}ms total, got {:?}",
        fresh.elapsed
    );
    backend.assert_untouched("pinned reload").await;
}

// ---------------------------------------------------------------------------
// HTTP/2 open DATA
// ---------------------------------------------------------------------------

/// DATA frames on an HTTP/2 stream that declares no `Content-Length` are cut
/// at the route total, and only that stream ends: the same connection then
/// serves a complete, authenticated upload.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn h2_open_data_without_content_length_is_cut_and_the_connection_stays_usable() {
    let backend = CountingBackend::spawn().await;
    let gateway = MatrixGateway::spawn(soap_yaml(backend.port, ROUTE_TOTAL_MS), &[]).await;
    let connection = H2Connection::open(gateway.proxy_port()).await;
    let open = Upload::soap(
        "/soap/op",
        BodyScript::trickle(stalled_prefix(), b"1", ms(100)),
    );
    let cut = connection.upload(&open, Instant::now()).await;
    assert_route_timeout(&cut, ms(ROUTE_TOTAL_MS), "open h2 DATA");
    backend.assert_untouched("open h2 DATA").await;

    let complete = Upload::soap("/soap/op", BodyScript::complete(valid_envelope()));
    let served = connection.upload(&complete, Instant::now()).await;
    assert_eq!(
        (served.status, served.body.as_ref()),
        (200, &b"ok"[..]),
        "the connection must still serve an authenticated upload, got {served:?}"
    );
    assert_eq!(
        backend.hits(),
        1,
        "exactly the complete upload reaches the backend"
    );
}

// ---------------------------------------------------------------------------
// HTTP/3 STOP_SENDING ordering and permit release
// ---------------------------------------------------------------------------

/// Over native HTTP/3 the gateway writes the `504` before it retires the
/// upload direction with `STOP_SENDING(H3_NO_ERROR)`: when the client learns
/// its upload was stopped, the response is already there. The budget admits
/// one buffered upload at a time, so the follow-up upload on the same
/// connection is admitted only if the cut upload released its permit. Two
/// rounds show the release repeats.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn h3_route_timeout_answers_before_stop_sending_and_releases_the_upload_permit() {
    let backend = CountingBackend::spawn().await;
    let yaml = soap_yaml(backend.port, ROUTE_TOTAL_MS);
    let gateway = MatrixGateway::spawn(yaml, ONE_BUFFERED_UPLOAD_FITS).await;
    let mut session = H3Session::open(gateway.https_port).await;
    let open = Upload::soap(
        "/soap/op",
        BodyScript::trickle(stalled_prefix(), b"1", ms(50)),
    );
    let complete = Upload::soap("/soap/op", BodyScript::complete(valid_envelope()));

    for round in 1..=2 {
        let started = Instant::now();
        let (send, mut recv) = session.open_stream(&open).await.split();
        let (writer, stopped) = spawn_h3_writer(send, open.script.clone(), started);
        let stopped = timeout(EXCHANGE_LIMIT, stopped)
            .await
            .unwrap_or_else(|_| panic!("round {round}: the gateway never stopped the upload"))
            .unwrap_or_else(|_| panic!("round {round}: the writer exited without a report"));
        let stop_code = match &stopped.error {
            h3::error::StreamError::RemoteTerminate { code, .. } => Some(*code),
            _ => None,
        };
        assert_eq!(
            stop_code,
            Some(h3::error::Code::H3_NO_ERROR),
            "round {round}: the upload must end with STOP_SENDING(H3_NO_ERROR), got {:?}",
            stopped.error
        );
        assert!(
            stopped.at.duration_since(started) + TIMER_SLACK >= ms(ROUTE_TOTAL_MS),
            "round {round}: the upload was stopped before the route total, after {:?}",
            stopped.at.duration_since(started)
        );
        // The grace covers only client-side scheduling of bytes that already
        // arrived: the response precedes STOP_SENDING on the wire.
        let head = timeout(Duration::from_secs(1), recv.recv_response())
            .await
            .unwrap_or_else(|_| {
                panic!("round {round}: STOP_SENDING arrived before the response head")
            })
            .unwrap_or_else(|error| panic!("round {round}: response head: {error}"));
        let (body, _) = read_h3_body(&mut recv).await;
        writer.abort();
        assert_eq!(head.status().as_u16(), 504, "round {round}");
        assert_eq!(
            header_str(head.headers(), "x-gateway-error"),
            Some("request_timeout"),
            "round {round}"
        );
        assert!(
            String::from_utf8_lossy(&body).contains("Request timeout"),
            "round {round}: route-timeout body, got {body:?}"
        );
        assert_eq!(
            backend.hits(),
            round - 1,
            "round {round}: the cut upload must not reach the backend"
        );

        let served = session.upload(&complete, Instant::now()).await;
        assert_eq!(
            (served.status, served.body.as_ref()),
            (200, &b"ok"[..]),
            "round {round}: the cut upload's retained-request permit must be released, \
             got {served:?}"
        );
        assert_eq!(backend.hits(), round, "round {round}");
    }
}

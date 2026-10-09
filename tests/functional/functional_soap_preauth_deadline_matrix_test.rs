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
//! - stalled and trickling uploads, a complete upload whose total elapses
//!   after it was collected but before dispatch, and a complete message whose
//!   total elapsed before its collector ran (expired-ready: refused unread);
//! - read/route deadline ordering, and a chunk that is ready when the route
//!   total elapses (late wake: refused, never collected);
//! - `backend_read_timeout_ms: 0` still bounded by the route total, for plain
//!   requests and as gRPC `DEADLINE_EXCEEDED`;
//! - the candidate-max profile for rules that cannot be decided before
//!   authentication, including an untimed sibling;
//! - a config reload during collection, and one that lands after receipt but
//!   before the collector previews its total, both keep the pinned
//!   generation's total;
//! - open HTTP/2 DATA without `Content-Length`;
//! - HTTP/3 response-before-`STOP_SENDING` ordering, observed as QUIC events,
//!   and the release of the retained-request permit.
//!
//! The pre-authentication collect cannot be held from outside the gateway.
//! The expired-ready and reload-before-preview cases therefore park requests
//! in `oauth2_introspection` (see `IntrospectionGate`) ahead of a
//! timestamp-only `soap_ws_security` collect, which runs the same collector.
//!
//! Every assertion checks the status, that the backend was never reached, and
//! a lower bound on the time to the answer. The backend counts every request
//! on every connection its listener accepts, HTTP/1.1 and h2c alike. The
//! client's clock starts before the request leaves, so a receipt-anchored
//! deadline can only fire later than the bound; there are no tight upper
//! bounds.
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
use h3::quic::{
    Connection as QuicConnection, ConnectionErrorIncoming, OpenStreams as QuicOpenStreams,
    StreamErrorIncoming,
};
use http::header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderName, HeaderValue};
use http::{HeaderMap, Method, Request, Response};
use serde_json::{Value, json};
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, ready};
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
/// How long past a route total a parked request is held, so that total has
/// certainly elapsed at the gateway.
const HELD_PAST_TOTAL: Duration = Duration::from_millis(200);

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
    /// `oauth2_introspection` against the gate on this port, then a
    /// timestamp-only `soap_ws_security` that collects before `before_proxy`.
    /// A message without a `wsu:Timestamp` that this collector reads is
    /// refused `401`.
    IntrospectedSoapTimestamp(u16),
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

    fn introspected_soap(
        id: &'static str,
        listen_path: &'static str,
        introspection_port: u16,
        rules: Vec<Value>,
    ) -> Self {
        Self {
            id,
            listen_path,
            read_timeout_ms: LONG_READ_TIMEOUT_MS,
            collector: Collector::IntrospectedSoapTimestamp(introspection_port),
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

/// Introspection against the gate, with no answer cached, so every request
/// makes its own call. The timeout outlasts any hold a test needs.
fn introspection_config(port: u16) -> Value {
    json!({
        "providers": [{
            "introspection_endpoint": format!("http://127.0.0.1:{port}/introspect"),
            "client_auth": {"method": "none"},
            "positive_cache_ttl_secs": 0,
            "negative_cache_ttl_secs": 0,
            "request_timeout_ms": 30_000
        }]
    })
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
            Collector::IntrospectedSoapTimestamp(introspection_port) => {
                let auth = format!("{}-introspection", route.id);
                plugin_configs.push(plugin_config(
                    auth.clone(),
                    route.id,
                    "oauth2_introspection",
                    introspection_config(introspection_port),
                ));
                let soap = format!("{}-soap", route.id);
                plugin_configs.push(plugin_config(
                    soap.clone(),
                    route.id,
                    "soap_ws_security",
                    json!({"timestamp": {"require": true}}),
                ));
                ids.push(auth);
                ids.push(soap);
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

/// A plaintext backend that counts every request on every connection its
/// listener accepts. A connection that opens with the h2c preface is served by
/// a real HTTP/2 server, so a native gRPC dispatch completes its handshake and
/// its request stream is counted whether or not the gateway waits for the
/// server's SETTINGS first. Any other connection is HTTP/1.1. Every request is
/// answered `200` (`ok`, or an empty gRPC `OK`).
///
/// The file-mode capability probe (at startup and after a reload) opens an h2c
/// connection and completes the handshake but sends no request, so it is never
/// counted.
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

/// The first bytes of the h2c connection preface. Every HTTP/1.1 request line
/// starts with a method instead.
const H2C_PREFACE_START: [u8; 4] = *b"PRI ";

async fn serve_counted_connection(stream: TcpStream, hits: Arc<AtomicUsize>) {
    // Peek, so the HTTP/2 server reads the whole preface itself.
    let mut start = [0u8; 4];
    loop {
        match stream.peek(&mut start).await {
            Ok(0) | Err(_) => return,
            Ok(read) if read == start.len() => break,
            Ok(_) => sleep(ms(1)).await,
        }
    }
    if start == H2C_PREFACE_START {
        serve_h2c_connection(stream, hits).await;
    } else {
        serve_h1_connection(stream, hits).await;
    }
}

async fn serve_h1_connection(mut stream: TcpStream, hits: Arc<AtomicUsize>) {
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
        hits.fetch_add(1, Ordering::SeqCst);
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
            let length = content_length(&head);
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

/// Serve an h2c connection, counting each request stream as it is accepted.
async fn serve_h2c_connection(stream: TcpStream, hits: Arc<AtomicUsize>) {
    let Ok(mut connection) = h2::server::handshake(stream).await else {
        return;
    };
    while let Some(Ok((request, respond))) = connection.accept().await {
        hits.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(answer_h2c_request(request, respond));
    }
}

async fn answer_h2c_request(
    request: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
) {
    let grpc = header_str(request.headers(), "content-type")
        .is_some_and(|value| value.starts_with("application/grpc"));
    let mut body = request.into_body();
    while let Some(Ok(chunk)) = body.data().await {
        let _ = body.flow_control().release_capacity(chunk.len());
    }
    let content_type = if grpc {
        "application/grpc"
    } else {
        "text/plain"
    };
    let Ok(head) = Response::builder()
        .status(200)
        .header(CONTENT_TYPE, content_type)
        .body(())
    else {
        return;
    };
    let Ok(mut send) = respond.send_response(head, false) else {
        return;
    };
    if grpc {
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        let _ = send.send_trailers(trailers);
    } else {
        let _ = send.send_data(Bytes::from_static(b"ok"), true);
    }
}

/// The `content-length` of a lowercased HTTP/1.1 head, `0` when absent.
fn content_length(head: &str) -> usize {
    head.lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0)
}

const BACKEND_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 2\r\n\r\nok";

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

// ---------------------------------------------------------------------------
// Introspection gate
// ---------------------------------------------------------------------------

/// An `oauth2_introspection` endpoint that answers each call only when the
/// test releases it. A request is received, and pinned to its plugin-cache
/// generation, before `authenticate` runs, and every collector that runs after
/// `authenticate` previews its route total only once the call is answered. So
/// holding a call parks the request inside that window, which nothing else
/// outside the gateway can reach.
struct IntrospectionGate {
    port: u16,
    calls: mpsc::UnboundedReceiver<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl IntrospectionGate {
    async fn spawn() -> Self {
        let reservation = reserve_port().await.expect("reserve introspection port");
        let port = reservation.port;
        let listener = reservation.into_listener();
        let (calls_tx, calls) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(answer_introspection_call(stream, calls_tx.clone()));
            }
        });
        Self { port, calls, task }
    }

    /// The next introspection call, held until the returned handle is sent.
    async fn next_call(&mut self) -> oneshot::Sender<()> {
        timeout(EXCHANGE_LIMIT, self.calls.recv())
            .await
            .expect("an introspection call in time")
            .expect("the introspection gate is open")
    }

    /// Take the next `calls` calls, hold them until `hold` has passed since the
    /// last one arrived, then answer them all.
    async fn release(&mut self, calls: usize, hold: Duration) {
        let mut held = Vec::with_capacity(calls);
        for _ in 0..calls {
            held.push(self.next_call().await);
        }
        sleep(hold).await;
        for call in held {
            let _ = call.send(());
        }
    }
}

impl Drop for IntrospectionGate {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Read one introspection request, report it, and answer `active` once
/// released.
async fn answer_introspection_call(
    mut stream: TcpStream,
    calls: mpsc::UnboundedSender<oneshot::Sender<()>>,
) {
    let mut buf = Vec::new();
    let head_end = loop {
        if let Some(index) = find(&buf, b"\r\n\r\n") {
            break index + 4;
        }
        if !fill(&mut stream, &mut buf).await {
            return;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
    let length = content_length(&head);
    while buf.len() < head_end + length {
        if !fill(&mut stream, &mut buf).await {
            return;
        }
    }
    let (release, released) = oneshot::channel();
    if calls.send(release).is_err() || released.await.is_err() {
        return;
    }
    let claims = r#"{"active":true,"username":"soap-client"}"#;
    let answer = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
         connection: close\r\n\r\n{claims}",
        claims.len()
    );
    let _ = stream.write_all(answer.as_bytes()).await;
}

/// The same upload once per protocol, each under its own bearer token. The
/// introspection plugin shares one call between concurrent requests for the
/// same token, and every upload has to park its own call at the gate.
fn bearer_uploads(upload: &Upload, tokens: [&'static str; 3]) -> [(Proto, Upload); 3] {
    let [h1, h2, h3] = tokens;
    [
        (Proto::H1, upload.clone().header("authorization", h1)),
        (Proto::H2, upload.clone().header("authorization", h2)),
        (Proto::H3, upload.clone().header("authorization", h3)),
    ]
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

    /// Each upload on its own protocol, all at once.
    async fn upload_each(&self, uploads: &[(Proto, Upload); 3]) -> [Outcome; 3] {
        let [(first, a), (second, b), (third, c)] = uploads;
        let (a, b, c) = tokio::join!(
            self.upload(*first, a),
            self.upload(*second, b),
            self.upload(*third, c),
        );
        [a, b, c]
    }
}

/// Rewrite the file-mode config and SIGHUP the gateway. Returns once the new
/// generation is applied.
#[cfg(unix)]
async fn reload(gateway: &MatrixGateway, yaml: String) {
    const APPLIED: &str = "Configuration reloaded successfully";
    let gateway = &gateway.gateway;
    let applied_before = gateway
        .read_combined_captured_output()
        .unwrap_or_default()
        .matches(APPLIED)
        .count();
    let config_path = gateway.config_path.clone().expect("file-mode config path");
    std::fs::write(config_path, yaml).expect("write the new generation");
    let pid = gateway.pid().expect("gateway pid");
    let signalled = std::process::Command::new("kill")
        .args(["-HUP", &pid.to_string()])
        .status()
        .expect("run kill -HUP");
    assert!(signalled.success(), "SIGHUP failed: {signalled:?}");
    let logs = gateway
        .wait_for_captured_output(
            |output| output.matches(APPLIED).count() > applied_before,
            Duration::from_secs(20),
        )
        .await
        .unwrap_or_default();
    assert!(
        logs.matches(APPLIED).count() > applied_before,
        "the new generation must apply; gateway output:\n{}",
        gateway.diagnostic_captured_output()
    );
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
        upload.path, upload.content_type
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

type H3SendRequest = h3::client::SendRequest<StopTapOpenStreams, Bytes>;
type H3ClientStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type H3SendHalf = h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type H3RecvHalf = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;

/// Completes when QUIC processes the peer's `STOP_SENDING` for one request
/// stream, with its code.
type StopSendingWatch =
    Pin<Box<dyn Future<Output = Result<Option<u64>, StreamErrorIncoming>> + Send>>;

/// The `h3_quinn` connection with one addition: as h3 opens each request
/// stream, the stream's `STOP_SENDING` watch is handed to the session. The h3
/// client keeps the QUIC stream private. The watch fires as soon as QUIC
/// processes the frame, whereas a failed write only notices it at the next
/// write.
struct StopTapConnection {
    inner: h3_quinn::Connection,
    watches: mpsc::UnboundedSender<StopSendingWatch>,
}

impl QuicOpenStreams<Bytes> for StopTapConnection {
    type BidiStream = h3_quinn::BidiStream<Bytes>;
    type SendStream = h3_quinn::SendStream<Bytes>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        QuicOpenStreams::<Bytes>::poll_open_bidi(&mut self.inner, cx)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        QuicOpenStreams::<Bytes>::poll_open_send(&mut self.inner, cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        QuicOpenStreams::<Bytes>::close(&mut self.inner, code, reason);
    }
}

impl QuicConnection<Bytes> for StopTapConnection {
    type RecvStream = h3_quinn::RecvStream;
    type OpenStreams = StopTapOpenStreams;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        QuicConnection::<Bytes>::poll_accept_recv(&mut self.inner, cx)
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        QuicConnection::<Bytes>::poll_accept_bidi(&mut self.inner, cx)
    }

    fn opener(&self) -> StopTapOpenStreams {
        StopTapOpenStreams {
            inner: QuicConnection::<Bytes>::opener(&self.inner),
            watches: self.watches.clone(),
        }
    }
}

/// The request-stream opener of a `StopTapConnection`.
struct StopTapOpenStreams {
    inner: h3_quinn::OpenStreams,
    watches: mpsc::UnboundedSender<StopSendingWatch>,
}

impl QuicOpenStreams<Bytes> for StopTapOpenStreams {
    type BidiStream = h3_quinn::BidiStream<Bytes>;
    type SendStream = h3_quinn::SendStream<Bytes>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        let opened = QuicOpenStreams::<Bytes>::poll_open_bidi(&mut self.inner, cx);
        let opened = ready!(opened);
        if let Ok(stream) = &opened {
            let watch = h3::quic::SendStreamStopped::stopped(stream);
            let _ = self.watches.send(Box::pin(watch));
        }
        Poll::Ready(opened)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        QuicOpenStreams::<Bytes>::poll_open_send(&mut self.inner, cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        QuicOpenStreams::<Bytes>::close(&mut self.inner, code, reason);
    }
}

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
    stop_watches: mpsc::UnboundedReceiver<StopSendingWatch>,
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
        let (watches, stop_watches) = mpsc::unbounded_channel();
        let connection = StopTapConnection {
            inner: h3_quinn::Connection::new(connection),
            watches,
        };
        let (mut driver, send_request) = h3::client::new(connection).await.expect("h3 client");
        let driver = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        Self {
            send_request,
            stop_watches,
            driver,
            endpoint,
            https_port,
        }
    }

    /// Open a request stream for `upload`'s head, with the stream's
    /// `STOP_SENDING` watch.
    async fn open_stream(&mut self, upload: &Upload) -> (H3ClientStream, StopSendingWatch) {
        let url = format!("https://127.0.0.1:{}{}", self.https_port, upload.path);
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(url)
            .header(CONTENT_TYPE, upload.content_type);
        for (name, value) in &upload.headers {
            builder = builder.header(*name, *value);
        }
        let request = builder.body(()).expect("h3 request");
        let stream = timeout(EXCHANGE_LIMIT, self.send_request.send_request(request))
            .await
            .expect("h3 request stream in time")
            .expect("open the h3 request stream");
        // Opening a request stream sends its watch before h3 returns it.
        let watch = self
            .stop_watches
            .try_recv()
            .expect("the request stream's STOP_SENDING watch");
        (stream, watch)
    }

    async fn upload(&mut self, upload: &Upload, started: Instant) -> Outcome {
        let (stream, _stop_sending) = self.open_stream(upload).await;
        let (send, mut recv) = stream.split();
        let writer = spawn_h3_writer(send, upload.script.clone(), started);
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

/// Drive `script` on an HTTP/3 request's send half, then hold the send half
/// until aborted. A write the gateway stopped ends the script early.
fn spawn_h3_writer(mut send: H3SendHalf, script: BodyScript, started: Instant) -> JoinHandle<()> {
    tokio::spawn(async move {
        let _ = drive_h3_upload(&mut send, script, started).await;
        std::future::pending::<()>().await;
    })
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

/// What a client saw first on an HTTP/3 request stream.
enum FirstOnStream {
    /// The response head, and the `STOP_SENDING` watch still to come.
    Head(
        Result<Response<()>, h3::error::StreamError>,
        StopSendingWatch,
    ),
    /// The peer's `STOP_SENDING`, while no response head had been received.
    StopSending(Result<Option<u64>, StreamErrorIncoming>),
}

/// Wait for the response head or the `STOP_SENDING`, whichever QUIC delivers
/// first, polling the head first on every wake. QUIC applies all of a
/// received packet's frames to the stream state before it wakes any task. So
/// a head the gateway wrote before `STOP_SENDING`, in an earlier packet or the
/// same one, is always readable by the time the watch fires. Only a
/// `STOP_SENDING` sent ahead of the head can win, with no grace for either.
async fn head_or_stop_sending(
    recv: &mut H3RecvHalf,
    mut stop_sending: StopSendingWatch,
) -> FirstOnStream {
    let first = {
        let mut head = std::pin::pin!(recv.recv_response());
        std::future::poll_fn(|cx| {
            if let Poll::Ready(head) = head.as_mut().poll(cx) {
                return Poll::Ready(Ok(head));
            }
            stop_sending.as_mut().poll(cx).map(Err)
        })
        .await
    };
    match first {
        Ok(head) => FirstOnStream::Head(head, stop_sending),
        Err(code) => FirstOnStream::StopSending(code),
    }
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

/// A complete, valid body ready with the request head is collected and
/// authenticated well inside the total, and the matched rule's fault delay
/// then outlasts the total. Gateway-local hooks are not cancelled mid-hook,
/// so the answer cannot come before the delay ends: it is the pre-dispatch
/// refusal of an elapsed total, the route-timeout `504` with the
/// `request_timeout` token, and no backend is dialed.
///
/// This passes under a refusal made only before dispatch as well. The
/// pre-authentication collect cannot be delayed from outside the gateway, so
/// nothing here can make its total elapse while the body is ready.
/// `a_ready_message_whose_total_elapsed_before_its_collector_ran_is_refused_unread`
/// does that for the collector that runs after `authenticate`. The
/// deterministic collector tests pin it for both
/// (`tests/unit/gateway_core/early_route_upload_tests.rs`,
/// `*_an_elapsed_*_refuses_a_ready_body_without_polling_it`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn a_ready_upload_whose_total_elapses_before_dispatch_never_reaches_the_backend() {
    const FAULT_DELAY_MS: u64 = 2 * ROUTE_TOTAL_MS;
    let backend = CountingBackend::spawn().await;
    let port = backend.port;
    let mut delayed = rule(port, json!({}), Some(ROUTE_TOTAL_MS));
    delayed["fault"] = json!({"delay": {"duration_ms": FAULT_DELAY_MS, "percentage": 100.0}});
    let yaml = gateway_yaml(
        port,
        &[Route::soap(
            "soap",
            "/soap",
            SoapMode::UsernameToken,
            LONG_READ_TIMEOUT_MS,
            vec![delayed],
        )],
    );
    let gateway = MatrixGateway::spawn(yaml, &[]).await;
    let upload = Upload::soap("/soap/op", BodyScript::complete(valid_envelope()));
    for outcome in gateway.upload_on_every_protocol(&upload).await {
        assert_route_timeout(&outcome, ms(FAULT_DELAY_MS), "elapsed before dispatch");
    }
    backend.assert_untouched("elapsed before dispatch").await;
}

/// Expired-ready: a complete message is ready with the request head, and its
/// route total elapses before the collector runs. Only a collector that checks
/// an elapsed total before it reads a ready body answers the `504`.
///
/// The route authenticates through `oauth2_introspection`, and a timestamp-only
/// `soap_ws_security` collects the message after that, before `before_proxy`.
/// That is the same deadline-first collector, previewing the same route total
/// from receipt, as the identity-mode collect. The gate holds each
/// introspection call until the total has elapsed for every request it parks.
/// The message carries no `wsu:Timestamp`, so a collector that read it would
/// hand it to the timestamp policy and answer `401`. That includes a refusal
/// made only before dispatch, since it comes after that policy. The control
/// route, under a total that cannot elapse, shows that `401`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn a_ready_message_whose_total_elapsed_before_its_collector_ran_is_refused_unread() {
    const TOTAL_MS: u64 = 300;
    const CONTROL_TOTAL_MS: u64 = 30_000;
    let backend = CountingBackend::spawn().await;
    let mut gate = IntrospectionGate::spawn().await;
    let port = backend.port;
    let yaml = gateway_yaml(
        port,
        &[
            Route::introspected_soap(
                "expired",
                "/expired",
                gate.port,
                vec![rule(port, json!({}), Some(TOTAL_MS))],
            ),
            Route::introspected_soap(
                "control",
                "/control",
                gate.port,
                vec![rule(port, json!({}), Some(CONTROL_TOTAL_MS))],
            ),
        ],
    );
    let gateway = MatrixGateway::spawn(yaml, &[]).await;

    let control = bearer_uploads(
        &Upload::soap("/control/op", BodyScript::complete(valid_envelope())),
        [
            "Bearer control-h1",
            "Bearer control-h2",
            "Bearer control-h3",
        ],
    );
    let (outcomes, ()) = tokio::join!(
        gateway.upload_each(&control),
        gate.release(control.len(), Duration::ZERO),
    );
    for outcome in outcomes {
        assert_eq!(
            outcome.status, 401,
            "control on {:?}: a collected message reaches the timestamp policy, got {outcome:?}",
            outcome.proto
        );
    }

    // Every request is received before its introspection call, so holding the
    // calls this long after the last one elapses every request's total.
    let expired = bearer_uploads(
        &Upload::soap("/expired/op", BodyScript::complete(valid_envelope())),
        [
            "Bearer expired-h1",
            "Bearer expired-h2",
            "Bearer expired-h3",
        ],
    );
    let (outcomes, ()) = tokio::join!(
        gateway.upload_each(&expired),
        gate.release(expired.len(), ms(TOTAL_MS) + HELD_PAST_TOTAL),
    );
    for outcome in outcomes {
        assert_route_timeout(&outcome, ms(TOTAL_MS), "ready message, elapsed total");
    }
    backend
        .assert_untouched("ready message, elapsed total")
        .await;
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
/// ends the collect with its `408`, never the shorter sibling's `504`. The
/// untimed candidate is a catch-all on the path, which is decided before
/// authentication, behind the undecided identity rule.
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
                rule(port, json!({"uri": {"prefix": "/"}}), None),
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
///
/// The collector previews its total just before that first poll, so here the
/// bound is already armed when the reload lands.
/// `a_reload_before_the_collector_previews_its_total_keeps_the_pinned_generation`
/// lands the reload before the preview.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn a_reload_during_collection_keeps_the_pinned_generation_total() {
    const PINNED_MS: u64 = 6_000;
    const RELOADED_MS: u64 = 600;
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

    reload(&gateway, soap_yaml(backend.port, RELOADED_MS)).await;
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

/// A reload that lands after a request was received but before its collector
/// previews the route total does not change that total. The gate parks each
/// upload inside `authenticate`, after receipt and before the collector that
/// runs once `authenticate` returns. The reload replaces the pinned total with
/// one that has already elapsed by the time the calls are released. A
/// collector that read the live generation would refuse at once, so each
/// stalled upload has to run to the pinned total instead. A request received
/// after the reload takes the new total.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn a_reload_before_the_collector_previews_its_total_keeps_the_pinned_generation() {
    const PINNED_MS: u64 = 8_000;
    const RELOADED_MS: u64 = 600;
    let backend = CountingBackend::spawn().await;
    let mut gate = IntrospectionGate::spawn().await;
    let (port, gate_port) = (backend.port, gate.port);
    let yaml = |total_ms| {
        gateway_yaml(
            port,
            &[Route::introspected_soap(
                "pinned",
                "/pinned",
                gate_port,
                vec![rule(port, json!({}), Some(total_ms))],
            )],
        )
    };
    let gateway = MatrixGateway::spawn(yaml(PINNED_MS), &[]).await;
    let stalled = bearer_uploads(
        &Upload::soap("/pinned/op", BodyScript::stalled(stalled_prefix())),
        ["Bearer pinned-h1", "Bearer pinned-h2", "Bearer pinned-h3"],
    );

    let started = Instant::now();
    let reload_while_parked = async {
        let mut parked = Vec::with_capacity(stalled.len());
        for _ in 0..stalled.len() {
            parked.push(gate.next_call().await);
        }
        reload(&gateway, yaml(RELOADED_MS)).await;
        // Each request was received before its call, and every call arrived
        // before the reload, so the reloaded total has elapsed for all of them.
        sleep(ms(RELOADED_MS) + HELD_PAST_TOTAL).await;
        let released_after = started.elapsed();
        for call in parked {
            let _ = call.send(());
        }
        released_after
    };
    let (outcomes, released_after) =
        tokio::join!(gateway.upload_each(&stalled), reload_while_parked);
    // A live-generation preview would answer at about `released_after`.
    assert!(
        released_after + ms(1_000) < ms(PINNED_MS),
        "the parked uploads must be released well inside the pinned total to tell the \
         generations apart, released after {released_after:?}"
    );
    for outcome in outcomes {
        assert_route_timeout(&outcome, ms(PINNED_MS), "previewed after the reload");
    }

    let fresh = Upload::soap("/pinned/op", BodyScript::stalled(stalled_prefix()))
        .header("authorization", "Bearer fresh-h1");
    let (fresh, ()) = tokio::join!(
        gateway.upload(Proto::H1, &fresh),
        gate.release(1, Duration::ZERO),
    );
    assert_route_timeout(&fresh, ms(RELOADED_MS), "received after the reload");
    assert!(
        fresh.elapsed < ms(PINNED_MS),
        "a request received after the reload takes the new {RELOADED_MS}ms total, got {:?}",
        fresh.elapsed
    );
    backend.assert_untouched("reload before the preview").await;
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
/// upload direction with `STOP_SENDING(H3_NO_ERROR)`. The client watches the
/// stream's `STOP_SENDING` as QUIC processes it and polls the response head
/// first on every wake, so the head has to be readable no later than the
/// `STOP_SENDING` is: there is no grace period. The budget admits one buffered
/// upload at a time, so the follow-up upload on the same connection is
/// admitted only if the cut upload released its permit. Two rounds show the
/// release repeats.
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
        let (stream, stop) = session.open_stream(&open).await;
        let (send, mut recv) = stream.split();
        let writer = spawn_h3_writer(send, open.script.clone(), started);
        let first = timeout(EXCHANGE_LIMIT, head_or_stop_sending(&mut recv, stop))
            .await
            .unwrap_or_else(|_| panic!("round {round}: neither a response nor STOP_SENDING"));
        let (head, stop) = match first {
            FirstOnStream::Head(head, stop) => (head, stop),
            FirstOnStream::StopSending(code) => panic!(
                "round {round}: STOP_SENDING ({code:?}) arrived while no response head had \
                 been received"
            ),
        };
        let head = head.unwrap_or_else(|error| panic!("round {round}: response head: {error}"));
        let answered_after = started.elapsed();
        let stop_code = timeout(EXCHANGE_LIMIT, stop)
            .await
            .unwrap_or_else(|_| panic!("round {round}: the gateway never stopped the upload"));
        assert_eq!(
            stop_code.as_ref().ok().copied().flatten(),
            Some(h3::error::Code::H3_NO_ERROR.value()),
            "round {round}: the upload must end with STOP_SENDING(H3_NO_ERROR), got {stop_code:?}"
        );
        assert!(
            answered_after + TIMER_SLACK >= ms(ROUTE_TOTAL_MS),
            "round {round}: answered before the route total, after {answered_after:?}"
        );
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

//! Pre-routing refusals keep the client's wire framing on HTTP/1.1 and HTTP/2
//! (issue #6943).
//!
//! The H1/H2 handler refuses some requests before routing: the header limits,
//! URL length, query-parameter count, the protocol-header guard, and the
//! HTTP/2 Host/`:authority` agreement check. Each refusal is framed for the
//! client, as on HTTP/3: plain HTTP gets the JSON error, native gRPC a
//! Trailers-Only status, gRPC-Web a status in its body trailer frame, and a
//! WebSocket handshake that carries a gRPC Content-Type keeps the HTTP
//! refusal. The header limits are the one gRPC-Web exception: they run before
//! the gateway negotiates a gRPC-Web response media type from request headers,
//! so gRPC-Web keeps the JSON answer there.
//!
//! A non-WebSocket CONNECT is never framed as gRPC, whatever its Content-Type
//! and whichever refusal answers it: a 2xx answer to CONNECT means "tunnel
//! established" (RFC 9110 §9.3.6), so a gRPC Trailers-Only or gRPC-Web HTTP
//! `200` cannot refuse one. Every flavor gets the HTTP refusal.
//!
//! Every refused request must stop at the gateway: the backend records each
//! path it serves, no refused path may appear there, and admitted controls on
//! both frontends prove the recording is live.
//!
//! Run with: `cargo test --test functional_tests functional_pre_routing_refusal -- --ignored --nocapture`

use crate::common::TestGateway;
use crate::scaffolding::port_registry::TestSocket;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

const WAIT: Duration = Duration::from_secs(10);
const MAX_URL_LENGTH_BYTES: usize = 64;
const MAX_QUERY_PARAMS: usize = 2;
const MAX_SINGLE_HEADER_SIZE_BYTES: usize = 4096;
const MAX_HEADER_COUNT: usize = 24;
const GRPC_INVALID_ARGUMENT: u32 = 3;
const GRPC_RESOURCE_EXHAUSTED: u32 = 8;
const GRPC_UNIMPLEMENTED: u32 = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wire {
    H1,
    H2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flavor {
    Plain,
    Grpc,
    GrpcWeb,
    /// A WebSocket handshake (H1 Upgrade / H2 Extended CONNECT) carrying a
    /// hostile native-gRPC Content-Type.
    WebSocket,
    /// The same handshake carrying a hostile gRPC-Web Content-Type, which must
    /// not select a gRPC-Web response representation.
    WebSocketGrpcWeb,
}

impl Flavor {
    fn is_websocket(self) -> bool {
        matches!(self, Flavor::WebSocket | Flavor::WebSocketGrpcWeb)
    }
}

const FLAVORS: [Flavor; 5] = [
    Flavor::Plain,
    Flavor::Grpc,
    Flavor::GrpcWeb,
    Flavor::WebSocket,
    Flavor::WebSocketGrpcWeb,
];

struct Refusal {
    name: &'static str,
    /// Replaces the flavor's request method. A WebSocket handshake is defined
    /// by its method, so such a case skips the WebSocket flavor.
    method: Option<Method>,
    target: String,
    headers: Vec<(&'static str, String)>,
    http_status: StatusCode,
    json_fragment: &'static str,
    grpc_status: u32,
    grpc_message: &'static str,
    /// `false` only for CONNECT (see the module docs): every flavor then gets
    /// the HTTP refusal, and `grpc_status` / `grpc_message` are unused.
    grpc_framed: bool,
    /// `false` for the header limits and CONNECT (see the module docs).
    grpc_web_framed: bool,
    wires: &'static [Wire],
}

fn refusals() -> Vec<Refusal> {
    vec![
        Refusal {
            method: None,
            name: "url_length",
            target: format!("/refusal-{}", "a".repeat(MAX_URL_LENGTH_BYTES * 2)),
            headers: Vec::new(),
            http_status: StatusCode::URI_TOO_LONG,
            json_fragment: "Request URL length",
            grpc_status: GRPC_RESOURCE_EXHAUSTED,
            grpc_message: "Request URL too long",
            grpc_framed: true,
            grpc_web_framed: true,
            wires: &[Wire::H1, Wire::H2],
        },
        Refusal {
            method: None,
            name: "query_count",
            target: "/refusal?a=1&b=2&c=3".to_string(),
            headers: Vec::new(),
            http_status: StatusCode::BAD_REQUEST,
            json_fragment: "Query parameter count (3) exceeds maximum of 2",
            grpc_status: GRPC_INVALID_ARGUMENT,
            grpc_message: "Too many query parameters",
            grpc_framed: true,
            grpc_web_framed: true,
            wires: &[Wire::H1, Wire::H2],
        },
        Refusal {
            method: None,
            name: "protocol_header_guard",
            target: "/refusal".to_string(),
            headers: vec![
                ("authorization", "Bearer first".to_string()),
                ("authorization", "Bearer second".to_string()),
            ],
            http_status: StatusCode::BAD_REQUEST,
            json_fragment: "Request contains multiple Authorization headers",
            grpc_status: GRPC_INVALID_ARGUMENT,
            grpc_message: "Protocol header violation",
            grpc_framed: true,
            grpc_web_framed: true,
            wires: &[Wire::H1, Wire::H2],
        },
        Refusal {
            // HTTP/1.1 carries no `:authority`; its absolute-form disagreement
            // is part of the protocol-header guard above.
            method: None,
            name: "host_authority_disagreement",
            target: "/refusal".to_string(),
            headers: vec![("host", "evil.example".to_string())],
            http_status: StatusCode::BAD_REQUEST,
            json_fragment: "Host header and request authority disagree",
            grpc_status: GRPC_INVALID_ARGUMENT,
            grpc_message: "Invalid :authority or Host",
            grpc_framed: true,
            grpc_web_framed: true,
            wires: &[Wire::H2],
        },
        Refusal {
            method: None,
            name: "single_header_size",
            target: "/refusal".to_string(),
            headers: vec![("x-padding", "p".repeat(MAX_SINGLE_HEADER_SIZE_BYTES + 1))],
            http_status: StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            json_fragment: "exceeds maximum size of 4096 bytes",
            grpc_status: GRPC_RESOURCE_EXHAUSTED,
            grpc_message: "Request header exceeds maximum size",
            grpc_framed: true,
            grpc_web_framed: false,
            wires: &[Wire::H1, Wire::H2],
        },
        Refusal {
            method: None,
            name: "header_count",
            target: "/refusal".to_string(),
            headers: (0..MAX_HEADER_COUNT + 6)
                .map(|_| ("x-count", "1".to_string()))
                .collect(),
            http_status: StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            json_fragment: "exceeds maximum of 24",
            grpc_status: GRPC_RESOURCE_EXHAUSTED,
            grpc_message: "Request header count exceeds maximum",
            grpc_framed: true,
            grpc_web_framed: false,
            wires: &[Wire::H1, Wire::H2],
        },
        Refusal {
            name: "trace_method",
            method: Some(Method::TRACE),
            target: "/refusal".to_string(),
            headers: Vec::new(),
            http_status: StatusCode::METHOD_NOT_ALLOWED,
            json_fragment: "TRACE method is not allowed",
            grpc_status: GRPC_UNIMPLEMENTED,
            grpc_message: "TRACE method is not allowed",
            grpc_framed: true,
            grpc_web_framed: true,
            wires: &[Wire::H1, Wire::H2],
        },
        Refusal {
            // HTTP/1.1 authority-form; HTTP/2 with `:authority` alone, no
            // `:protocol`. The WebSocket flavors are Extended CONNECT, which
            // is admitted, so they are skipped.
            name: "connect_method",
            method: Some(Method::CONNECT),
            target: "/refusal".to_string(),
            headers: Vec::new(),
            http_status: StatusCode::METHOD_NOT_ALLOWED,
            json_fragment: "CONNECT method is not allowed",
            grpc_status: GRPC_UNIMPLEMENTED,
            grpc_message: "CONNECT method is not allowed",
            grpc_framed: false,
            grpc_web_framed: false,
            wires: &[Wire::H1, Wire::H2],
        },
        // Refusals that run before the CONNECT gate keep a CONNECT's HTTP
        // status too.
        Refusal {
            name: "connect_protocol_header_guard",
            method: Some(Method::CONNECT),
            target: "/refusal".to_string(),
            headers: vec![
                ("authorization", "Bearer first".to_string()),
                ("authorization", "Bearer second".to_string()),
            ],
            http_status: StatusCode::BAD_REQUEST,
            json_fragment: "Request contains multiple Authorization headers",
            grpc_status: GRPC_INVALID_ARGUMENT,
            grpc_message: "Protocol header violation",
            grpc_framed: false,
            grpc_web_framed: false,
            wires: &[Wire::H1, Wire::H2],
        },
        Refusal {
            name: "connect_header_count",
            method: Some(Method::CONNECT),
            target: "/refusal".to_string(),
            headers: (0..MAX_HEADER_COUNT + 6)
                .map(|_| ("x-count", "1".to_string()))
                .collect(),
            http_status: StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            json_fragment: "exceeds maximum of 24",
            grpc_status: GRPC_RESOURCE_EXHAUSTED,
            grpc_message: "Request header count exceeds maximum",
            grpc_framed: false,
            grpc_web_framed: false,
            wires: &[Wire::H1, Wire::H2],
        },
    ]
}

struct RecordingBackend {
    port: u16,
    paths: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for RecordingBackend {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl RecordingBackend {
    fn paths(&self) -> Vec<String> {
        self.paths.lock().expect("recorded paths").clone()
    }
}

/// An HTTP/1.1 + h2c backend that records every request path it serves, so
/// the test can prove which requests reached dispatch. Paths are recorded
/// rather than connections because the gateway's startup capability probe
/// and pool warmup also dial the backend.
async fn spawn_recording_backend() -> RecordingBackend {
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind recording backend");
    let port = listener.local_addr().expect("backend address").port();
    let paths = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&paths);
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let recorded = Arc::clone(&recorded);
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    recorded
                        .lock()
                        .expect("recorded paths")
                        .push(request.uri().path().to_string());
                    async {
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                            b"backend",
                        ))))
                    }
                });
                let _ = AutoBuilder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    RecordingBackend { port, paths, task }
}

fn gateway_config(backend_port: u16) -> String {
    format!(
        "version: \"1\"\nproxies:\n\
         \x20 - id: \"pre-routing-refusal\"\n\
         \x20   listen_path: \"/\"\n\
         \x20   backend_scheme: http\n\
         \x20   backend_host: \"127.0.0.1\"\n\
         \x20   backend_port: {backend_port}\n\
         \x20   strip_listen_path: false\n\
         \x20   plugins: []\n\
         consumers: []\n\
         plugin_configs: []\n",
    )
}

struct WireResponse {
    status: StatusCode,
    headers: http::HeaderMap,
    body: Bytes,
}

impl WireResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }
}

/// One request on a fresh connection, so a refusal that closes the
/// connection cannot disturb the next case.
async fn send(
    port: u16,
    wire: Wire,
    flavor: Flavor,
    method: Option<&Method>,
    target: &str,
    headers: &[(&'static str, String)],
) -> WireResponse {
    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect to gateway");
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);

    let mut builder = match (wire, flavor) {
        (Wire::H1, Flavor::WebSocket | Flavor::WebSocketGrpcWeb) => Request::builder()
            .method(Method::GET)
            .uri(target)
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
        (Wire::H2, Flavor::WebSocket | Flavor::WebSocketGrpcWeb) => Request::builder()
            .method(Method::CONNECT)
            .version(http::Version::HTTP_2)
            .uri(format!("http://127.0.0.1:{port}{target}"))
            .extension(hyper::ext::Protocol::from_static("websocket"))
            .header("sec-websocket-version", "13"),
        (Wire::H1, Flavor::Plain) => Request::builder().method(Method::GET).uri(target),
        (Wire::H2, Flavor::Plain) => Request::builder()
            .method(Method::GET)
            .uri(format!("http://127.0.0.1:{port}{target}")),
        (Wire::H1, Flavor::Grpc | Flavor::GrpcWeb) => {
            Request::builder().method(Method::POST).uri(target)
        }
        (Wire::H2, Flavor::Grpc | Flavor::GrpcWeb) => Request::builder()
            .method(Method::POST)
            .uri(format!("http://127.0.0.1:{port}{target}"))
            .header("te", "trailers"),
    };
    if let Some(method) = method {
        builder = builder.method(method.clone());
        // A plain CONNECT names only an authority: the HTTP/1.1 authority-form
        // request-target, and on HTTP/2 a request with `:authority` but no
        // `:scheme`, `:path`, or `:protocol` (h2 omits both for a CONNECT
        // without the `Protocol` extension).
        if *method == Method::CONNECT {
            builder = builder.uri(format!("127.0.0.1:{port}"));
        }
    }
    builder = match flavor {
        Flavor::Plain => builder,
        Flavor::Grpc | Flavor::WebSocket => builder.header("content-type", "application/grpc"),
        Flavor::GrpcWeb | Flavor::WebSocketGrpcWeb => {
            builder.header("content-type", "application/grpc-web+proto")
        }
    };
    if wire == Wire::H1 && !headers.iter().any(|(name, _)| *name == "host") {
        builder = builder.header("host", format!("127.0.0.1:{port}"));
    }
    for (name, value) in headers {
        builder = builder.header(*name, value.as_str());
    }
    let request = builder.body(Empty::<Bytes>::new()).expect("build request");

    let response = match wire {
        Wire::H1 => {
            let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
                .await
                .expect("HTTP/1.1 handshake");
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            let response = tokio::time::timeout(WAIT, sender.send_request(request))
                .await
                .expect("HTTP/1.1 response deadline")
                .expect("HTTP/1.1 response");
            (response, driver)
        }
        Wire::H2 => {
            let (mut sender, connection) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
                    .await
                    .expect("HTTP/2 handshake");
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            let response = tokio::time::timeout(WAIT, sender.send_request(request))
                .await
                .expect("HTTP/2 response deadline")
                .expect("HTTP/2 response");
            (response, driver)
        }
    };
    let (response, driver) = response;
    let status = response.status();
    let response_headers = response.headers().clone();
    let body = tokio::time::timeout(WAIT, response.into_body().collect())
        .await
        .expect("response body deadline")
        .expect("clean response body")
        .to_bytes();
    driver.abort();
    WireResponse {
        status,
        headers: response_headers,
        body,
    }
}

/// Decode one binary gRPC-Web trailer frame: flag `0x80`, a big-endian
/// length, then `name: value\r\n` lines.
fn grpc_web_trailers(body: &[u8]) -> HashMap<String, String> {
    assert!(
        body.len() >= 5,
        "gRPC-Web trailer frame too short: {body:?}"
    );
    assert_eq!(body[0], 0x80, "the only frame must be the trailer frame");
    let length = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
    assert_eq!(body.len(), 5 + length, "exactly one trailer frame");
    let block = std::str::from_utf8(&body[5..]).expect("UTF-8 trailer block");
    block
        .split("\r\n")
        .filter(|line| !line.is_empty())
        .map(|line| {
            let (name, value) = line.split_once(':').expect("trailer line");
            (name.trim().to_ascii_lowercase(), value.trim().to_string())
        })
        .collect()
}

fn assert_refusal(case: &Refusal, wire: Wire, flavor: Flavor, response: &WireResponse) {
    let label = format!("{} over {wire:?} as {flavor:?}", case.name);
    let body_text = String::from_utf8_lossy(&response.body);
    let expected_grpc_status = case.grpc_status.to_string();
    match flavor {
        Flavor::Grpc if case.grpc_framed => {
            assert_eq!(response.status, StatusCode::OK, "{label}: Trailers-Only");
            assert_eq!(
                response.header("content-type"),
                Some("application/grpc"),
                "{label}"
            );
            assert_eq!(
                response.header("grpc-status"),
                Some(expected_grpc_status.as_str()),
                "{label}"
            );
            assert_eq!(
                response.header("grpc-message"),
                Some(case.grpc_message),
                "{label}"
            );
            assert!(
                response.body.is_empty(),
                "{label}: no JSON entity may appear in gRPC DATA: {body_text}"
            );
        }
        Flavor::GrpcWeb if case.grpc_web_framed => {
            assert_eq!(response.status, StatusCode::OK, "{label}: framed status");
            assert_eq!(
                response.header("content-type"),
                Some("application/grpc-web+proto"),
                "{label}"
            );
            assert!(
                !response.headers.contains_key("grpc-status"),
                "{label}: gRPC-Web carries its status in the body trailer frame"
            );
            let trailers = grpc_web_trailers(&response.body);
            assert_eq!(
                trailers.get("grpc-status").map(String::as_str),
                Some(expected_grpc_status.as_str()),
                "{label}"
            );
            assert_eq!(
                trailers.get("grpc-message").map(String::as_str),
                Some(case.grpc_message),
                "{label}"
            );
        }
        Flavor::Plain
        | Flavor::Grpc
        | Flavor::GrpcWeb
        | Flavor::WebSocket
        | Flavor::WebSocketGrpcWeb => {
            assert_eq!(response.status, case.http_status, "{label}: {body_text}");
            assert!(
                !response.headers.contains_key("grpc-status"),
                "{label}: an HTTP refusal carries no gRPC status"
            );
            assert_eq!(
                response.header("content-type"),
                Some("application/json"),
                "{label}"
            );
            assert!(
                body_text.contains(case.json_fragment),
                "{label}: unexpected body {body_text}"
            );
        }
    }
}

#[ignore]
#[tokio::test]
async fn functional_pre_routing_refusal_framing_matches_client_flavor_on_h1_and_h2() {
    let backend = spawn_recording_backend().await;
    let mut gateway = TestGateway::builder()
        .mode_file(gateway_config(backend.port))
        .log_level("warn")
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .env(
            "FERRUM_MAX_URL_LENGTH_BYTES",
            MAX_URL_LENGTH_BYTES.to_string(),
        )
        .env("FERRUM_MAX_QUERY_PARAMS", MAX_QUERY_PARAMS.to_string())
        .env("FERRUM_MAX_HEADER_COUNT", MAX_HEADER_COUNT.to_string())
        .env(
            "FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES",
            MAX_SINGLE_HEADER_SIZE_BYTES.to_string(),
        )
        .capture_output()
        .spawn()
        .await
        .expect("start gateway");
    gateway
        .wait_for_proxy_port(WAIT)
        .await
        .expect("proxy port ready");
    let port = gateway.proxy_port;

    for case in refusals() {
        for wire in case.wires {
            for flavor in FLAVORS {
                if case.method.is_some() && flavor.is_websocket() {
                    continue;
                }
                let response = send(
                    port,
                    *wire,
                    flavor,
                    case.method.as_ref(),
                    &case.target,
                    &case.headers,
                )
                .await;
                assert_refusal(&case, *wire, flavor, &response);
                if case.http_status == StatusCode::METHOD_NOT_ALLOWED {
                    assert_eq!(
                        response.header("allow"),
                        Some("GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"),
                        "{} over {wire:?} as {flavor:?}: every 405 keeps Allow",
                        case.name
                    );
                }
            }
        }
    }
    // Admitted controls on both frontends prove the backend records what
    // dispatch delivers, so an absent refused path is evidence rather than an
    // idle backend.
    for (wire, path) in [(Wire::H1, "/control-h1"), (Wire::H2, "/control-h2")] {
        let control = send(port, wire, Flavor::Plain, None, &format!("{path}?a=1"), &[]).await;
        assert_eq!(control.status, StatusCode::OK, "{wire:?} admitted control");
        assert_eq!(
            control.body.as_ref(),
            b"backend",
            "{wire:?} admitted control"
        );
    }
    let paths = backend.paths();
    assert!(
        paths.iter().any(|path| path == "/control-h1")
            && paths.iter().any(|path| path == "/control-h2"),
        "the admitted controls must reach the backend: {paths:?}"
    );
    assert!(
        !paths.iter().any(|path| path.starts_with("/refusal")),
        "no pre-routing refusal may reach backend dispatch: {paths:?}"
    );

    gateway.shutdown();
}

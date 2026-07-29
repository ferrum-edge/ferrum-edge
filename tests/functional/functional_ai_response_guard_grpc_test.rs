//! Functional tests for `ai_response_guard` native-gRPC response inspection
//! (issue #3305).
//!
//! These tests:
//! 1. Start a local gRPC echo backend (h2c HTTP/2) that returns the request
//!    body as the response body, so the test controls the protobuf payload the
//!    guard inspects.
//! 2. Start the gateway binary in file mode with an `ai_response_guard` config
//!    whose `grpc` block enrolls `/test.Greeter/SayHello` against the
//!    checked-in `tests/fixtures/test_validator.bin` descriptor.
//! 3. Assert reject / redact / pass-through behavior end to end over the real
//!    native gRPC data path.
//!
//! Run with:
//! `cargo test --test functional_tests functional_ai_response_guard_grpc -- --ignored --nocapture`

use crate::scaffolding::ports::reserve_port;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http2::Builder as Http2ServerBuilder;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_stream::wrappers::ReceiverStream;

// ============================================================================
// Protobuf fixtures
// ============================================================================

fn descriptor_path() -> String {
    format!(
        "{}/tests/fixtures/test_validator.bin",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn encode_hello_response(message: &str) -> Vec<u8> {
    use prost::Message;
    use prost_reflect::{DescriptorPool, DynamicMessage, Value};

    let bytes = std::fs::read(descriptor_path()).expect("descriptor fixture");
    let pool = DescriptorPool::decode(bytes.as_slice()).expect("descriptor parses");
    let descriptor = pool
        .get_message_by_name("test.HelloResponse")
        .expect("test.HelloResponse");
    let mut msg = DynamicMessage::new(descriptor);
    msg.set_field_by_name("message", Value::String(message.to_string()));
    msg.set_field_by_name("success", Value::Bool(true));
    msg.encode_to_vec()
}

fn decode_hello_message(payload: &[u8]) -> String {
    use prost_reflect::{DescriptorPool, DynamicMessage};

    let bytes = std::fs::read(descriptor_path()).expect("descriptor fixture");
    let pool = DescriptorPool::decode(bytes.as_slice()).expect("descriptor parses");
    let descriptor = pool
        .get_message_by_name("test.HelloResponse")
        .expect("test.HelloResponse");
    let msg = DynamicMessage::decode(descriptor, payload).expect("payload decodes");
    msg.get_field_by_name("message")
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn grpc_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(0);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn gzip_grpc_frame(payload: &[u8]) -> Vec<u8> {
    use flate2::write::GzEncoder;

    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(payload).expect("gzip write");
    let compressed = encoder.finish().expect("gzip finish");
    let mut frame = Vec::with_capacity(5 + compressed.len());
    frame.push(1);
    frame.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
    frame.extend_from_slice(&compressed);
    frame
}

/// Split an identity-framed gRPC body into its message payloads.
fn frame_payloads(body: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset + 5 <= body.len() {
        let length = u32::from_be_bytes([
            body[offset + 1],
            body[offset + 2],
            body[offset + 3],
            body[offset + 4],
        ]) as usize;
        offset += 5;
        if offset + length > body.len() {
            break;
        }
        out.push(body[offset..offset + length].to_vec());
        offset += length;
    }
    out
}

// ============================================================================
// Harness
// ============================================================================

async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    listener.local_addr().unwrap().port()
}

/// Echo backend: returns the request body as the gRPC response body, and
/// mirrors `x-set-grpc-encoding` into the response `grpc-encoding` so the test
/// can drive the compressed-frame path.
///
/// Terminal `grpc-status: 0` is emitted as an HTTP/2 TRAILERS frame after the
/// DATA frame(s). Placing it in the initial HEADERS block is protocol-invalid
/// for ordinary message-carrying responses; the gateway treats that field as
/// transport-managed and will not forward it as a success signal.
async fn start_grpc_echo_backend() -> (u16, tokio::task::JoinHandle<()>) {
    let reservation = reserve_port().await.expect("reserve backend port");
    let port = reservation.port;
    let listener = reservation.into_listener();

    let handle = tokio::spawn(async move {
        loop {
            let (stream, _addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let _ = stream.set_nodelay(true);

            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let builder = Http2ServerBuilder::new(TokioExecutor::new());
                let service = service_fn(|req: Request<Incoming>| async move {
                    let encoding = req
                        .headers()
                        .get("x-set-grpc-encoding")
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_string);
                    let body_bytes = req
                        .into_body()
                        .collect()
                        .await
                        .map(|collected| collected.to_bytes())
                        .unwrap_or_default();

                    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(2);
                    let _ = tx.send(Ok(Frame::data(body_bytes))).await;
                    let mut trailers = hyper::HeaderMap::new();
                    trailers.insert("grpc-status", hyper::header::HeaderValue::from_static("0"));
                    let _ = tx.send(Ok(Frame::trailers(trailers))).await;
                    drop(tx);

                    let mut builder = Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc");
                    if let Some(encoding) = encoding {
                        builder = builder.header("grpc-encoding", encoding);
                    }
                    let response = builder
                        .body(StreamBody::new(ReceiverStream::new(rx)))
                        .unwrap();
                    Ok::<_, hyper::Error>(response)
                });
                if let Err(e) = builder.serve_connection(io, service).await
                    && !format!("{}", e).contains("connection closed")
                {
                    eprintln!("gRPC echo backend error: {}", e);
                }
            });
        }
    });

    (port, handle)
}

fn build_gateway() -> Result<(), Box<dyn std::error::Error>> {
    crate::common::ensure_gateway_built().map_err(|e| -> Box<dyn std::error::Error> { e })
}

fn gateway_binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else {
        "./target/release/ferrum-edge"
    }
}

fn start_gateway(
    config_path: &str,
    http_port: u16,
    admin_port: u16,
) -> Result<std::process::Child, Box<dyn std::error::Error>> {
    let child = std::process::Command::new(gateway_binary_path())
        .env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .env("RUST_LOG", "ferrum_edge=debug")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    Ok(child)
}

async fn wait_for_gateway(
    admin_port: u16,
    gateway_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let health_url = format!("http://127.0.0.1:{}/health", admin_port);
    for _ in 0..60 {
        if let Ok(resp) = client.get(&health_url).send().await
            && resp.status().is_success()
            && tokio::net::TcpStream::connect(("127.0.0.1", gateway_port))
                .await
                .is_ok()
        {
            return Ok(());
        }
        sleep(Duration::from_millis(250)).await;
    }
    Err("Gateway did not become healthy within 15 seconds".into())
}

async fn start_gateway_with_retry(config_path: &str) -> (std::process::Child, u16, u16) {
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let gateway_port = free_port().await;
        let admin_port = free_port().await;
        let mut child = match start_gateway(config_path, gateway_port, admin_port) {
            Ok(child) => child,
            Err(e) => {
                eprintln!(
                    "Gateway spawn attempt {}/{} failed: {}",
                    attempt, MAX_ATTEMPTS, e
                );
                if attempt < MAX_ATTEMPTS {
                    sleep(Duration::from_secs(1)).await;
                }
                continue;
            }
        };
        match wait_for_gateway(admin_port, gateway_port).await {
            Ok(()) => return (child, gateway_port, admin_port),
            Err(e) => {
                eprintln!(
                    "Gateway health attempt {}/{} failed: {}",
                    attempt, MAX_ATTEMPTS, e
                );
                let _ = child.kill();
                let _ = child.wait();
                if attempt < MAX_ATTEMPTS {
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
    panic!("Gateway did not start after {} attempts", MAX_ATTEMPTS);
}

struct GrpcCall {
    status: u16,
    /// Initial response HEADERS (excluding trailers).
    headers: HashMap<String, String>,
    /// Terminal TRAILERS frame values, when present.
    trailers: HashMap<String, String>,
    body: Vec<u8>,
}

impl GrpcCall {
    /// Terminal `grpc-status`: prefer the TRAILERS frame (ordinary responses),
    /// then fall back to initial HEADERS for the gRPC Trailers-Only error shape.
    fn grpc_status(&self) -> &str {
        self.trailers
            .get("grpc-status")
            .or_else(|| self.headers.get("grpc-status"))
            .map(String::as_str)
            .unwrap_or("")
    }

    /// `grpc-status` from the TRAILERS frame only — never from initial HEADERS.
    fn trailer_grpc_status(&self) -> Option<&str> {
        self.trailers.get("grpc-status").map(String::as_str)
    }
}

/// Assert a protocol-correct non-OK gRPC termination: a present, parseable,
/// nonempty, nonzero terminal status. An empty/missing status must fail —
/// `assert_ne!(status, "0")` alone is insufficient because `"" != "0"`.
fn assert_nonzero_terminal_grpc_status(call: &GrpcCall, context: &str) {
    let raw = call.grpc_status();
    assert!(
        !raw.is_empty(),
        "{context}: expected a present terminal grpc-status, got empty/missing \
         (headers={:?}, trailers={:?})",
        call.headers.get("grpc-status"),
        call.trailers.get("grpc-status"),
    );
    let code: u32 = raw.parse().unwrap_or_else(|_| {
        panic!(
            "{context}: grpc-status {raw:?} is not a parseable u32 \
             (headers={:?}, trailers={:?})",
            call.headers.get("grpc-status"),
            call.trailers.get("grpc-status"),
        )
    });
    assert_ne!(
        code,
        0,
        "{context}: expected nonzero terminal grpc-status, got {code} \
         (headers={:?}, trailers={:?})",
        call.headers.get("grpc-status"),
        call.trailers.get("grpc-status"),
    );
}

/// Assert a successful message-carrying gRPC response: `grpc-status: 0` must
/// arrive in terminal trailers. An initial-header-only value is not accepted.
fn assert_ok_trailer_grpc_status(call: &GrpcCall, context: &str) {
    assert_eq!(
        call.trailer_grpc_status(),
        Some("0"),
        "{context}: expected grpc-status: 0 in terminal trailers, got \
         trailer={:?} header={:?}",
        call.trailer_grpc_status(),
        call.headers.get("grpc-status"),
    );
    assert!(
        !call.headers.contains_key("grpc-status"),
        "{context}: message-carrying responses must not expose grpc-status in \
         initial HEADERS (got {:?})",
        call.headers.get("grpc-status"),
    );
}

async fn send_grpc_request(
    gateway_addr: &str,
    path: &str,
    body: &[u8],
    extra_headers: &[(&str, &str)],
) -> Result<GrpcCall, Box<dyn std::error::Error + Send + Sync>> {
    use hyper::client::conn::http2;

    let addr: SocketAddr = gateway_addr.parse()?;
    let stream = tokio::net::TcpStream::connect(addr).await?;
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);

    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), io).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            eprintln!("Client h2 connection error: {}", e);
        }
    });

    let mut req_builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/grpc")
        .header("te", "trailers");
    for (key, value) in extra_headers {
        req_builder = req_builder.header(*key, *value);
    }
    let req = req_builder.body(Full::new(Bytes::from(body.to_vec())))?;
    let response = sender.send_request(req).await?;

    let status = response.status().as_u16();
    let mut headers = HashMap::new();
    for (key, value) in response.headers() {
        if let Ok(text) = value.to_str() {
            headers.insert(key.as_str().to_string(), text.to_string());
        }
    }
    let collected = response.into_body().collect().await?;
    let mut trailers = HashMap::new();
    if let Some(trailer_map) = collected.trailers() {
        for (key, value) in trailer_map {
            if let Ok(text) = value.to_str() {
                trailers.insert(key.as_str().to_string(), text.to_string());
            }
        }
    }

    Ok(GrpcCall {
        status,
        headers,
        trailers,
        body: collected.to_bytes().to_vec(),
    })
}

/// Write a file-mode config with one `ai_response_guard` instance whose `grpc`
/// block enrolls `/test.Greeter/SayHello`.
fn write_guard_config(
    config_path: &std::path::Path,
    backend_port: u16,
    action: &str,
    extra_grpc_config: &str,
) {
    let descriptor = descriptor_path();
    let config = format!(
        r#"
version: "1"
proxies:
  - id: "grpc-guard-proxy"
    listen_path: "/"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false
    auth_mode: single
    plugins:
      - plugin_config_id: "grpc-guard"

consumers: []

plugin_configs:
  - id: "grpc-guard"
    plugin_name: "ai_response_guard"
    scope: proxy
    proxy_id: "grpc-guard-proxy"
    enabled: true
    config:
      action: "{action}"
      pii_patterns: ["email"]
      grpc:
        descriptor_path: "{descriptor}"
{extra_grpc_config}
        methods:
          "/test.Greeter/SayHello":
            response_type: "test.HelloResponse"
"#
    );
    let mut file = std::fs::File::create(config_path).expect("create config file");
    file.write_all(config.as_bytes()).expect("write config");
}

struct Harness {
    gateway: std::process::Child,
    backend: tokio::task::JoinHandle<()>,
    addr: String,
    _temp: TempDir,
}

impl Harness {
    async fn start(action: &str, extra_grpc_config: &str) -> Self {
        build_gateway().expect("build gateway binary");
        let (backend_port, backend) = start_grpc_echo_backend().await;
        let temp = TempDir::new().expect("temp dir");
        let config_path = temp.path().join("config.yaml");
        write_guard_config(&config_path, backend_port, action, extra_grpc_config);
        let (gateway, port, _admin) =
            start_gateway_with_retry(config_path.to_str().expect("utf-8 path")).await;
        Self {
            gateway,
            backend,
            addr: format!("127.0.0.1:{}", port),
            _temp: temp,
        }
    }

    fn shutdown(mut self) {
        let _ = self.gateway.kill();
        let _ = self.gateway.wait();
        self.backend.abort();
    }
}

// ============================================================================
// Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn grpc_guard_passes_clean_unary_response() {
    let harness = Harness::start("reject", "").await;
    let body = grpc_frame(&encode_hello_response("nothing sensitive here"));
    let call = send_grpc_request(&harness.addr, "/test.Greeter/SayHello", &body, &[])
        .await
        .expect("gRPC call");

    assert_eq!(call.status, 200);
    assert_ok_trailer_grpc_status(&call, "clean unary");
    assert_eq!(
        call.body, body,
        "a clean response must be forwarded verbatim"
    );
    harness.shutdown();
}

#[tokio::test]
#[ignore]
async fn grpc_guard_rejects_unary_response_with_pii() {
    let harness = Harness::start("reject", "").await;
    let body = grpc_frame(&encode_hello_response("contact ops@example.com"));
    let call = send_grpc_request(&harness.addr, "/test.Greeter/SayHello", &body, &[])
        .await
        .expect("gRPC call");

    assert_nonzero_terminal_grpc_status(
        &call,
        "a guarded gRPC violation must terminate with a non-OK gRPC status",
    );
    assert!(
        call.body.is_empty(),
        "a gRPC plugin reject must be trailers-only, not an HTTP JSON body"
    );
    harness.shutdown();
}

#[tokio::test]
#[ignore]
async fn grpc_guard_never_inspects_unenrolled_methods() {
    let harness = Harness::start("reject", "").await;
    let body = grpc_frame(&encode_hello_response("contact ops@example.com"));
    let call = send_grpc_request(&harness.addr, "/test.Greeter/Unenrolled", &body, &[])
        .await
        .expect("gRPC call");

    assert_eq!(call.status, 200);
    assert_ok_trailer_grpc_status(&call, "unenrolled method");
    assert_eq!(
        call.body, body,
        "an un-enrolled method must be forwarded untouched"
    );
    harness.shutdown();
}

#[tokio::test]
#[ignore]
async fn grpc_guard_inspects_every_streaming_frame() {
    let harness = Harness::start("reject", "").await;

    let mut clean = grpc_frame(&encode_hello_response("first"));
    clean.extend_from_slice(&grpc_frame(&encode_hello_response("second")));
    let call = send_grpc_request(&harness.addr, "/test.Greeter/SayHello", &clean, &[])
        .await
        .expect("gRPC call");
    assert_ok_trailer_grpc_status(&call, "clean streaming");
    assert_eq!(call.body, clean);

    let mut dirty = grpc_frame(&encode_hello_response("first"));
    dirty.extend_from_slice(&grpc_frame(&encode_hello_response("second")));
    dirty.extend_from_slice(&grpc_frame(&encode_hello_response("ops@example.com")));
    let call = send_grpc_request(&harness.addr, "/test.Greeter/SayHello", &dirty, &[])
        .await
        .expect("gRPC call");
    assert_nonzero_terminal_grpc_status(
        &call,
        "a violation in a later stream frame must still terminate the call",
    );
    harness.shutdown();
}

#[tokio::test]
#[ignore]
async fn grpc_guard_decodes_compressed_frames_and_refuses_unknown_encodings() {
    let harness = Harness::start("reject", "").await;

    let gzipped = gzip_grpc_frame(&encode_hello_response("contact ops@example.com"));
    let call = send_grpc_request(
        &harness.addr,
        "/test.Greeter/SayHello",
        &gzipped,
        &[("x-set-grpc-encoding", "gzip")],
    )
    .await
    .expect("gRPC call");
    assert_nonzero_terminal_grpc_status(
        &call,
        "a gzip-compressed violation must be decoded and rejected",
    );

    let call = send_grpc_request(
        &harness.addr,
        "/test.Greeter/SayHello",
        &gzipped,
        &[("x-set-grpc-encoding", "snappy")],
    )
    .await
    .expect("gRPC call");
    assert_nonzero_terminal_grpc_status(
        &call,
        "an encoding the guard cannot inflate must fail closed",
    );
    harness.shutdown();
}

#[tokio::test]
#[ignore]
async fn grpc_guard_fails_closed_on_malformed_framing() {
    let harness = Harness::start("reject", "").await;
    let mut truncated = grpc_frame(&encode_hello_response("clean"));
    truncated.pop();
    let call = send_grpc_request(&harness.addr, "/test.Greeter/SayHello", &truncated, &[])
        .await
        .expect("gRPC call");
    assert_nonzero_terminal_grpc_status(&call, "truncated gRPC framing must fail closed");
    harness.shutdown();
}

#[tokio::test]
#[ignore]
async fn grpc_guard_fails_closed_on_oversized_messages() {
    let harness = Harness::start("reject", "        max_message_bytes: 8\n").await;
    let body = grpc_frame(&encode_hello_response(
        "a message that is definitely longer",
    ));
    let call = send_grpc_request(&harness.addr, "/test.Greeter/SayHello", &body, &[])
        .await
        .expect("gRPC call");
    assert_nonzero_terminal_grpc_status(
        &call,
        "a message above max_message_bytes must fail closed",
    );
    harness.shutdown();
}

#[tokio::test]
#[ignore]
async fn grpc_guard_redacts_and_reencodes_the_protobuf_response() {
    let harness = Harness::start("redact", "").await;
    let body = grpc_frame(&encode_hello_response("mail ops@example.com today"));
    let call = send_grpc_request(&harness.addr, "/test.Greeter/SayHello", &body, &[])
        .await
        .expect("gRPC call");

    assert_eq!(call.status, 200);
    assert_ok_trailer_grpc_status(&call, "redacted unary");
    let payloads = frame_payloads(&call.body);
    assert_eq!(payloads.len(), 1, "expected one re-encoded response frame");
    let message = decode_hello_message(&payloads[0]);
    assert!(
        !message.contains("ops@example.com"),
        "PII survived redaction: {message}"
    );
    assert!(
        message.contains("[REDACTED:pii:email]"),
        "expected a redaction placeholder, got: {message}"
    );
    harness.shutdown();
}

#[tokio::test]
#[ignore]
async fn grpc_guard_rejects_pii_split_across_streaming_frames() {
    let harness = Harness::start("reject", "").await;
    let mut body = grpc_frame(&encode_hello_response("ops@"));
    body.extend_from_slice(&grpc_frame(&encode_hello_response("example.com")));
    let call = send_grpc_request(&harness.addr, "/test.Greeter/SayHello", &body, &[])
        .await
        .expect("gRPC call");
    assert_nonzero_terminal_grpc_status(
        &call,
        "a blocked email split across frames must still terminate the call",
    );
    harness.shutdown();
}

#[tokio::test]
#[ignore]
async fn grpc_guard_redact_fails_closed_on_cross_frame_only_match() {
    let harness = Harness::start("redact", "").await;
    let mut body = grpc_frame(&encode_hello_response("ops@"));
    body.extend_from_slice(&grpc_frame(&encode_hello_response("example.com")));
    let call = send_grpc_request(&harness.addr, "/test.Greeter/SayHello", &body, &[])
        .await
        .expect("gRPC call");
    assert_nonzero_terminal_grpc_status(
        &call,
        "redact mode must fail closed when a match exists only across frame boundaries",
    );
    assert!(
        call.body.is_empty(),
        "cross-frame-only redaction residual must be trailers-only, not original frames"
    );
    harness.shutdown();
}

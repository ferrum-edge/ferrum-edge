//! Functional tests for `ai_transcript_audit` native-gRPC payload capture
//! (issue #3304), exercised over the REAL proxy data path rather than by
//! calling plugin hooks directly.
//!
//! Issue #3304 requires coverage through live unary and streaming gRPC data
//! paths, so each test here:
//! 1. Starts a local gRPC echo backend (h2c HTTP/2) that returns the request
//!    body as the response body, so the test controls both protobuf payloads.
//! 2. Starts a local HTTP audit collector and points the plugin's batching sink
//!    at it, so the assertion target is the record the gateway actually shipped.
//! 3. Starts the gateway binary in file mode with an `ai_transcript_audit`
//!    config whose `grpc` block enrolls `/test.Greeter/SayHello` against the
//!    checked-in `tests/fixtures/test_validator.bin` descriptor.
//! 4. Drives real native gRPC calls through the gateway and asserts on the
//!    exported record.
//!
//! Assertions are deliberately positive: a real, nonempty, decoded excerpt (or
//! the exact compiled-in omission reason), never merely "the secret is absent"
//! — an empty record would satisfy that trivially.
//!
//! Run with:
//! `cargo test --test functional_tests functional_ai_transcript_audit_grpc -- --ignored --nocapture`

use crate::common::TestGateway;
use crate::scaffolding::ports::reserve_port;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1::Builder as Http1ServerBuilder;
use hyper::server::conn::http2::Builder as Http2ServerBuilder;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::Value;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
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

/// `test.HelloRequest { string name = 1; int32 age = 2; }`.
///
/// `age` is the knob that controls whether the encoded message is valid UTF-8:
/// a negative `int32` encodes as a ten-byte varint of `0xFF` bytes, which is
/// not valid UTF-8 anywhere in the buffer.
///
/// Leaving `age` at the proto3 default (`0`) omits it from the wire, so the
/// encoding is exactly `field 1 = <name>` — byte-identical to a
/// `test.HelloResponse { string message = 1; }`. The echo backend can therefore
/// return the request verbatim and still be a well-formed response of the
/// enrolled response type.
fn encode_hello_request(name: &str, age: i32) -> Vec<u8> {
    use prost::Message;
    use prost_reflect::{DescriptorPool, DynamicMessage, Value as ProtoValue};

    let bytes = std::fs::read(descriptor_path()).expect("descriptor fixture");
    let pool = DescriptorPool::decode(bytes.as_slice()).expect("descriptor parses");
    let descriptor = pool
        .get_message_by_name("test.HelloRequest")
        .expect("test.HelloRequest");
    let mut msg = DynamicMessage::new(descriptor);
    msg.set_field_by_name("name", ProtoValue::String(name.to_string()));
    msg.set_field_by_name("age", ProtoValue::I32(age));
    msg.encode_to_vec()
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
    use std::io::Write;

    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(payload).expect("gzip write");
    let compressed = encoder.finish().expect("gzip finish");
    let mut frame = Vec::with_capacity(5 + compressed.len());
    frame.push(1);
    frame.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
    frame.extend_from_slice(&compressed);
    frame
}

// ============================================================================
// Harness
// ============================================================================

/// Echo backend: returns the request body as the gRPC response body. Terminal
/// `grpc-status: 0` is emitted as an HTTP/2 TRAILERS frame after the DATA
/// frame(s), which is what an ordinary message-carrying gRPC reply looks like.
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
                        .get("grpc-encoding")
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
                    // Echo the request encoding back so the response frames are
                    // self-consistent with what the client sent.
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

/// Collected audit records, newest last. Each POSTed batch is a JSON array.
#[derive(Clone, Default)]
struct CollectedRecords(Arc<Mutex<Vec<Value>>>);

impl CollectedRecords {
    fn push_batch(&self, body: &[u8]) {
        if let Ok(Value::Array(batch)) = serde_json::from_slice::<Value>(body)
            && let Ok(mut guard) = self.0.lock()
        {
            guard.extend(batch);
        }
    }

    fn snapshot(&self) -> Vec<Value> {
        self.0.lock().map(|guard| guard.clone()).unwrap_or_default()
    }

    /// Poll until at least `expected` records have arrived, then return them.
    /// Returns whatever arrived if the wait elapses, so callers assert.
    async fn wait_for(&self, expected: usize) -> Vec<Value> {
        for _ in 0..120 {
            let records = self.snapshot();
            if records.len() >= expected {
                return records;
            }
            sleep(Duration::from_millis(100)).await;
        }
        self.snapshot()
    }
}

/// Local HTTP/1.1 collector standing in for the operator's transcript sink.
async fn start_audit_collector() -> (u16, CollectedRecords, tokio::task::JoinHandle<()>) {
    let reservation = reserve_port().await.expect("reserve collector port");
    let port = reservation.port;
    let listener = reservation.into_listener();
    let records = CollectedRecords::default();

    let served = records.clone();
    let handle = tokio::spawn(async move {
        loop {
            let (stream, _addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let _ = stream.set_nodelay(true);
            let connection_records = served.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(move |req: Request<Incoming>| {
                    let request_records = connection_records.clone();
                    async move {
                        let body = req
                            .into_body()
                            .collect()
                            .await
                            .map(|collected| collected.to_bytes())
                            .unwrap_or_default();
                        request_records.push_batch(&body);
                        Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(200)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from_static(b"{\"status\":\"ok\"}")))
                                .unwrap(),
                        )
                    }
                });
                let _ = Http1ServerBuilder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    (port, records, handle)
}

fn build_gateway() -> Result<(), Box<dyn std::error::Error>> {
    crate::common::ensure_gateway_built().map_err(|e| -> Box<dyn std::error::Error> { e })
}

/// Fragments of a GATEWAY-authored listener bind failure. Every one is a
/// literal piece of a message this binary emits when a listener cannot take its
/// port — `Stream listener bind failed: …`, `Stream listener(s) failed to
/// bind:…`, `Stream listener failed to bind on config reload: …`, or `Proxy
/// listener bind failed: …` chained through a listener task's outer context.
/// `"listener failed"` covers the ADMIN listener, whose message never contains
/// the word "bind": it reads `Admin HTTP listener failed: Address already in
/// use (os error 98)`, unlike the stream/proxy listeners this list was first
/// written for. Without it a lost admin-port race was classified non-retryable
/// and failed the run outright (issue #3660).
const LISTENER_BIND_FAILURE_MARKERS: [&str; 3] =
    ["bind failed", "failed to bind", "listener failed"];

/// Fragments naming the kernel condition a lost bind race actually produces.
const ADDRESS_IN_USE_MARKERS: [&str; 3] = [
    "address already in use",
    "eaddrinuse",
    "is already in use on",
];

/// Whether ONE gateway-authored message reports a listener that lost its port.
///
/// All three terms must be present in the same message: it must be about a
/// listener, it must be a bind failure, and the failure must be address-in-use.
/// A diagnostic that merely quotes one of these phrases — an operator config
/// value, a rejected request body, an error detail — satisfies none of the
/// conjunction on its own.
fn message_reports_listener_bind_race(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("listener")
        && LISTENER_BIND_FAILURE_MARKERS
            .iter()
            .any(|marker| lower.contains(marker))
        && ADDRESS_IN_USE_MARKERS
            .iter()
            .any(|marker| lower.contains(marker))
}

/// The gateway's OWN message for one captured line, or `None` when the line is
/// not a structured gateway event.
///
/// The binary logs through `tracing_subscriber::fmt().json()`, which nests the
/// event message under `fields.message`; its pre-subscriber bootstrap writer
/// emits a flattened top-level `message`. Every other key on those objects —
/// `error`, `target`, span fields, and any operator- or peer-derived detail a
/// structured event attaches — is deliberately NOT read: a config value, a
/// response body, or an error detail carrying "Address already in use" must not
/// be able to buy a rerun of a deterministic startup failure.
fn gateway_authored_message(line: &str) -> Option<String> {
    let event = serde_json::from_str::<Value>(line).ok()?;
    let object = event.as_object()?;
    object
        .get("fields")
        .and_then(Value::as_object)
        .and_then(|fields| fields.get("message"))
        .or_else(|| object.get("message"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// True only when captured startup evidence shows the child lost an ephemeral
/// port bind race. Every other failure — spawn/config errors, non-bind exits,
/// authenticated readiness timeouts while the child is still alive, and any
/// unclassified diagnostic — must stop the outer loop immediately.
///
/// Structured lines are judged on the gateway's own `message` field alone.
/// Bootstrap and other non-JSON output has no field structure to trust, so the
/// complete line must carry the whole conjunction itself. Nothing else is
/// retryable: an unknown failure is never rerun.
fn gateway_startup_failure_is_bind_race(diagnostic: &str) -> bool {
    diagnostic.lines().any(line_reports_listener_bind_race)
}

/// Judge ONE captured line of the harness diagnostic.
fn line_reports_listener_bind_race(line: &str) -> bool {
    match gateway_authored_message(line) {
        // Structured event: only the gateway's own message may vouch for it.
        Some(message) => message_reports_listener_bind_race(&message),
        // Non-JSON output has no field structure to trust, so the complete
        // line must carry the whole conjunction itself.
        None => message_reports_listener_bind_race(line),
    }
}

/// Spawn a file-mode gateway through the shared harness. Each outer-loop
/// iteration gets fresh ports, temp config, and a per-attempt observability
/// token; only gateway-authored listener bind-race evidence is retryable.
async fn spawn_audit_gateway_with_bind_race_retry(
    config_yaml: &str,
) -> Result<TestGateway, Box<dyn std::error::Error + Send + Sync>> {
    const MAX_BIND_RACE_ATTEMPTS: u32 = 3;
    const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);
    let mut last_bind_race = String::new();

    for attempt in 1..=MAX_BIND_RACE_ATTEMPTS {
        match TestGateway::builder()
            .mode_file(config_yaml.to_string())
            .skip_auto_build()
            .max_attempts(1)
            .capture_output()
            .health_timeout(STARTUP_TIMEOUT)
            .log_level("debug")
            .env("RUST_LOG", "ferrum_edge=debug")
            .spawn()
            .await
        {
            Ok(gateway) => return Ok(gateway),
            Err(error) => {
                let diagnostic = error.to_string();
                if !gateway_startup_failure_is_bind_race(&diagnostic) {
                    return Err(
                        format!("gateway startup failed (non-retryable): {diagnostic}").into(),
                    );
                }
                last_bind_race = diagnostic;
                eprintln!(
                    "Gateway bind-race retry {attempt}/{MAX_BIND_RACE_ATTEMPTS}: \
                     address-in-use evidence recorded"
                );
            }
        }
    }

    Err(format!(
        "gateway startup failed after {MAX_BIND_RACE_ATTEMPTS} bind-race retries: {last_bind_race}"
    )
    .into())
}

#[cfg(test)]
mod gateway_startup_classifier_tests {
    use super::gateway_startup_failure_is_bind_race;

    /// The captured-output section the harness appends to a spawn failure.
    fn diagnostic_with(captured: &str) -> String {
        format!(
            "gateway process exited before proving ownership\n\
             --- captured gateway output ---\n\
             {captured}"
        )
    }

    #[test]
    fn accepts_a_structured_listener_bind_race() {
        // `tracing_subscriber::fmt().json()` shape: the gateway's own message
        // is nested under `fields.message`.
        assert!(gateway_startup_failure_is_bind_race(&diagnostic_with(
            r#"{"timestamp":"2026-08-05T00:00:00Z","level":"ERROR","fields":{"message":"Stream listener bind failed: Port 38421 is already in use on 127.0.0.1: Address already in use (os error 48)"},"target":"ferrum_edge::proxy::stream_listener"}"#
        )));
        // Aggregated reconcile failure — the embedded newline stays inside the
        // JSON string, so the event is still one complete line.
        assert!(gateway_startup_failure_is_bind_race(&diagnostic_with(
            r#"{"level":"ERROR","fields":{"message":"Stream listener(s) failed to bind:\nproxy 'edge-tcp' port 38421: Port 38421 is already in use on 127.0.0.1: Address already in use (os error 48)"},"target":"ferrum_edge::proxy"}"#
        )));
        assert!(gateway_startup_failure_is_bind_race(&diagnostic_with(
            r#"{"level":"ERROR","fields":{"message":"Stream listener failed to bind on config reload: Port 38421 is already in use on 127.0.0.1: Address already in use (os error 48)"},"target":"ferrum_edge::proxy"}"#
        )));
    }

    /// Issue #3660. The ADMIN listener's message never contains "bind" — it
    /// reads `<name> failed: Address already in use` — so the original
    /// `["bind failed", "failed to bind"]` conjunction classified a lost
    /// admin-port race as non-retryable and failed the whole run. This is the
    /// exact `fields.message` the gateway emitted on PRs #3599, #3607, #3636,
    /// and #3653.
    #[test]
    fn accepts_a_structured_admin_listener_bind_race() {
        assert!(gateway_startup_failure_is_bind_race(&diagnostic_with(
            r#"{"timestamp":"2026-08-07T10:16:03Z","level":"ERROR","fields":{"message":"Gateway listener task 'Admin HTTP listener' failed: Admin HTTP listener failed: Address already in use (os error 98)"},"target":"ferrum_edge::modes::file"}"#
        )));
    }

    #[test]
    fn accepts_a_non_json_bootstrap_line_carrying_the_whole_conjunction() {
        assert!(gateway_startup_failure_is_bind_race(
            "failed to bind admin listener: EADDRINUSE"
        ));
    }

    /// The masking case this classifier exists to refuse: the phrase appears
    /// only in operator- or peer-controlled text, never in the gateway's own
    /// message for a listener bind.
    #[test]
    fn rejects_address_in_use_text_outside_the_gateway_message() {
        // Sibling field on a structured event (config echo).
        assert!(!gateway_startup_failure_is_bind_race(&diagnostic_with(
            r#"{"level":"ERROR","fields":{"message":"Invalid plugin configuration"},"config":"listener failed to bind: Address already in use","target":"ferrum_edge::config"}"#
        )));
        // Bootstrap writer detail field — `message` names the real failure and
        // the OS text hangs off `error`.
        assert!(!gateway_startup_failure_is_bind_race(&diagnostic_with(
            r#"{"timestamp":"2026-08-05T00:00:00Z","level":"ERROR","target":"ferrum_edge::bootstrap","message":"secret resolution failed","error":"provider listener failed to bind: Address already in use (os error 48)"}"#
        )));
        // A rejected request body quoted back inside a structured event.
        assert!(!gateway_startup_failure_is_bind_race(&diagnostic_with(
            r#"{"level":"WARN","fields":{"message":"Rejected upstream response"},"body":"listener failed to bind: address already in use","target":"ferrum_edge::proxy"}"#
        )));
        // Operator detail nested one level deeper than the message field.
        assert!(!gateway_startup_failure_is_bind_race(&diagnostic_with(
            r#"{"level":"ERROR","fields":{"message":"Plugin validation failed","detail":"listener bind failed: Address already in use"},"target":"ferrum_edge::plugins"}"#
        )));
    }

    /// File mode logs the full gateway-authored anyhow chain for a fallible
    /// listener task. The explicit bind context plus the OS cause is enough to
    /// classify the ephemeral-port race without broadening retry eligibility to
    /// arbitrary task failures that merely mention address-in-use text.
    #[test]
    fn accepts_gateway_listener_task_bind_race_with_full_error_chain() {
        assert!(gateway_startup_failure_is_bind_race(&diagnostic_with(
            r#"{"level":"ERROR","fields":{"message":"Gateway listener task 'HTTP proxy listener' failed: HTTP proxy listener failed: Proxy listener bind failed: Address already in use (os error 98)"},"target":"ferrum_edge::modes::file"}"#
        )));
    }

    /// A listener message that is not an address-in-use bind failure, and an
    /// address-in-use string with nothing tying it to a listener bind, are both
    /// unclassified — and an unclassified failure is never rerun.
    #[test]
    fn rejects_incomplete_conjunctions() {
        assert!(!gateway_startup_failure_is_bind_race(&diagnostic_with(
            r#"{"level":"ERROR","fields":{"message":"Gateway listener task 'HTTP proxy listener' failed: HTTP proxy listener failed"},"target":"ferrum_edge::modes::file"}"#
        )));
        assert!(!gateway_startup_failure_is_bind_race(&diagnostic_with(
            r#"{"level":"ERROR","fields":{"message":"Fatal error: Gateway startup failed: HTTP proxy listener exited before completing startup"},"target":"ferrum_edge"}"#
        )));
        assert!(!gateway_startup_failure_is_bind_race(&diagnostic_with(
            r#"{"level":"ERROR","fields":{"message":"Gateway listener task 'HTTP proxy listener' failed: task panicked with message 'Address already in use'"},"target":"ferrum_edge::modes::file"}"#
        )));
        assert!(!gateway_startup_failure_is_bind_race(
            "Address already in use (os error 48)"
        ));
        // Split across lines is not the same line.
        assert!(!gateway_startup_failure_is_bind_race(&diagnostic_with(
            "listener failed to bind\nAddress already in use (os error 48)"
        )));
    }

    #[test]
    fn rejects_generic_startup_errors() {
        assert!(!gateway_startup_failure_is_bind_race(
            "gateway did not prove ownership of admin port 38421 within 60s \
             (last observation: HTTP 503: identified gateway is not ready yet)"
        ));
        assert!(!gateway_startup_failure_is_bind_race(
            "invalid config: grpc.descriptor_path does not exist"
        ));
        assert!(!gateway_startup_failure_is_bind_race(
            "cargo build spawn failed: No such file or directory"
        ));
    }
}

struct GrpcCall {
    status: u16,
    headers: HashMap<String, String>,
    trailers: HashMap<String, String>,
}

impl GrpcCall {
    fn grpc_status(&self) -> &str {
        self.trailers
            .get("grpc-status")
            .or_else(|| self.headers.get("grpc-status"))
            .map(String::as_str)
            .unwrap_or("")
    }
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
        .uri(format!("http://{addr}{path}"))
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
    })
}

/// Build a file-mode config with one `ai_transcript_audit` instance whose
/// `grpc` block enrolls `/test.Greeter/SayHello`, plus optional extra plugin
/// entries/configs (used to install a `before_proxy` short-circuit).
fn build_audit_config_yaml(
    backend_port: u16,
    collector_port: u16,
    extra_proxy_plugins: &str,
    extra_plugin_configs: &str,
) -> String {
    let descriptor = descriptor_path();
    format!(
        r#"
version: "1"
proxies:
  - id: "grpc-audit-proxy"
    listen_path: "/"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false
    auth_mode: single
    plugins:
      - plugin_config_id: "grpc-audit"
{extra_proxy_plugins}

consumers: []

plugin_configs:
  - id: "grpc-audit"
    plugin_name: "ai_transcript_audit"
    scope: proxy
    proxy_id: "grpc-audit-proxy"
    enabled: true
    config:
      mode: "redacted_body"
      sampling:
        rate: 1.0
      redaction:
        builtins: ["email"]
        hash_redacted_values: false
      sink:
        type: "http"
        endpoint_url: "http://127.0.0.1:{collector_port}/ingest"
        allow_insecure_loopback: true
        batch_size: 1
        flush_interval_ms: 100
      grpc:
        descriptor_path: "{descriptor}"
        methods:
          "/test.Greeter/SayHello":
            request_type: "test.HelloRequest"
            response_type: "test.HelloResponse"
{extra_plugin_configs}
"#
    )
}

// ============================================================================
// Backend-effective method transition fixture
// ============================================================================

/// The one enrolled method, spelled exactly as the excerpt reports it.
const ENROLLED_METHOD: &str = "/test.Greeter/SayHello";

/// Client path whose own method is NOT enrolled and whose backend-effective
/// method is. `/audit/SayHello` parses as `audit/SayHello`; after
/// `strip_listen_path` removes `/audit` and `backend_path` prepends
/// `/test.Greeter`, the backend sees `/test.Greeter/SayHello`.
const BACKEND_ENROLLS_PATH: &str = "/audit/SayHello";

/// Client path that IS the enrolled method but whose backend-effective method
/// is not. Stripping the whole listen path leaves nothing, so `backend_path`
/// alone decides: the backend sees `/test.Greeter/Refuted`.
const BACKEND_REFUTES_PATH: &str = "/test.Greeter/SayHello";

/// Config for the backend-effective enrollment transitions, driven end to end
/// through the real router, the real `grpc_method_router`, and the real native
/// gRPC dispatch — no plugin hooks are called directly.
///
/// `grpc_method_router` is what makes this a lifecycle test rather than a
/// metadata test: it publishes `grpc_full_method` twice, provisionally from the
/// CLIENT path in `on_request_received` and authoritatively from the
/// backend-effective path in `on_backend_path_resolved`. Both proxies are
/// listed in its allow list, so it never rejects here; its only role is to
/// publish the method view `ai_transcript_audit` reads.
///
/// Both plugin instances are global-scoped so the two proxies share one
/// enrollment and one sink, which is what lets a record captured on either
/// proxy be observed on the same collector queue.
fn build_transition_config_yaml(backend_port: u16, collector_port: u16) -> String {
    let descriptor = descriptor_path();
    format!(
        r#"
version: "1"
proxies:
  - id: "grpc-audit-transition-in"
    listen_path: "/audit"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    backend_path: "/test.Greeter"
    strip_listen_path: true
    auth_mode: single

  - id: "grpc-audit-transition-out"
    listen_path: "/test.Greeter/SayHello"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    backend_path: "/test.Greeter/Refuted"
    strip_listen_path: true
    auth_mode: single

consumers: []

plugin_configs:
  - id: "grpc-audit"
    plugin_name: "ai_transcript_audit"
    scope: global
    enabled: true
    config:
      mode: "redacted_body"
      sampling:
        rate: 1.0
      redaction:
        builtins: ["email"]
        hash_redacted_values: false
      sink:
        type: "http"
        endpoint_url: "http://127.0.0.1:{collector_port}/ingest"
        allow_insecure_loopback: true
        batch_size: 1
        flush_interval_ms: 100
      grpc:
        descriptor_path: "{descriptor}"
        methods:
          "/test.Greeter/SayHello":
            request_type: "test.HelloRequest"
            response_type: "test.HelloResponse"

  - id: "grpc-method-policy"
    plugin_name: "grpc_method_router"
    scope: global
    enabled: true
    config:
      allow_methods:
        - "test.Greeter/SayHello"
        - "test.Greeter/Refuted"
"#
    )
}

/// A 100%-abort `fault_injection` instance. Its priority (2940) is after
/// `ai_transcript_audit` (2740), so it is a genuine `before_proxy`
/// short-circuit for an already-staged audit candidate: no backend dispatch,
/// and therefore no final request-body hook.
const ABORT_PROXY_PLUGIN: &str = r#"      - plugin_config_id: "grpc-abort""#;
const ABORT_PLUGIN_CONFIG: &str = r#"  - id: "grpc-abort"
    plugin_name: "fault_injection"
    scope: proxy
    proxy_id: "grpc-audit-proxy"
    enabled: true
    config:
      abort:
        status_code: 503
        percentage: 100.0
"#;

struct Harness {
    gateway: TestGateway,
    backend: tokio::task::JoinHandle<()>,
    collector: tokio::task::JoinHandle<()>,
    records: CollectedRecords,
    addr: String,
}

impl Harness {
    async fn start(extra_proxy_plugins: &str, extra_plugin_configs: &str) -> Self {
        Self::start_with(|backend_port, collector_port| {
            build_audit_config_yaml(
                backend_port,
                collector_port,
                extra_proxy_plugins,
                extra_plugin_configs,
            )
        })
        .await
    }

    /// Start the echo backend and collector, then bring up a gateway whose
    /// file-mode config is built from their live ports.
    async fn start_with(build_config: impl FnOnce(u16, u16) -> String) -> Self {
        build_gateway().expect("build gateway binary");
        let (backend_port, backend) = start_grpc_echo_backend().await;
        let (collector_port, records, collector) = start_audit_collector().await;
        let config_yaml = build_config(backend_port, collector_port);
        let gateway = spawn_audit_gateway_with_bind_race_retry(&config_yaml)
            .await
            .expect("spawn audit gateway");
        let addr = format!("127.0.0.1:{}", gateway.proxy_port);
        Self {
            gateway,
            backend,
            collector,
            records,
            addr,
        }
    }

    async fn plain() -> Self {
        Self::start("", "").await
    }

    fn shutdown(self) {
        // Cleanup is implemented by Drop so assertion panics receive the same
        // treatment as the ordinary success path.
        drop(self);
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.gateway.shutdown();
        self.backend.abort();
        self.collector.abort();
    }
}

/// The single record's decoded request excerpt. Fails loudly rather than
/// degrading to an empty string, so no assertion below can pass vacuously.
fn request_excerpt(record: &Value) -> String {
    assert_eq!(
        record
            .get("request_body_omitted_reason")
            .and_then(Value::as_str),
        None,
        "the request excerpt must not be omitted: {record}"
    );
    let excerpt = record
        .get("request_body")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("record carries no request_body excerpt: {record}"));
    assert!(
        !excerpt.is_empty(),
        "record carries an empty request_body excerpt: {record}"
    );
    excerpt.to_string()
}

// ============================================================================
// Tests
// ============================================================================

/// Live unary path: one framed request through the real native-gRPC dispatch
/// must produce exactly one audit record whose excerpt is a real decoded
/// protobuf projection naming the enrolled method.
#[tokio::test]
#[ignore]
async fn grpc_audit_captures_live_unary_request_and_response() {
    let harness = Harness::plain().await;
    let body = grpc_frame(&encode_hello_request("live-unary-subject", 0));
    let call = send_grpc_request(&harness.addr, "/test.Greeter/SayHello", &body, &[])
        .await
        .expect("gRPC call");
    assert_eq!(call.status, 200);
    assert_eq!(
        call.grpc_status(),
        "0",
        "unary call must succeed end to end"
    );

    let records = harness.records.wait_for(1).await;
    assert_eq!(
        records.len(),
        1,
        "one enrolled unary call must export exactly one audit record: {records:?}"
    );
    let excerpt = request_excerpt(&records[0]);
    assert!(
        excerpt.contains("/test.Greeter/SayHello"),
        "the excerpt must name the normalized enrolled method: {excerpt}"
    );
    assert!(
        excerpt.contains("live-unary-subject"),
        "the excerpt must carry the decoded protobuf string field: {excerpt}"
    );
    assert!(
        records[0]
            .get("request_hash")
            .and_then(Value::as_str)
            .is_some_and(|hash| !hash.is_empty()),
        "a captured request must carry its keyed body hash: {}",
        records[0]
    );
    // The echo backend returns the request frame, so the response side must
    // decode as the enrolled response type against the same descriptor.
    assert_eq!(
        records[0]
            .get("response_body_omitted_reason")
            .and_then(Value::as_str),
        None,
        "the response excerpt must not be omitted: {}",
        records[0]
    );
    assert!(
        records[0]
            .get("response_body")
            .and_then(Value::as_str)
            .is_some_and(|body| body.contains("live-unary-subject")),
        "the response excerpt must carry the decoded echoed field: {}",
        records[0]
    );
    harness.shutdown();
}

/// Live multi-message (streaming-framed) path: every frame of one enrolled
/// request body must appear in the excerpt under its own message index, not
/// just the first.
#[tokio::test]
#[ignore]
async fn grpc_audit_captures_every_frame_of_a_live_multi_message_request() {
    let harness = Harness::plain().await;
    let mut body = grpc_frame(&encode_hello_request("stream-frame-alpha", 0));
    body.extend_from_slice(&grpc_frame(&encode_hello_request("stream-frame-beta", 0)));
    body.extend_from_slice(&grpc_frame(&encode_hello_request("stream-frame-gamma", 0)));

    let call = send_grpc_request(&harness.addr, "/test.Greeter/SayHello", &body, &[])
        .await
        .expect("gRPC call");
    assert_eq!(call.status, 200);
    assert_eq!(call.grpc_status(), "0", "streamed frames must succeed");

    let records = harness.records.wait_for(1).await;
    assert_eq!(records.len(), 1, "expected one audit record: {records:?}");
    let excerpt = request_excerpt(&records[0]);
    for subject in [
        "stream-frame-alpha",
        "stream-frame-beta",
        "stream-frame-gamma",
    ] {
        assert!(
            excerpt.contains(subject),
            "every framed message must be captured, missing {subject}: {excerpt}"
        );
    }
    assert!(
        excerpt.contains("\"index\":2"),
        "each frame must export under its own message index: {excerpt}"
    );
    harness.shutdown();
}

/// Live redaction: a PII value inside a decoded protobuf string must be
/// replaced in the exported excerpt while the surrounding capture stays real.
#[tokio::test]
#[ignore]
async fn grpc_audit_redacts_pii_inside_a_live_decoded_protobuf_string() {
    let harness = Harness::plain().await;
    let body = grpc_frame(&encode_hello_request("escalate for ops@example.com now", 0));
    let call = send_grpc_request(&harness.addr, "/test.Greeter/SayHello", &body, &[])
        .await
        .expect("gRPC call");
    assert_eq!(call.grpc_status(), "0");

    let records = harness.records.wait_for(1).await;
    assert_eq!(records.len(), 1, "expected one audit record: {records:?}");
    let excerpt = request_excerpt(&records[0]);
    assert!(
        !excerpt.contains("ops@example.com"),
        "the live excerpt leaked an email: {excerpt}"
    );
    // Not merely "the secret is absent": the surrounding decoded text must
    // still be there, so the redaction is proven to be surgical rather than a
    // dropped capture.
    assert!(
        excerpt.contains("escalate for") && excerpt.contains("now"),
        "redaction must keep the rest of the decoded string: {excerpt}"
    );
    harness.shutdown();
}

/// Enrollment is the gate: an unenrolled method travelling the same live
/// native-gRPC path must be forwarded with an unchanged client-visible result
/// and export no record at all.
///
/// A configured `grpc` block does buffer this request — the backend-effective
/// method is not decidable before routing, so buffering is selected
/// conservatively and the final request-body hook makes the authoritative call.
/// What must not change is the transcript: no candidate, no record.
#[tokio::test]
#[ignore]
async fn grpc_audit_never_captures_an_unenrolled_live_method() {
    let harness = Harness::plain().await;
    let body = grpc_frame(&encode_hello_request("unenrolled-subject", 0));
    let call = send_grpc_request(&harness.addr, "/test.Greeter/Unenrolled", &body, &[])
        .await
        .expect("gRPC call");
    assert_eq!(call.status, 200);
    assert_eq!(call.grpc_status(), "0", "unenrolled call must pass through");

    // Give the batching sink well past its 100 ms flush interval to prove the
    // absence is real rather than a race.
    sleep(Duration::from_secs(2)).await;
    let records = harness.records.snapshot();
    assert!(
        records.is_empty(),
        "an unenrolled method must not be captured: {records:?}"
    );
    harness.shutdown();
}

/// Backend-effective enrollment, transition IN, over the live data path.
///
/// The client method (`audit/SayHello`) is a well-formed gRPC method that this
/// instance does not enroll, so nothing is staged in `before_proxy`. Routing,
/// listen-path stripping, and `backend_path` then produce
/// `/test.Greeter/SayHello`, `grpc_method_router` republishes it in
/// `on_backend_path_resolved`, and the final request-body hook is the first
/// place the call is known to be auditable. Exactly one record must ship, under
/// the NORMALIZED BACKEND-EFFECTIVE method, carrying the real request and
/// response payloads.
#[tokio::test]
#[ignore]
async fn grpc_audit_captures_a_method_only_the_backend_effective_path_enrolls() {
    let harness = Harness::start_with(build_transition_config_yaml).await;
    let body = grpc_frame(&encode_hello_request("transition-in-subject", 0));
    let call = send_grpc_request(&harness.addr, BACKEND_ENROLLS_PATH, &body, &[])
        .await
        .expect("gRPC call");
    assert_eq!(call.status, 200);
    assert_eq!(
        call.grpc_status(),
        "0",
        "the transitioned call must succeed end to end: headers={:?} trailers={:?}",
        call.headers,
        call.trailers
    );

    let records = harness.records.wait_for(1).await;
    assert_eq!(
        records.len(),
        1,
        "a backend-effective enrolled call must export exactly one record: {records:?}"
    );
    let excerpt = request_excerpt(&records[0]);
    assert!(
        excerpt.contains(&format!("\"grpc_method\":\"{ENROLLED_METHOD}\"")),
        "the record must be filed under the normalized backend-effective method, \
         not the client path {BACKEND_ENROLLS_PATH}: {excerpt}"
    );
    assert!(
        !excerpt.contains(BACKEND_ENROLLS_PATH),
        "the unenrolled client path must not appear as the captured method: {excerpt}"
    );
    assert!(
        excerpt.contains("transition-in-subject"),
        "the excerpt must carry the decoded protobuf string field: {excerpt}"
    );
    assert!(
        records[0]
            .get("request_hash")
            .and_then(Value::as_str)
            .is_some_and(|hash| !hash.is_empty()),
        "a captured request must carry its keyed body hash: {}",
        records[0]
    );
    assert_eq!(
        records[0]
            .get("response_body_omitted_reason")
            .and_then(Value::as_str),
        None,
        "the response excerpt must not be omitted: {}",
        records[0]
    );
    assert!(
        records[0]
            .get("response_body")
            .and_then(Value::as_str)
            .is_some_and(|body| body.contains("transition-in-subject")),
        "the response excerpt must carry the decoded echoed field: {}",
        records[0]
    );
    harness.shutdown();
}

/// Backend-effective enrollment, transition OUT, over the live data path.
///
/// Here the CLIENT path is the enrolled method, so `before_proxy` stages a
/// provisional candidate. `backend_path` then rewrites the call to
/// `/test.Greeter/Refuted`, which this instance does not enroll, and the final
/// request-body hook must discard that staging entry. The request must still
/// reach the backend unchanged, and no record — no excerpt, no hash — may ship
/// for the refuted method.
///
/// The absence is proven by a BARRIER, not a sleep: after the refuted call
/// completes, a sentinel call is driven through the enrolling proxy on the same
/// gateway. The audit policy is global-scoped, so both proxies run the SAME
/// instance and therefore the same sink — a single FIFO queue drained by one
/// worker that awaits each flush before starting the next (`batch_size: 1`
/// makes every record its own awaited delivery). A record captured during the
/// refuted call would therefore be delivered STRICTLY BEFORE the sentinel's, so
/// observing the sentinel as the first and only record is positive proof the
/// refuted call captured nothing.
#[tokio::test]
#[ignore]
async fn grpc_audit_discards_a_candidate_the_backend_effective_method_refutes() {
    let harness = Harness::start_with(build_transition_config_yaml).await;

    let refuted_body = grpc_frame(&encode_hello_request("refuted-subject", 0));
    let refuted = send_grpc_request(&harness.addr, BACKEND_REFUTES_PATH, &refuted_body, &[])
        .await
        .expect("gRPC call");
    assert_eq!(refuted.status, 200);
    assert_eq!(
        refuted.grpc_status(),
        "0",
        "a refuted enrollment must not change what the client sees: \
         headers={:?} trailers={:?}",
        refuted.headers,
        refuted.trailers
    );

    let sentinel_body = grpc_frame(&encode_hello_request("sentinel-subject", 0));
    let sentinel = send_grpc_request(&harness.addr, BACKEND_ENROLLS_PATH, &sentinel_body, &[])
        .await
        .expect("gRPC call");
    assert_eq!(
        sentinel.grpc_status(),
        "0",
        "the sentinel call must succeed so its record is a usable barrier"
    );

    let records = harness.records.wait_for(1).await;
    assert_eq!(
        records.len(),
        1,
        "only the sentinel may be exported; the refuted method must not be captured: {records:?}"
    );
    let excerpt = request_excerpt(&records[0]);
    assert!(
        excerpt.contains(&format!("\"grpc_method\":\"{ENROLLED_METHOD}\"")),
        "the surviving record must be the sentinel's enrolled capture: {excerpt}"
    );
    assert!(
        excerpt.contains("sentinel-subject"),
        "the surviving record must carry the sentinel payload: {excerpt}"
    );
    // No stale candidate and no stale hash: nothing derived from the refuted
    // request may ride along on any exported record.
    for record in &records {
        let serialized = record.to_string();
        assert!(
            !serialized.contains("refuted-subject"),
            "a refuted candidate leaked into an exported record: {serialized}"
        );
        assert!(
            !serialized.contains("Refuted"),
            "the refuted backend-effective method leaked into an exported record: {serialized}"
        );
    }
    harness.shutdown();
}

/// Live gzip framing: a compressed enrolled request must be inflated within
/// the configured bounds and exported as a real decoded excerpt.
#[tokio::test]
#[ignore]
async fn grpc_audit_decodes_a_live_gzip_framed_request() {
    let harness = Harness::plain().await;
    let body = gzip_grpc_frame(&encode_hello_request("gzip-framed-subject", 0));
    let call = send_grpc_request(
        &harness.addr,
        "/test.Greeter/SayHello",
        &body,
        &[("grpc-encoding", "gzip")],
    )
    .await
    .expect("gRPC call");
    assert_eq!(call.grpc_status(), "0");

    let records = harness.records.wait_for(1).await;
    assert_eq!(records.len(), 1, "expected one audit record: {records:?}");
    let excerpt = request_excerpt(&records[0]);
    assert!(
        excerpt.contains("gzip-framed-subject"),
        "a gzip-framed request must export its inflated decoded excerpt: {excerpt}"
    );
    harness.shutdown();
}

/// Binary-safe short-circuit, end to end.
///
/// The request body is deliberately NOT valid UTF-8 (a negative `int32` field),
/// so the UTF-8-only body view the plugin used to depend on does not exist, and
/// a 100%-abort `fault_injection` instance at priority 2940 terminates the
/// request in `before_proxy` — after `ai_transcript_audit` (2740) staged it and
/// before any backend dispatch or final request-body hook. The audit record
/// must still ship, with a real decoded excerpt.
#[tokio::test]
#[ignore]
async fn grpc_audit_captures_a_non_utf8_request_short_circuited_in_before_proxy() {
    let harness = Harness::start(ABORT_PROXY_PLUGIN, ABORT_PLUGIN_CONFIG).await;
    let payload = encode_hello_request("binary-safe-subject", -1);
    assert!(
        std::str::from_utf8(&payload).is_err(),
        "the fixture must be non-UTF-8 for this test to mean anything"
    );
    let body = grpc_frame(&payload);

    let call = send_grpc_request(&harness.addr, "/test.Greeter/SayHello", &body, &[])
        .await
        .expect("gRPC call");
    assert_ne!(
        call.grpc_status(),
        "0",
        "the injected abort must terminate the call before the backend: \
         headers={:?} trailers={:?}",
        call.headers,
        call.trailers
    );

    let records = harness.records.wait_for(1).await;
    assert_eq!(
        records.len(),
        1,
        "a short-circuited enrolled request must still be audited: {records:?}"
    );
    let excerpt = request_excerpt(&records[0]);
    assert!(
        excerpt.contains("/test.Greeter/SayHello"),
        "the excerpt must name the enrolled method: {excerpt}"
    );
    assert!(
        excerpt.contains("binary-safe-subject"),
        "a non-UTF-8 protobuf request must still export its decoded excerpt: {excerpt}"
    );
    harness.shutdown();
}

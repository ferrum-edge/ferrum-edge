//! Live-datapath coverage for aggregate `mcp_gateway` admission of the mediated
//! upstream session header, observed at the real MCP upstream socket on
//! HTTP/1.1, HTTP/2 (h2c prior knowledge), and HTTP/3.
//!
//! The aggregate router places the gateway-selected upstream session id on the
//! backend request. Two later writers can touch that header:
//!
//!   * a later `request_transformer` header rule (priority 3000) during
//!     `before_proxy` — the request is refused with JSON-RPC `-32014` before
//!     any backend request is admitted;
//!   * a `serverless_function` `pre_proxy` header overlay (priority 3025),
//!     merged in the finalized-request-egress phase after the final
//!     request-body hook — the gateway's final backend-header policy re-asserts
//!     exactly the recorded session, so the overlay value never reaches the
//!     upstream.
//!
//! The same harness drives an `mcp_gateway` OpenAPI bridge server (issue
//! #5906) on all three frontends: a `tools/call` becomes the operation's own
//! REST request (backend method, path, and query) and the backend answer,
//! including a chunked one of unknown length, is returned as the JSON-RPC
//! tool result.
//!
//! Run: `cargo build --bin ferrum-edge && cargo test --test functional_tests
//! functional_mcp_gateway -- --ignored --nocapture`

use crate::scaffolding::port_registry::TestSocket;

use crate::scaffolding::clients::{GetOptions, Http3Client};
use crate::scaffolding::{reserve_colocated_tcp_udp, reserve_port};

use bytes::Bytes;
use ferrum_edge::admin::jwt_auth::{JwtConfig, JwtManager};
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::modes::file::ServeOptions;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

const TEST_NAMESPACE: &str = "ferrum";
const TEST_JWT_SECRET: &str = "ferrum-edge-mcp-admission-secret-000000000";
const TEST_JWT_ISSUER: &str = "ferrum-edge-mcp-admission";
const PROTOCOL_VERSION: &str = "2025-11-25";
const SESSION_HEADER: &str = "mcp-session-id";
/// The session id the scripted upstream mints at `initialize`; the only value
/// the gateway may ever present to it.
const UPSTREAM_SESSION: &str = "upstream-session";
/// A session value a later request-header rule tries to substitute.
const TRANSFORMER_SESSION: &str = "transformer-substituted-session";
/// A session value a `pre_proxy` function response tries to inject.
const FUNCTION_SESSION: &str = "function-injected-session";
/// Routed to the upstream through `capabilities.passthrough_unknown_methods`.
const ROUTED_METHOD: &str = "session/echo";
const MAX_MESSAGE_BYTES: usize = 256 * 1024;

// ===========================================================================
// Scripted MCP upstream
// ===========================================================================

/// One request the upstream received: its JSON-RPC method and raw head.
#[derive(Clone, Debug)]
struct Captured {
    method: String,
    head: String,
}

impl Captured {
    /// Every value of the session header on the wire, any spelling.
    fn session_values(&self) -> Vec<String> {
        self.head
            .lines()
            .filter_map(|line| line.split_once(':'))
            .filter(|(name, _)| name.trim().eq_ignore_ascii_case(SESSION_HEADER))
            .map(|(_, value)| value.trim().to_string())
            .collect()
    }
}

type Captures = Arc<Mutex<Vec<Captured>>>;

/// Answer MCP over HTTP/1.1: `initialize` mints [`UPSTREAM_SESSION`],
/// notifications get an empty `202`, and every other request is echoed back as
/// an empty JSON-RPC result carrying the request's own id.
async fn serve_mcp_upstream(listener: TcpListener, captures: Captures) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let captures = Arc::clone(&captures);
        tokio::spawn(async move {
            let mut pending = Vec::new();
            while let Some((head, body)) = read_one_http_request(&mut stream, &mut pending).await {
                let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                let method = parsed["method"].as_str().unwrap_or_default().to_string();
                {
                    let mut captured = captures.lock().expect("captures lock");
                    captured.push(Captured {
                        method: method.clone(),
                        head,
                    });
                }
                let written = match parsed.get("id") {
                    None => write_http_response(&mut stream, 202, &[], "").await,
                    Some(id) if method == "initialize" => {
                        let payload = json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}}
                        });
                        let extra = [(SESSION_HEADER, UPSTREAM_SESSION)];
                        write_http_response(&mut stream, 200, &extra, &payload.to_string()).await
                    }
                    Some(id) => {
                        let payload = json!({"jsonrpc": "2.0", "id": id, "result": {}});
                        write_http_response(&mut stream, 200, &[], &payload.to_string()).await
                    }
                };
                if written.is_err() {
                    return;
                }
            }
        });
    }
}

/// A REST backend for the OpenAPI bridge: records each request head, answers
/// `GET` with a chunked JSON body of unknown length and every other method
/// with a `Content-Length` one.
async fn serve_rest_backend(listener: TcpListener, captures: Captures) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let captures = Arc::clone(&captures);
        tokio::spawn(async move {
            let mut pending = Vec::new();
            while let Some((head, _)) = read_one_http_request(&mut stream, &mut pending).await {
                let method = head.split(' ').next().unwrap_or_default().to_string();
                {
                    let mut captured = captures.lock().expect("captures lock");
                    captured.push(Captured {
                        method: method.clone(),
                        head,
                    });
                }
                let written = if method == "GET" {
                    write_chunked_json(&mut stream, r#"{"id":"7","name":"Rex"}"#).await
                } else {
                    write_http_response(&mut stream, 200, &[], r#"{"deleted":"7"}"#).await
                };
                if written.is_err() {
                    return;
                }
            }
        });
    }
}

/// Answer 200 with `body` in two chunks and no `Content-Length`.
async fn write_chunked_json(stream: &mut TcpStream, body: &str) -> std::io::Result<()> {
    let (first, rest) = body.split_at(body.len() / 2);
    let mut wire = String::from("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n");
    wire.push_str("Transfer-Encoding: chunked\r\n\r\n");
    for chunk in [first, rest] {
        wire.push_str(&format!("{:x}\r\n{chunk}\r\n", chunk.len()));
    }
    wire.push_str("0\r\n\r\n");
    stream.write_all(wire.as_bytes()).await?;
    stream.flush().await
}

/// Answer every `pre_proxy` invocation with a header overlay that tries to
/// replace the mediated upstream session.
async fn serve_function(listener: TcpListener) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            let mut pending = Vec::new();
            while read_one_http_request(&mut stream, &mut pending)
                .await
                .is_some()
            {
                let payload = json!({ "headers": { "mcp-session-id": FUNCTION_SESSION } });
                if write_http_response(&mut stream, 200, &[], &payload.to_string())
                    .await
                    .is_err()
                {
                    return;
                }
            }
        });
    }
}

/// Read one HTTP/1.1 request, returning its head and exactly `Content-Length`
/// body bytes; any pipelined remainder stays in `pending`.
async fn read_one_http_request(
    stream: &mut TcpStream,
    pending: &mut Vec<u8>,
) -> Option<(String, Vec<u8>)> {
    let mut chunk = [0u8; 8192];
    loop {
        if let Some(offset) = pending.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = std::str::from_utf8(&pending[..offset]).ok()?.to_string();
            let length = content_length(&head)?;
            let need = offset + 4 + length;
            if pending.len() >= need {
                let body = pending[offset + 4..need].to_vec();
                pending.drain(..need);
                return Some((head, body));
            }
        }
        if pending.len() > MAX_MESSAGE_BYTES {
            return None;
        }
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        pending.extend_from_slice(&chunk[..read]);
    }
}

fn content_length(head: &str) -> Option<usize> {
    let mut length = Some(0usize);
    for line in head.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("transfer-encoding") {
            return None;
        }
        if name.trim().eq_ignore_ascii_case("content-length") {
            length = value.trim().parse::<usize>().ok();
        }
    }
    length.filter(|value| *value <= MAX_MESSAGE_BYTES)
}

async fn write_http_response(
    stream: &mut TcpStream,
    status: u16,
    extra_headers: &[(&str, &str)],
    body: &str,
) -> std::io::Result<()> {
    let reason = if status == 200 { "OK" } else { "Accepted" };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in extra_headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.flush().await
}

// ===========================================================================
// Gateway harness
// ===========================================================================

/// Which backend the fixture serves behind the proxy.
#[derive(Clone, Copy, PartialEq)]
enum Backend {
    /// A scripted MCP upstream (the aggregate router's `upstream_url`).
    McpUpstream,
    /// A REST API behind an OpenAPI bridge server.
    Rest,
}

#[derive(Clone, Copy, PartialEq)]
enum LaterWriter {
    /// A `request_transformer` header rule replaces the session header.
    RequestTransformer,
    /// A `serverless_function` `pre_proxy` overlay injects the session header.
    FunctionOverlay,
}

struct Fixture {
    http_port: u16,
    https_port: u16,
    shutdown_tx: watch::Sender<bool>,
    join: JoinHandle<()>,
    tasks: Vec<JoinHandle<()>>,
    captures: Captures,
}

impl Fixture {
    async fn start(writer: LaterWriter) -> Self {
        Self::start_with(Backend::McpUpstream, |upstream_port, function_port| {
            admission_config(writer, upstream_port, function_port)
        })
        .await
    }

    async fn start_with(backend: Backend, config: impl FnOnce(u16, u16) -> GatewayConfig) -> Self {
        let upstream = TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind MCP upstream");
        let upstream_port = upstream.local_addr().expect("upstream addr").port();
        let function = TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind function");
        let function_port = function.local_addr().expect("function addr").port();
        let captures: Captures = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&captures);
        let backend_task = match backend {
            Backend::McpUpstream => tokio::spawn(serve_mcp_upstream(upstream, captured)),
            Backend::Rest => tokio::spawn(serve_rest_backend(upstream, captured)),
        };
        let tasks = vec![backend_task, tokio::spawn(serve_function(function))];

        let http = reserve_port().await.expect("reserve http");
        let (https_tcp, https_udp) = reserve_colocated_tcp_udp().await.expect("reserve https");
        let admin = reserve_port().await.expect("reserve admin");
        let http_port = http.port;
        let https_port = https_tcp.port;
        let env_config = EnvConfig {
            mode: OperatingMode::File,
            log_level: "warn".to_string(),
            proxy_http_port: http_port,
            proxy_https_port: https_port,
            admin_http_port: admin.port,
            admin_https_port: 0,
            admin_jwt_secret: Some(TEST_JWT_SECRET.to_string()),
            admin_jwt_issuer: TEST_JWT_ISSUER.to_string(),
            frontend_tls_cert_path: Some("tests/certs/server.crt".to_string()),
            frontend_tls_key_path: Some("tests/certs/server.key".to_string()),
            enable_http3: true,
            pool_warmup_enabled: false,
            shutdown_drain_seconds: 0,
            max_connections: 0,
            namespace: TEST_NAMESPACE.to_string(),
            ..EnvConfig::default()
        };
        let jwt_manager = JwtManager::new(JwtConfig {
            secret: TEST_JWT_SECRET.to_string(),
            issuer: TEST_JWT_ISSUER.to_string(),
            audience: None,
            max_ttl_seconds: 3600,
            algorithm: jsonwebtoken::Algorithm::HS256,
        });
        let options = ServeOptions {
            proxy_http: Some(http.into_listener()),
            proxy_https: Some(https_tcp.into_listener()),
            admin_http: Some(admin.into_listener()),
            admin_jwt_manager: Some(jwt_manager),
            skip_initial_capability_refresh: true,
            ..ServeOptions::default()
        };
        drop(https_udp);

        let config = config(upstream_port, function_port);
        let (shutdown_tx, _) = watch::channel(false);
        let handles =
            ferrum_edge::modes::file::serve(env_config, config, options, shutdown_tx.clone())
                .await
                .expect("start MCP admission gateway");
        let join = tokio::spawn(async move {
            if let Err(error) = handles.join().await {
                eprintln!("in-process MCP admission gateway listener panicked: {error}");
            }
        });

        Self {
            http_port,
            https_port,
            shutdown_tx,
            join,
            tasks,
            captures,
        }
    }

    /// Requests the upstream received for the routed method.
    fn routed(&self) -> Vec<Captured> {
        self.captures
            .lock()
            .expect("captures lock")
            .iter()
            .filter(|captured| captured.method == ROUTED_METHOD)
            .cloned()
            .collect()
    }

    /// Every request the backend received.
    fn received(&self) -> Vec<Captured> {
        self.captures.lock().expect("captures lock").clone()
    }

    fn clear(&self) {
        self.captures.lock().expect("captures lock").clear();
    }

    /// Initialize a fresh downstream session, then send one routed call on it.
    async fn call(&self, protocol: &str) -> (u16, Value) {
        let session = self.post(protocol, None, &initialize_body()).await;
        assert_eq!(session.0, 200, "{protocol}: initialize must succeed");
        let session_id = session.2.expect("initialize mints a downstream session");
        let (status, body, _) = self
            .post(protocol, Some(&session_id), &routed_call_body())
            .await;
        (status, body)
    }

    async fn post(
        &self,
        protocol: &str,
        session_id: Option<&str>,
        body: &Value,
    ) -> (u16, Value, Option<String>) {
        let bytes = serde_json::to_vec(body).expect("serialize JSON-RPC body");
        if protocol == "HTTP/3" {
            return self.post_h3(session_id, bytes).await;
        }
        let builder = reqwest::Client::builder().timeout(Duration::from_secs(20));
        let builder = if protocol == "HTTP/2" {
            builder.http2_prior_knowledge()
        } else {
            builder.http1_only()
        };
        let client = builder.build().expect("build client");
        let mut request = client
            .post(format!("http://127.0.0.1:{}/mcp", self.http_port))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", PROTOCOL_VERSION)
            .body(bytes);
        if let Some(session_id) = session_id {
            request = request.header(SESSION_HEADER, session_id);
        }
        let response = request.send().await.expect("JSON-RPC POST");
        let status = response.status().as_u16();
        let session = header_string(response.headers());
        let text = response.text().await.expect("JSON-RPC POST body");
        (status, parse_json(&text), session)
    }

    async fn post_h3(
        &self,
        session_id: Option<&str>,
        bytes: Vec<u8>,
    ) -> (u16, Value, Option<String>) {
        let client = Http3Client::insecure().expect("h3 client");
        let url = format!("https://localhost:{}/mcp", self.https_port);
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            let mut options = GetOptions::default()
                .method(http::Method::POST)
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .header("mcp-protocol-version", PROTOCOL_VERSION)
                .body(Bytes::from(bytes.clone()));
            if let Some(session_id) = session_id {
                options = options.header(SESSION_HEADER, session_id.to_string());
            }
            match client.get_with_options(&url, options).await {
                Ok(response) => {
                    let session = header_string(&response.headers);
                    let body = parse_json(&response.body_text());
                    return (response.status.as_u16(), body, session);
                }
                Err(_) if std::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => panic!("H3 MCP request did not complete: {error}"),
            }
        }
    }

    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(10), self.join).await;
        for task in self.tasks {
            task.abort();
        }
    }
}

fn header_string(headers: &http::HeaderMap) -> Option<String> {
    headers
        .get(SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

fn parse_json(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|_| panic!("expected a JSON body, got: {text}"))
}

fn initialize_body() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": "init",
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "ferrum-functional-admission", "version": "1"}
        }
    })
}

fn routed_call_body() -> Value {
    json!({ "jsonrpc": "2.0", "id": 7, "method": ROUTED_METHOD, "params": {} })
}

fn admission_config(writer: LaterWriter, upstream_port: u16, function_port: u16) -> GatewayConfig {
    let later = match writer {
        LaterWriter::RequestTransformer => json!({
            "id": "mcp-admission-later",
            "namespace": TEST_NAMESPACE,
            "plugin_name": "request_transformer",
            "scope": "proxy",
            "proxy_id": "mcp-admission",
            "enabled": true,
            "config": {
                "rules": [{
                    "operation": "update",
                    "target": "header",
                    "key": "Mcp-Session-Id",
                    "value": TRANSFORMER_SESSION
                }]
            }
        }),
        LaterWriter::FunctionOverlay => json!({
            "id": "mcp-admission-later",
            "namespace": TEST_NAMESPACE,
            "plugin_name": "serverless_function",
            "scope": "proxy",
            "proxy_id": "mcp-admission",
            "enabled": true,
            "config": {
                "provider": "gcp_cloud_functions",
                "mode": "pre_proxy",
                "function_url": format!("http://127.0.0.1:{function_port}/function"),
                "timeout_ms": 5000
            }
        }),
    };
    serde_json::from_value(json!({
        "version": "1",
        "proxies": [{
            "id": "mcp-admission",
            "namespace": TEST_NAMESPACE,
            "listen_path": "/mcp",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": upstream_port,
            "strip_listen_path": false,
            "pool_enable_http2": false,
            "plugins": [
                {"plugin_config_id": "mcp-admission-gw"},
                {"plugin_config_id": "mcp-admission-later"}
            ]
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [
            {
                "id": "mcp-admission-gw",
                "namespace": TEST_NAMESPACE,
                "plugin_name": "mcp_gateway",
                "scope": "proxy",
                "proxy_id": "mcp-admission",
                "enabled": true,
                "config": {
                    "enabled": true,
                    "mode": "aggregate_router",
                    "endpoint": {"path": "/mcp", "protocol_versions": [PROTOCOL_VERSION]},
                    "servers": {
                        "echo": {
                            "upstream_url": format!("http://127.0.0.1:{upstream_port}/mcp"),
                            "namespace": "echo",
                            "enabled": true,
                            "expose_tools": true
                        }
                    },
                    "sessions": {"initialize_upstreams": "lazy"},
                    "capabilities": {"passthrough_unknown_methods": true},
                    "policy": {"default_action": "allow"}
                }
            },
            later
        ]
    }))
    .expect("MCP admission config is valid")
}

/// An `aggregate_router` gateway whose only server is an OpenAPI bridge over
/// this proxy's own REST backend.
fn bridge_config(backend_port: u16) -> GatewayConfig {
    let pet_id = json!({
        "name": "petId",
        "in": "path",
        "required": true,
        "schema": {"type": "string"}
    });
    let verbose = json!({"name": "verbose", "in": "query", "schema": {"type": "boolean"}});
    serde_json::from_value(json!({
        "version": "1",
        "proxies": [{
            "id": "mcp-bridge",
            "namespace": TEST_NAMESPACE,
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
            "pool_enable_http2": false,
            "plugins": [{"plugin_config_id": "mcp-bridge-gw"}]
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "mcp-bridge-gw",
            "namespace": TEST_NAMESPACE,
            "plugin_name": "mcp_gateway",
            "scope": "proxy",
            "proxy_id": "mcp-bridge",
            "enabled": true,
            "config": {
                "mode": "aggregate_router",
                "endpoint": {"path": "/mcp", "protocol_versions": [PROTOCOL_VERSION]},
                "discovery": {"on_new_tool": "allow", "on_schema_change": "allow"},
                "policy": {"default_action": "allow"},
                "servers": {
                    "petstore": {
                        "namespace": "pets",
                        "openapi": {"operations": [
                            {
                                "name": "getPet",
                                "method": "GET",
                                "path": "/pets/{petId}",
                                "parameters": [pet_id.clone(), verbose]
                            },
                            {
                                "name": "deletePet",
                                "method": "DELETE",
                                "path": "/pets/{petId}",
                                "parameters": [pet_id]
                            }
                        ]}
                    }
                }
            }
        }]
    }))
    .expect("MCP bridge config is valid")
}

fn bridge_call_body(id: i64, name: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments}
    })
}

// ===========================================================================
// Tests
// ===========================================================================

/// A later request-header rule that swaps the mediated upstream session is
/// refused before any backend request is admitted, on every frontend.
#[ignore]
#[tokio::test]
async fn functional_mcp_gateway_admission_refuses_a_later_session_header_rewrite_on_h1_h2_h3() {
    let fixture = Fixture::start(LaterWriter::RequestTransformer).await;
    for protocol in ["HTTP/1.1", "HTTP/2", "HTTP/3"] {
        fixture.clear();
        let (status, body) = fixture.call(protocol).await;
        assert_eq!(status, 200, "{protocol}: JSON-RPC refusal rides HTTP 200");
        assert_eq!(
            body["error"]["code"],
            json!(-32014),
            "{protocol}: a swapped upstream session must be refused: {body}"
        );
        assert_eq!(body["id"], json!(7), "{protocol}: names the call");
        assert!(
            fixture.routed().is_empty(),
            "{protocol}: the refused call must never reach the upstream"
        );
    }
    fixture.shutdown().await;
}

/// A `pre_proxy` function overlay merged after the final request-body hook
/// cannot replace the mediated upstream session: the upstream sees exactly the
/// session it minted, once, on every frontend.
#[ignore]
#[tokio::test]
async fn functional_mcp_gateway_admission_reasserts_session_over_a_function_overlay() {
    let fixture = Fixture::start(LaterWriter::FunctionOverlay).await;
    for protocol in ["HTTP/1.1", "HTTP/2", "HTTP/3"] {
        fixture.clear();
        let (status, body) = fixture.call(protocol).await;
        assert_eq!(status, 200, "{protocol}: routed call succeeds: {body}");
        assert_eq!(body["id"], json!(7), "{protocol}: {body}");
        assert!(body.get("error").is_none(), "{protocol}: {body}");
        let routed = fixture.routed();
        assert_eq!(routed.len(), 1, "{protocol}: exactly one routed request");
        assert_eq!(
            routed[0].session_values(),
            vec![UPSTREAM_SESSION.to_string()],
            "{protocol}: the upstream must see only its own session:\n{}",
            routed[0].head
        );
        assert!(
            !routed[0].head.contains(FUNCTION_SESSION),
            "{protocol}: the function overlay value must not reach the upstream"
        );
    }
    fixture.shutdown().await;
}

/// An OpenAPI bridge `tools/call` on the HTTP/1.1, HTTP/2, and native HTTP/3
/// frontends runs as the operation's own REST request: the backend sees the
/// bridged method, path, and query (never the MCP `POST` or its transport
/// headers), and the client gets the converted JSON-RPC result on HTTP 200,
/// also when the backend answers with a chunked body of unknown length.
#[ignore]
#[tokio::test]
async fn functional_mcp_gateway_openapi_bridge_call_on_h1_h2_h3() {
    let config = |backend_port: u16, _: u16| bridge_config(backend_port);
    let fixture = Fixture::start_with(Backend::Rest, config).await;
    for protocol in ["HTTP/1.1", "HTTP/2", "HTTP/3"] {
        fixture.clear();
        let session = fixture.post(protocol, None, &initialize_body()).await;
        assert_eq!(session.0, 200, "{protocol}: initialize must succeed");
        let session_id = session.2.expect("initialize mints a downstream session");

        let arguments = json!({"petId": "7", "verbose": true});
        let call = bridge_call_body(8, "pets.getPet", arguments);
        let (status, body, _) = fixture.post(protocol, Some(&session_id), &call).await;
        assert_eq!(status, 200, "{protocol}: {body}");
        assert_eq!(body["id"], json!(8), "{protocol}: {body}");
        assert_eq!(
            body["result"]["isError"],
            json!(false),
            "{protocol}: {body}"
        );
        assert_eq!(
            body["result"]["structuredContent"],
            json!({"id": "7", "name": "Rex"}),
            "{protocol}: the chunked backend body is converted: {body}"
        );

        let call = bridge_call_body(9, "pets.deletePet", json!({"petId": "7"}));
        let (status, body, _) = fixture.post(protocol, Some(&session_id), &call).await;
        assert_eq!(status, 200, "{protocol}: {body}");
        assert_eq!(body["id"], json!(9), "{protocol}: {body}");
        assert_eq!(
            body["result"]["structuredContent"],
            json!({"deleted": "7"}),
            "{protocol}: {body}"
        );

        let received = fixture.received();
        let request_lines: Vec<&str> = received
            .iter()
            .map(|request| request.head.lines().next().unwrap_or_default())
            .collect();
        assert_eq!(
            request_lines,
            vec![
                "GET /pets/7?verbose=true HTTP/1.1",
                "DELETE /pets/7 HTTP/1.1"
            ],
            "{protocol}: the backend sees the bridged requests only"
        );
        for request in &received {
            let head = request.head.to_ascii_lowercase();
            assert!(
                !head.contains("mcp-session-id") && !head.contains("mcp-protocol-version"),
                "{protocol}: MCP transport headers never reach the REST backend:\n{}",
                request.head
            );
            assert!(
                head.contains("accept-encoding: identity"),
                "{protocol}: the bridged request asks for an identity body:\n{}",
                request.head
            );
        }
    }
    fixture.shutdown().await;
}

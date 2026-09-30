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
//! The bridge fixture also runs under the AI governance stack (issue #5908):
//! `key_auth`, `ai_transcript_audit`, and an `mcp_tool_calls` `rate_limiting`
//! in front of the gateway, proving that only `tools/call` spends a consumer's
//! budget and that every call is audited with the consumer, the public tool
//! name, and its JSON-RPC outcome.
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
    body: Vec<u8>,
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
                        body: body.clone(),
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
                    Some(id) if method == "tools/list" => {
                        let payload = json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "tools": [{
                                    "name": "echo",
                                    "inputSchema": {"type": "object"}
                                }]
                            }
                        });
                        write_http_response(&mut stream, 200, &[], &payload.to_string()).await
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
            while let Some((head, body)) = read_one_http_request(&mut stream, &mut pending).await {
                let method = head.split(' ').next().unwrap_or_default().to_string();
                {
                    let mut captured = captures.lock().expect("captures lock");
                    captured.push(Captured {
                        method: method.clone(),
                        head,
                        body,
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

/// Transcript-audit records received by [`serve_audit_collector`].
type AuditRecords = Arc<Mutex<Vec<Value>>>;

/// A transcript-audit sink: every POSTed batch is a JSON array of records.
async fn serve_audit_collector(listener: TcpListener, records: AuditRecords) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let records = Arc::clone(&records);
        tokio::spawn(async move {
            let mut pending = Vec::new();
            while let Some((_, body)) = read_one_http_request(&mut stream, &mut pending).await {
                if let Ok(Value::Array(batch)) = serde_json::from_slice::<Value>(&body) {
                    records.lock().expect("records lock").extend(batch);
                }
                if write_http_response(&mut stream, 200, &[], "{}")
                    .await
                    .is_err()
                {
                    return;
                }
            }
        });
    }
}

/// Poll the collector until it holds at least `expected` records.
async fn wait_for_audit_records(records: &AuditRecords, expected: usize) -> Vec<Value> {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let snapshot = records.lock().expect("records lock").clone();
        if snapshot.len() >= expected || std::time::Instant::now() >= deadline {
            return snapshot;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
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

    /// One HTTP/1.1 JSON-RPC POST carrying `extra` request headers, returning
    /// the status, the JSON body, and the response headers.
    async fn post_h1_with(
        &self,
        session_id: Option<&str>,
        body: &Value,
        extra: &[(&str, &str)],
    ) -> (u16, Value, http::HeaderMap) {
        self.post_h1_method_with(http::Method::POST, session_id, body, extra)
            .await
    }

    async fn post_h1_method_with(
        &self,
        method: http::Method,
        session_id: Option<&str>,
        body: &Value,
        extra: &[(&str, &str)],
    ) -> (u16, Value, http::HeaderMap) {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .http1_only()
            .build()
            .expect("build client");
        let bytes = serde_json::to_vec(body).expect("serialize JSON-RPC body");
        let mut request = client
            .request(method, format!("http://127.0.0.1:{}/mcp", self.http_port))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", PROTOCOL_VERSION)
            .body(bytes);
        if let Some(session_id) = session_id {
            request = request.header(SESSION_HEADER, session_id);
        }
        for (name, value) in extra {
            request = request.header(*name, *value);
        }
        let response = request.send().await.expect("JSON-RPC POST");
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let text = response.text().await.expect("JSON-RPC POST body");
        (status, parse_json(&text), headers)
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

fn shielded_admission_config(upstream_port: u16) -> GatewayConfig {
    let mut config = serde_json::to_value(admission_config(
        LaterWriter::RequestTransformer,
        upstream_port,
        0,
    ))
    .expect("serialize admission config");
    config["proxies"][0]["plugins"] = json!([
        {"plugin_config_id": "mcp-admission-gw"},
        {"plugin_config_id": "mcp-admission-shield"}
    ]);
    let configs = config["plugin_configs"]
        .as_array_mut()
        .expect("plugin configs");
    configs.retain(|plugin| plugin["id"] == "mcp-admission-gw");
    configs.push(json!({
        "id": "mcp-admission-shield",
        "namespace": TEST_NAMESPACE,
        "plugin_name": "ai_prompt_shield",
        "scope": "proxy",
        "proxy_id": "mcp-admission",
        "enabled": true,
        "config": {"action": "redact", "scan_fields": "mcp_arguments", "patterns": ["email"]}
    }));
    serde_json::from_value(config).expect("shielded admission config is valid")
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

/// API key of the one agent Consumer in [`governed_bridge_config`].
const AGENT_KEY: &str = "agent-alice-key";

/// [`bridge_config`]'s OpenAPI bridge behind the AI governance stack:
/// `key_auth`, `ai_transcript_audit` exporting to the collector on
/// `collector_port`, and a consumer-keyed `rate_limiting` that counts only
/// `tools/call` (three per minute).
fn governed_bridge_config(backend_port: u16, collector_port: u16) -> GatewayConfig {
    let plugin = |id: &str, plugin_name: &str, config: Value| {
        json!({
            "id": id,
            "namespace": TEST_NAMESPACE,
            "plugin_name": plugin_name,
            "scope": "proxy",
            "proxy_id": "mcp-governed",
            "enabled": true,
            "config": config
        })
    };
    let pet_id = json!({
        "name": "petId",
        "in": "path",
        "required": true,
        "schema": {"type": "string"}
    });
    let audit = json!({
        "mode": "redacted_body",
        "sampling": {"rate": 1.0},
        "privacy": {"include_consumer_username": true},
        "sink": {
            "type": "http",
            "endpoint_url": format!("http://127.0.0.1:{collector_port}/ingest"),
            "allow_insecure_loopback": true,
            "batch_size": 1,
            "flush_interval_ms": 100
        }
    });
    let limit = json!({
        "limit_by": "consumer",
        "expose_headers": true,
        "limits": [{"scope": "default", "window_seconds": 60, "max_requests": 3}],
        "mcp_tool_calls": {"endpoint_path": "/mcp"}
    });
    let gateway = json!({
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
                        "parameters": [pet_id.clone()]
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
    });
    serde_json::from_value(json!({
        "version": "1",
        "proxies": [{
            "id": "mcp-governed",
            "namespace": TEST_NAMESPACE,
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
            "pool_enable_http2": false,
            "plugins": [
                {"plugin_config_id": "governed-auth"},
                {"plugin_config_id": "governed-audit"},
                {"plugin_config_id": "governed-limit"},
                {"plugin_config_id": "governed-gw"}
            ]
        }],
        "consumers": [{
            "id": "agent-alice",
            "namespace": TEST_NAMESPACE,
            "username": "agent-alice",
            "credentials": {"keyauth": [{"key": AGENT_KEY}]}
        }],
        "upstreams": [],
        "plugin_configs": [
            plugin("governed-auth", "key_auth", json!({})),
            plugin("governed-audit", "ai_transcript_audit", audit),
            plugin("governed-limit", "rate_limiting", limit),
            plugin("governed-gw", "mcp_gateway", gateway)
        ]
    }))
    .expect("governed MCP bridge config is valid")
}

fn shielded_governed_bridge_config(backend_port: u16, collector_port: u16) -> GatewayConfig {
    let mut config = serde_json::to_value(governed_bridge_config(backend_port, collector_port))
        .expect("serialize governed bridge config");
    config["proxies"][0]["plugins"]
        .as_array_mut()
        .expect("proxy plugin list")
        .push(json!({"plugin_config_id": "governed-shield"}));
    config["plugin_configs"]
        .as_array_mut()
        .expect("plugin configs")
        .push(json!({
            "id": "governed-shield",
            "namespace": TEST_NAMESPACE,
            "plugin_name": "ai_prompt_shield",
            "scope": "proxy",
            "proxy_id": "mcp-governed",
            "enabled": true,
            "config": {"action": "redact", "scan_fields": "mcp_arguments", "patterns": ["email"]}
        }));
    serde_json::from_value(config).expect("shielded governed bridge config is valid")
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

#[ignore]
#[tokio::test]
async fn functional_mcp_gateway_forwards_shielded_upstream_tool_arguments() {
    let config = |upstream_port: u16, _| shielded_admission_config(upstream_port);
    let fixture = Fixture::start_with(Backend::Mcp, config).await;
    let (status, _, session) = fixture.post("HTTP/1.1", None, &initialize_body()).await;
    assert_eq!(status, 200);
    let session = session.expect("downstream session");
    let list = json!({"jsonrpc": "2.0", "id": 90, "method": "tools/list"});
    let (status, body, _) = fixture.post("HTTP/1.1", Some(&session), &list).await;
    assert_eq!(status, 200, "{body}");
    assert!(body["result"]["tools"].is_array(), "{body}");

    let call = json!({
        "jsonrpc": "2.0",
        "id": 91,
        "method": "tools/call",
        "params": {
            "name": "echo.echo",
            "arguments": {"contact": "alice@example.com"}
        }
    });
    let (status, body, _) = fixture.post("HTTP/1.1", Some(&session), &call).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["id"], json!(91), "{body}");
    let forwarded = fixture.captures.lock().expect("upstream captures").clone();
    let forwarded = forwarded
        .iter()
        .find(|request| request.method == "tools/call")
        .expect("upstream tools/call request");
    let call_body: Value = serde_json::from_slice(&forwarded.body).expect("forwarded JSON-RPC");
    assert_eq!(
        call_body["params"]["arguments"]["contact"], "[REDACTED:email]",
        "mcp_gateway must dispatch and log only the shielded arguments: {call_body}"
    );
    assert!(!call_body.to_string().contains("alice@example.com"));
    fixture.shutdown().await;
}

fn response_header<'a>(headers: &'a http::HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// The audit records whose single call named `tool`.
fn audited_calls<'a>(records: &'a [Value], tool: &str) -> Vec<&'a Value> {
    records
        .iter()
        .filter(|record| record["mcp"]["calls"][0]["tool"] == tool)
        .collect()
}

/// The AI governance stack in front of an OpenAPI bridge (issue #5908): only
/// `tools/call` spends the consumer's budget — `initialize` and `tools/list`
/// never do, and each `tools/call` member of a batch is one charge — a refusal
/// is a JSON-RPC `-32015` on HTTP 200 with `x-ratelimit-*` headers, nothing
/// refused reaches the REST backend, and every call is audited with the
/// consumer, the public tool name, and its JSON-RPC outcome (the converted
/// `tools/call` result for a bridged call, never the REST body).
#[ignore]
#[tokio::test]
async fn functional_mcp_gateway_governed_bridge_audits_and_limits_tool_calls() {
    let collector = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind audit collector");
    let collector_port = collector.local_addr().expect("collector addr").port();
    let records: AuditRecords = Arc::new(Mutex::new(Vec::new()));
    let collector_task = tokio::spawn(serve_audit_collector(collector, Arc::clone(&records)));
    let config =
        move |backend_port: u16, _: u16| governed_bridge_config(backend_port, collector_port);
    let fixture = Fixture::start_with(Backend::Rest, config).await;
    let key = [("x-api-key", AGENT_KEY)];

    let (status, body, headers) = fixture.post_h1_with(None, &initialize_body(), &key).await;
    assert_eq!(status, 200, "initialize must succeed: {body}");
    let session = header_string(&headers).expect("initialize mints a downstream session");
    assert!(
        response_header(&headers, "x-ratelimit-remaining").is_none(),
        "initialize is not a tool call"
    );

    // Discovery is never charged, however often it is repeated.
    for id in 20..25 {
        let list = json!({"jsonrpc": "2.0", "id": id, "method": "tools/list"});
        let (status, body, headers) = fixture.post_h1_with(Some(&session), &list, &key).await;
        assert_eq!(status, 200, "{body}");
        assert!(body["result"]["tools"].is_array(), "{body}");
        assert!(response_header(&headers, "x-ratelimit-remaining").is_none());
    }

    // Two admitted calls spend the budget of three down to one.
    for (id, remaining) in [(30, "2"), (31, "1")] {
        let call = bridge_call_body(id, "pets.getPet", json!({"petId": "7"}));
        let (status, body, headers) = fixture.post_h1_with(Some(&session), &call, &key).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["id"], json!(id), "{body}");
        assert_eq!(body["result"]["isError"], json!(false), "{body}");
        let header = response_header(&headers, "x-ratelimit-remaining");
        assert_eq!(header, Some(remaining), "call {id}");
    }

    // A batch of two calls needs two charges with one left: the whole batch
    // is refused, one JSON-RPC error per member.
    let batch = json!([
        bridge_call_body(32, "pets.getPet", json!({"petId": "7"})),
        bridge_call_body(33, "pets.getPet", json!({"petId": "8"}))
    ]);
    let (status, body, headers) = fixture.post_h1_with(Some(&session), &batch, &key).await;
    assert_eq!(status, 200, "a JSON-RPC refusal rides HTTP 200: {body}");
    let errors = body.as_array().expect("one error per batch member");
    let ids: Vec<&Value> = errors.iter().map(|error| &error["id"]).collect();
    assert_eq!(ids, vec![&json!(32), &json!(33)], "{body}");
    for error in errors {
        assert_eq!(error["error"]["code"], json!(-32015), "{body}");
    }
    let remaining = response_header(&headers, "x-ratelimit-remaining");
    assert_eq!(remaining, Some("0"));

    // The budget is spent: a single call is refused before any dispatch.
    let call = bridge_call_body(34, "pets.deletePet", json!({"petId": "7"}));
    let (status, body, headers) = fixture.post_h1_with(Some(&session), &call, &key).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["id"], json!(34), "{body}");
    assert_eq!(body["error"]["code"], json!(-32015), "{body}");
    assert_eq!(response_header(&headers, "x-ratelimit-limit"), Some("3"));
    let remaining = response_header(&headers, "x-ratelimit-remaining");
    assert_eq!(remaining, Some("0"));

    // Discovery and session setup stay free after the budget is spent.
    let list = json!({"jsonrpc": "2.0", "id": 35, "method": "tools/list"});
    let (status, body, _) = fixture.post_h1_with(Some(&session), &list, &key).await;
    assert_eq!(status, 200, "{body}");
    assert!(body["result"]["tools"].is_array(), "{body}");
    let (status, body, _) = fixture.post_h1_with(None, &initialize_body(), &key).await;
    assert_eq!(status, 200, "{body}");

    // Only the two admitted calls reached the REST backend.
    let received = fixture.received();
    let request_lines: Vec<&str> = received
        .iter()
        .map(|request| request.head.lines().next().unwrap_or_default())
        .collect();
    assert_eq!(
        request_lines,
        vec!["GET /pets/7 HTTP/1.1", "GET /pets/7 HTTP/1.1"],
        "refused calls are never dispatched"
    );

    // Four tool-call exchanges, four audit records; discovery and session
    // setup produce none.
    let audited = wait_for_audit_records(&records, 4).await;
    assert_eq!(audited.len(), 4, "{audited:#?}");
    for record in &audited {
        assert_eq!(record["consumer_username"], "agent-alice", "{record}");
        let calls = record["mcp"]["calls"].as_array().expect("mcp.calls");
        for call in calls {
            let hash = call["arguments_hash"].as_str().unwrap_or_default();
            assert_eq!(hash.len(), 64, "keyed arguments hash: {record}");
        }
    }
    let admitted = audited_calls(&audited, "pets.getPet");
    let admitted: Vec<&Value> = admitted
        .into_iter()
        .filter(|record| record["mcp"]["batch"] == json!(false))
        .collect();
    assert_eq!(admitted.len(), 2, "{audited:#?}");
    for record in admitted {
        let call = &record["mcp"]["calls"][0];
        assert_eq!(call["result"], "result", "{record}");
        assert_eq!(call["is_error"], json!(false), "{record}");
        let upstream_status = &record["mcp"]["gateway"]["mcp.bridge.upstream_status"];
        assert_eq!(upstream_status, "200", "{record}");
    }
    let refused = audited_calls(&audited, "pets.deletePet");
    assert_eq!(refused.len(), 1, "{audited:#?}");
    assert_eq!(refused[0]["mcp"]["calls"][0]["error_code"], json!(-32015));
    let batches: Vec<&Value> = audited
        .iter()
        .filter(|record| record["mcp"]["batch"] == json!(true))
        .collect();
    assert_eq!(batches.len(), 1, "{audited:#?}");
    let calls = batches[0]["mcp"]["calls"].as_array().expect("batch calls");
    assert_eq!(calls.len(), 2);
    for call in calls {
        assert_eq!(call["error_code"], json!(-32015), "{call}");
    }

    fixture.shutdown().await;
    collector_task.abort();
}

#[ignore]
#[tokio::test]
async fn functional_mcp_gateway_lowercase_post_is_shielded_and_audited() {
    let collector = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind audit collector");
    let collector_port = collector.local_addr().expect("collector addr").port();
    let records: AuditRecords = Arc::new(Mutex::new(Vec::new()));
    let collector_task = tokio::spawn(serve_audit_collector(collector, Arc::clone(&records)));
    let config = move |backend_port: u16, _: u16| {
        shielded_governed_bridge_config(backend_port, collector_port)
    };
    let fixture = Fixture::start_with(Backend::Rest, config).await;
    let key = [("x-api-key", AGENT_KEY)];
    let (status, _, headers) = fixture.post_h1_with(None, &initialize_body(), &key).await;
    assert_eq!(status, 200);
    let session = header_string(&headers).expect("initialize session");

    let call = bridge_call_body(81, "pets.getPet", json!({"petId": "alice@example.com"}));
    let lower_post = http::Method::from_bytes(b"post").expect("lowercase HTTP method");
    let (status, body, _) = fixture
        .post_h1_method_with(lower_post, Some(&session), &call, &key)
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["id"], json!(81), "{body}");
    let received = fixture.received();
    assert!(
        received.iter().any(|request| {
            request
                .head
                .starts_with("GET /pets/%5BREDACTED:email%5D HTTP/1.1")
        }),
        "the bridge must receive only the shielded argument: {received:#?}"
    );
    let audited = wait_for_audit_records(&records, 1).await;
    assert_eq!(
        audited.len(),
        1,
        "lowercase POST must be audited: {audited:#?}"
    );
    assert_eq!(audited[0]["mcp"]["calls"][0]["tool"], "pets.getPet");
    assert!(
        !audited[0].to_string().contains("alice@example.com"),
        "the original argument must not be exported: {audited:#?}"
    );

    fixture.shutdown().await;
    collector_task.abort();
}

//! Live-datapath functional coverage for aggregate MCP Streamable HTTP.
//!
//! These tests drive a real gateway over a real client transport: a downstream
//! MCP session is initialized, one `GET` with `Accept: text/event-stream`
//! attaches the session's single listener, and concurrent JSON-RPC requests are
//! issued over `POST` while a scripted MCP upstream holds both of them in
//! flight at once. The assertions are made on the wire — each POST whose result
//! had to be fetched is answered on THAT POST with its own
//! `text/event-stream` response carrying one `id:`/`event: message`/`data:`
//! record, with the string id `"7"` and the number id `7` kept as distinct
//! streams, and the session `GET` listener never carries either answer.
//!
//! Covered transports: HTTP/1.1 (raw socket, so the absence of
//! `Content-Length` and the chunked framing on the listener are observed
//! directly), HTTP/2 over h2c prior knowledge, and native HTTP/3 through the
//! shared H3 client scaffolding.
//!
//! Covered lifecycle/security behavior: a second `GET` while a listener is
//! attached is refused `409`, a client disconnect releases the slot so the
//! session can reattach, `notifications/cancelled` suppresses a late response
//! (its POST stream closes carrying no message), and session `DELETE` ends the
//! listener's stream — which is also how each test proves, by ORDER rather than
//! by elapsed time, that the listener never carried a POST response.
//!
//! Every wait in this file is either a channel handshake driven by the scripted
//! upstream or a bounded poll. No assertion is timing-based: an absence is
//! always proved by a later, ordered observation (the next event cursor, or the
//! end of the listener stream after session `DELETE`) rather than by elapsed
//! time, and no authoritative protocol answer is ever re-requested. The one
//! backoff loop is the post-disconnect reattach, which polls a SETUP step whose
//! only tolerated intermediate outcome is the duplicate-listener `409`.
//!
//! Run: `cargo build --bin ferrum-edge && cargo test --test functional_tests
//! functional_mcp_aggregate_sse -- --ignored --nocapture`

use crate::scaffolding::clients::{GetOptions, Http3Client, Http3ResponseStream};
use crate::scaffolding::{reserve_colocated_tcp_udp, reserve_port};

use ferrum_edge::admin::jwt_auth::{JwtConfig, JwtManager};
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::modes::file::ServeOptions;
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

const TEST_NAMESPACE: &str = "ferrum";
const TEST_JWT_SECRET: &str = "ferrum-edge-mcp-aggregate-sse-secret-0000";
const TEST_JWT_ISSUER: &str = "ferrum-edge-mcp-aggregate-sse";
const PROTOCOL_VERSION: &str = "2025-11-25";
const SESSION_HEADER: &str = "mcp-session-id";
/// Method the aggregate router does not implement, so it is routed to the
/// scripted upstream through `capabilities.passthrough_unknown_methods`. That
/// is what lets a test hold a request in flight and observe true multiplexing
/// rather than back-to-back synthetic answers.
const HELD_METHOD: &str = "session/echo";
/// Opening comment the broker writes as soon as a stream is established, as an
/// SSE RECORD (record separators already stripped).
const SSE_GREETING_RECORD: &str = ": mcp-sse";
/// The same greeting as raw body bytes, including its record separator. A
/// POST-attached stream is a bounded body, so tests compare it verbatim.
const SSE_GREETING_RECORD_BODY: &str = ": mcp-sse\n\n";
/// Hard ceiling on one buffered message in the scripted upstream and in the
/// test's own response readers.
const MAX_MESSAGE_BYTES: usize = 256 * 1024;
/// Bound on every socket read. A wedged datapath fails the test instead of
/// hanging the suite; it is never used to infer a protocol outcome.
const READ_TIMEOUT: Duration = Duration::from_secs(20);
/// Bounded reattach budget after a client disconnect. The gateway learns of the
/// disconnect when the transport drops the broker-owned body, which is a
/// separate task from this one, so the retry is on the ATTACH (a non-
/// authoritative setup step), never on a protocol answer under assertion.
const REATTACH_ATTEMPTS: u32 = 300;
/// Backoff between reattach attempts. Bounds the poll's cost; it is never used
/// to decide a protocol outcome.
const REATTACH_POLL_INTERVAL: Duration = Duration::from_millis(50);

// ===========================================================================
// Scripted MCP upstream
// ===========================================================================

/// One JSON-RPC request the scripted upstream has received and is holding.
///
/// The upstream answers only after `release` is fired, which is what makes
/// "both requests are in flight at the same time" an observed fact rather than
/// a timing assumption.
struct Arrival {
    id: Value,
    raw_id: String,
    release: oneshot::Sender<()>,
}

/// Serve HTTP/1.1 JSON-RPC on `listener` until it is dropped.
///
/// Requests carrying an `id` are parked: the arrival (with its release handle)
/// is published to the test, and the response is written only once the test
/// releases it. Notification-form messages (no `id`) are answered immediately
/// with an empty `202`, which is what `notifications/cancelled` needs when it
/// is routed upstream.
///
/// The JSON body is serialized WITHOUT a trailing newline on purpose: the
/// broker refuses to fold CR/LF into an SSE `data:` line, so a newline-
/// terminated upstream body would legitimately fall back to an inline answer.
async fn serve_scripted_mcp_upstream(
    listener: TcpListener,
    arrivals: mpsc::UnboundedSender<Arrival>,
    requests: Arc<AtomicUsize>,
) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let arrivals = arrivals.clone();
        let requests = Arc::clone(&requests);
        tokio::spawn(async move {
            let _ = stream.set_nodelay(true);
            let mut pending = Vec::new();
            loop {
                let Some(body) = read_one_http_request(&mut stream, &mut pending).await else {
                    return;
                };
                requests.fetch_add(1, Ordering::SeqCst);
                let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                let Some(id) = parsed.get("id").cloned() else {
                    if write_http_response(&mut stream, 202, "").await.is_err() {
                        return;
                    }
                    continue;
                };
                let fields: std::collections::BTreeMap<String, &serde_json::value::RawValue> =
                    serde_json::from_slice(&body).unwrap();
                let raw_id = fields["id"].get().to_string();
                // Tests may script a different response id without ever
                // materializing the numeric token through serde_json::Number.
                let response_id = fields
                    .get("params")
                    .and_then(|params| {
                        serde_json::from_str::<
                            std::collections::BTreeMap<String, &serde_json::value::RawValue>,
                        >(params.get())
                        .ok()
                    })
                    .and_then(|params| params.get("responseId").copied())
                    .map(|id| id.get())
                    .unwrap_or(&raw_id);
                let (release, released) = oneshot::channel();
                if arrivals
                    .send(Arrival {
                        id: id.clone(),
                        raw_id: raw_id.clone(),
                        release,
                    })
                    .is_err()
                {
                    return;
                }
                // A dropped release handle means the test finished with this
                // request; answering anyway keeps the socket well-framed.
                let _ = released.await;
                let kind = match &id {
                    Value::String(_) => "string",
                    Value::Number(_) => "number",
                    _ => "other",
                };
                let payload = format!(
                    r#"{{"jsonrpc":"2.0","id":{response_id},"result":{{"kind":"{kind}"}}}}"#
                );
                if write_http_response(&mut stream, 200, &payload)
                    .await
                    .is_err()
                {
                    return;
                }
            }
        });
    }
}

/// Read exactly one HTTP/1.1 message off `stream`, leaving any pipelined bytes
/// in `pending`. Returns `None` (fail closed, no answer) on EOF-before-complete,
/// a missing/invalid `Content-Length`, `Transfer-Encoding`, or an oversized
/// message. Termination is decided entirely by the parsed framing.
async fn read_one_http_request(stream: &mut TcpStream, pending: &mut Vec<u8>) -> Option<Vec<u8>> {
    let mut chunk = [0u8; 8192];
    loop {
        if let Some(offset) = find_header_terminator(pending) {
            let headers = std::str::from_utf8(&pending[..offset]).ok()?;
            let length = parse_content_length(headers)?;
            let need = offset + 4 + length;
            if pending.len() >= need {
                let body = pending[offset + 4..need].to_vec();
                pending.drain(..need);
                return Some(body);
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

fn find_header_terminator(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

/// Body length from a request/response head. Absent `Content-Length` means an
/// empty body; `Transfer-Encoding` is refused rather than guessed at.
fn parse_content_length(headers: &str) -> Option<usize> {
    let mut length = Some(0usize);
    for line in headers.lines().skip(1) {
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
    body: &str,
) -> std::io::Result<()> {
    let reason = if status == 200 { "OK" } else { "Accepted" };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.flush().await
}

async fn next_arrival(rx: &mut mpsc::UnboundedReceiver<Arrival>) -> Arrival {
    tokio::time::timeout(READ_TIMEOUT, rx.recv())
        .await
        .expect("scripted upstream did not receive the request")
        .expect("scripted upstream arrival channel closed")
}

// ===========================================================================
// Gateway harness
// ===========================================================================

struct RunningGateway {
    http_port: u16,
    https_port: u16,
    shutdown_tx: watch::Sender<bool>,
    join: JoinHandle<()>,
}

impl RunningGateway {
    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(10), self.join).await;
    }
}

/// Fixture bundling the gateway with its scripted upstream and the arrival
/// channel that drives every handshake in these tests.
struct SseFixture {
    gateway: RunningGateway,
    arrivals: mpsc::UnboundedReceiver<Arrival>,
    upstream_task: JoinHandle<()>,
    requests: Arc<AtomicUsize>,
}

impl SseFixture {
    async fn start() -> Self {
        Self::start_mode("aggregate_router").await
    }

    async fn start_mode(mode: &str) -> Self {
        // Pre-bound fixture listener: the socket is never dropped and rebound,
        // so it cannot race a port the gateway is about to claim.
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind scripted MCP upstream");
        let upstream_port = upstream_listener
            .local_addr()
            .expect("scripted upstream local addr")
            .port();
        let (arrivals_tx, arrivals) = mpsc::unbounded_channel();
        let requests = Arc::new(AtomicUsize::new(0));
        let upstream_task = tokio::spawn(serve_scripted_mcp_upstream(
            upstream_listener,
            arrivals_tx,
            Arc::clone(&requests),
        ));

        let mut config = aggregate_sse_config(upstream_port);
        if mode == "transparent_proxy" {
            config.plugin_configs[0].config = json!({
                "mode": "transparent_proxy",
                "endpoint": {"path": "/mcp", "protocol_versions": [PROTOCOL_VERSION]},
                "servers": {"echo": {
                    "upstream_url": format!("http://127.0.0.1:{upstream_port}/mcp"),
                    "namespace": "echo"
                }}
            });
        }
        let gateway = start_gateway(config)
            .await
            .expect("start aggregate MCP SSE gateway");

        Self {
            gateway,
            arrivals,
            upstream_task,
            requests,
        }
    }

    fn http_port(&self) -> u16 {
        self.gateway.http_port
    }

    fn https_port(&self) -> u16 {
        self.gateway.https_port
    }

    async fn shutdown(self) {
        self.gateway.shutdown().await;
        self.upstream_task.abort();
    }
}

async fn start_gateway(
    config: GatewayConfig,
) -> Result<RunningGateway, Box<dyn std::error::Error + Send + Sync>> {
    let http = reserve_port().await?;
    let (https_tcp, https_udp) = reserve_colocated_tcp_udp().await?;
    let admin = reserve_port().await?;
    let http_port = http.port;
    let https_port = https_tcp.port;
    assert_eq!(https_port, https_udp.port);

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
    // The QUIC listener is bound by the gateway on the same port the TCP
    // reservation proved free; hold the reservation until `serve` owns it.
    drop(https_udp);

    let (shutdown_tx, _) = watch::channel(false);
    let handles = ferrum_edge::modes::file::serve(env_config, config, options, shutdown_tx.clone())
        .await
        .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> {
            format!("file::serve failed: {error}").into()
        })?;
    let join = tokio::spawn(async move {
        if let Err(error) = handles.join().await {
            eprintln!("in-process aggregate MCP SSE gateway listener panicked: {error}");
        }
    });

    Ok(RunningGateway {
        http_port,
        https_port,
        shutdown_tx,
        join,
    })
}

fn aggregate_sse_config(upstream_port: u16) -> GatewayConfig {
    serde_json::from_value(json!({
        "version": "1",
        "proxies": [{
            "id": "mcp-aggregate-sse",
            "namespace": TEST_NAMESPACE,
            "listen_path": "/mcp",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": upstream_port,
            "strip_listen_path": false,
            "plugins": [{"plugin_config_id": "mcp-aggregate-sse-gw"}]
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "mcp-aggregate-sse-gw",
            "namespace": TEST_NAMESPACE,
            "plugin_name": "mcp_gateway",
            "scope": "proxy",
            "proxy_id": "mcp-aggregate-sse",
            "enabled": true,
            "config": {
                "enabled": true,
                "mode": "aggregate_router",
                "endpoint": {
                    "path": "/mcp",
                    "protocol_versions": [PROTOCOL_VERSION]
                },
                "servers": {
                    "echo": {
                        "upstream_url": format!("http://127.0.0.1:{upstream_port}/mcp"),
                        "namespace": "echo",
                        "enabled": true,
                        "expose_tools": true
                    }
                },
                "sessions": {
                    // No upstream initialize handshake: the scripted upstream
                    // only has to answer the requests the test issues.
                    "initialize_upstreams": "passthrough",
                    "sse_multiplexing": true,
                    // A short keepalive bounds when the gateway next writes to
                    // a listener. That is what makes "the client went away"
                    // observable in bounded time without depending on how a
                    // transport happens to detect a half-closed peer.
                    "sse_keepalive_seconds": 5,
                    "sse_listener_max_lifetime_seconds": 120
                },
                "capabilities": {
                    "passthrough_unknown_methods": true
                },
                "policy": {
                    "default_action": "allow"
                }
            }
        }]
    }))
    .expect("aggregate MCP SSE config is valid")
}

// ===========================================================================
// SSE record parsing
// ===========================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
struct SseMessage {
    event_id: u64,
    data: String,
}

impl SseMessage {
    fn json(&self) -> Value {
        serde_json::from_str(&self.data).expect("SSE data line is a JSON-RPC response")
    }
}

/// Incremental SSE record splitter. Records are separated by a blank line, so a
/// record boundary is decided by the bytes on the wire, never by a timer.
#[derive(Default)]
struct SseCursor {
    decoded: Vec<u8>,
}

impl SseCursor {
    fn feed(&mut self, bytes: &[u8]) {
        self.decoded.extend_from_slice(bytes);
    }

    fn take_record(&mut self) -> Option<String> {
        let position = self
            .decoded
            .windows(2)
            .position(|window| window == b"\n\n")?;
        let record =
            String::from_utf8(self.decoded[..position].to_vec()).expect("SSE record is UTF-8");
        self.decoded.drain(..position + 2);
        Some(record)
    }
}

/// Parse a non-comment SSE record into its `id:` / `data:` pair, asserting the
/// event name the broker publishes.
fn parse_sse_message(record: &str) -> SseMessage {
    let mut event_id = None;
    let mut data = None;
    let mut event_name = None;
    for line in record.split('\n') {
        if let Some(rest) = line.strip_prefix("id: ") {
            event_id = Some(rest.parse::<u64>().expect("SSE id is a numeric cursor"));
        } else if let Some(rest) = line.strip_prefix("data: ") {
            data = Some(rest.to_string());
        } else if let Some(rest) = line.strip_prefix("event: ") {
            event_name = Some(rest.to_string());
        }
    }
    assert_eq!(
        event_name.as_deref(),
        Some("message"),
        "multiplexed JSON-RPC responses must be published as `event: message`: {record:?}"
    );
    SseMessage {
        event_id: event_id.expect("SSE record carries an id"),
        data: data.expect("SSE record carries a data line"),
    }
}

fn is_comment_record(record: &str) -> bool {
    record.starts_with(':')
}

// ===========================================================================
// HTTP/1.1 raw SSE listener
// ===========================================================================

/// Raw HTTP/1.1 listener socket.
///
/// Raw rather than `reqwest` on purpose: this is the only way to observe that
/// the gateway published NO `Content-Length` for the event stream and framed it
/// as `chunked`, and it makes "the client disconnected" an unambiguous act
/// (dropping the socket) rather than a client-library detail.
struct RawSseListener {
    stream: TcpStream,
    raw: Vec<u8>,
    cursor: SseCursor,
    ended: bool,
}

enum SseAttach {
    Attached(RawSseListener),
    Refused { status: u16, body: String },
}

async fn attach_sse_h1(port: u16, session_id: &str, last_event_id: Option<&str>) -> SseAttach {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect to gateway proxy port");
    stream.set_nodelay(true).expect("set nodelay");
    let mut request = format!(
        "GET /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n\
         {SESSION_HEADER}: {session_id}\r\nMCP-Protocol-Version: {PROTOCOL_VERSION}\r\n"
    );
    if let Some(cursor) = last_event_id {
        request.push_str(&format!("Last-Event-ID: {cursor}\r\n"));
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write SSE GET request");
    stream.flush().await.expect("flush SSE GET request");

    let mut raw = Vec::new();
    let (status, headers) = read_response_head(&mut stream, &mut raw).await;
    if status != 200 {
        let length = parse_content_length(&headers).unwrap_or(0);
        while raw.len() < length {
            let mut chunk = [0u8; 4096];
            let read = read_with_timeout(&mut stream, &mut chunk).await;
            if read == 0 {
                break;
            }
            raw.extend_from_slice(&chunk[..read]);
        }
        let body = String::from_utf8_lossy(&raw[..raw.len().min(length)]).to_string();
        return SseAttach::Refused { status, body };
    }

    let lowered = headers.to_ascii_lowercase();
    assert!(
        lowered.contains("content-type: text/event-stream"),
        "attached listener must be an event stream: {headers}"
    );
    assert!(
        !lowered.contains("\ncontent-length:"),
        "an event stream must not publish Content-Length for unwritten bytes: {headers}"
    );
    assert!(
        lowered.contains("transfer-encoding: chunked"),
        "HTTP/1.1 event streams must be chunk-framed: {headers}"
    );

    let mut listener = RawSseListener {
        stream,
        raw,
        cursor: SseCursor::default(),
        ended: false,
    };
    listener.decode_buffered();
    SseAttach::Attached(listener)
}

/// Reattach a session's listener after a client disconnect.
///
/// Slot release is owned by the transport task that drops the broker-owned
/// body, not by the disconnecting client, so this is a bounded poll on a SETUP
/// step: every attempt is a real attach whose only tolerated outcome is the
/// duplicate-listener refusal, and exhausting the budget fails the test. No
/// protocol answer under assertion is ever retried.
async fn reattach_with_bounded_poll(port: u16, session_id: &str) -> RawSseListener {
    for _ in 0..REATTACH_ATTEMPTS {
        match attach_sse_h1(port, session_id, None).await {
            SseAttach::Attached(listener) => return listener,
            SseAttach::Refused { status, body } => {
                assert_eq!(
                    status, 409,
                    "only the duplicate-listener refusal is expected while the slot drains: {body}"
                );
                tokio::time::sleep(REATTACH_POLL_INTERVAL).await;
            }
        }
    }
    panic!("client disconnect must release the session's listener slot");
}

async fn attach_sse_h1_expect_attached(port: u16, session_id: &str) -> RawSseListener {
    match attach_sse_h1(port, session_id, None).await {
        SseAttach::Attached(listener) => listener,
        SseAttach::Refused { status, body } => {
            panic!("expected an attached SSE listener, got {status}: {body}")
        }
    }
}

impl RawSseListener {
    /// Decode whatever chunked bytes are already buffered. Returns `true` once
    /// the terminal zero-length chunk has been seen.
    fn decode_buffered(&mut self) -> bool {
        loop {
            let Some(position) = self.raw.windows(2).position(|window| window == b"\r\n") else {
                return false;
            };
            let line = String::from_utf8_lossy(&self.raw[..position]).to_string();
            let size_token = line
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_string();
            let size = usize::from_str_radix(&size_token, 16)
                .unwrap_or_else(|_| panic!("malformed chunk size {size_token:?}"));
            let start = position + 2;
            let need = start + size + 2;
            if self.raw.len() < need {
                return false;
            }
            let data = self.raw[start..start + size].to_vec();
            self.cursor.feed(&data);
            self.raw.drain(..need);
            if size == 0 {
                self.ended = true;
                return true;
            }
        }
    }

    /// Next SSE record, or `None` once the response body has ended.
    async fn next_record(&mut self) -> Option<String> {
        loop {
            if let Some(record) = self.cursor.take_record() {
                return Some(record);
            }
            if self.ended {
                return None;
            }
            let mut chunk = [0u8; 8192];
            let read = read_with_timeout(&mut self.stream, &mut chunk).await;
            if read == 0 {
                self.ended = true;
                return self.cursor.take_record();
            }
            self.raw.extend_from_slice(&chunk[..read]);
            self.decode_buffered();
        }
    }

    async fn expect_greeting(&mut self) {
        let record = self
            .next_record()
            .await
            .expect("attached listener must emit its opening comment");
        assert_eq!(
            record, SSE_GREETING_RECORD,
            "listener must open with the broker greeting"
        );
    }

    /// Drain until the stream ends, asserting no further message record is
    /// published. Used to prove a session `DELETE` really terminated the
    /// listener rather than leaving it idle.
    async fn expect_end_without_message(&mut self) {
        while let Some(record) = self.next_record().await {
            assert!(
                is_comment_record(&record),
                "listener must not publish a message after the session ended: {record:?}"
            );
        }
    }
}

async fn read_response_head(stream: &mut TcpStream, raw: &mut Vec<u8>) -> (u16, String) {
    loop {
        if let Some(offset) = find_header_terminator(raw) {
            let head = String::from_utf8_lossy(&raw[..offset]).to_string();
            let status = head
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|code| code.parse::<u16>().ok())
                .unwrap_or_else(|| panic!("malformed status line: {head:?}"));
            raw.drain(..offset + 4);
            return (status, head);
        }
        let mut chunk = [0u8; 4096];
        let read = read_with_timeout(stream, &mut chunk).await;
        assert!(read > 0, "connection closed before response headers");
        raw.extend_from_slice(&chunk[..read]);
    }
}

async fn read_with_timeout(stream: &mut TcpStream, chunk: &mut [u8]) -> usize {
    match tokio::time::timeout(READ_TIMEOUT, stream.read(chunk)).await {
        Ok(Ok(read)) => read,
        Ok(Err(_)) => 0,
        Err(_) => panic!("timed out reading from the gateway"),
    }
}

// ===========================================================================
// JSON-RPC client helpers
// ===========================================================================

fn mcp_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}/mcp")
}

fn initialize_body() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": "init",
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "ferrum-functional-sse", "version": "1"}
        }
    })
}

fn held_request_body(id: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": HELD_METHOD,
        "params": {}
    })
}

fn cancel_notification_body(request_id: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": {"requestId": request_id}
    })
}

/// Initialize a downstream MCP session and return its id.
async fn initialize_session(client: &reqwest::Client, port: u16) -> String {
    let response = client
        .post(mcp_url(port))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .json(&initialize_body())
        .send()
        .await
        .expect("initialize request");
    assert_eq!(response.status().as_u16(), 200, "initialize must succeed");
    let session_id = response
        .headers()
        .get(SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("initialize must mint a downstream session id")
        .to_string();
    assert!(!session_id.is_empty(), "session id must not be empty");
    session_id
}

/// POST a JSON-RPC message and return `(status, content-type, body)`.
///
/// The content type is part of the contract now: MCP Streamable HTTP lets the
/// server answer a POST that carried a request with either `application/json`
/// or its own `text/event-stream`, and which one it chose is exactly what these
/// tests assert.
async fn post_jsonrpc(
    client: &reqwest::Client,
    port: u16,
    session_id: &str,
    body: Value,
) -> PostAnswer {
    let response = client
        .post(mcp_url(port))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header(SESSION_HEADER, session_id)
        .header("mcp-protocol-version", PROTOCOL_VERSION)
        .json(&body)
        .send()
        .await
        .expect("JSON-RPC POST");
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let text = response.text().await.expect("JSON-RPC POST body");
    PostAnswer {
        status,
        content_type,
        body: text,
    }
}

/// The complete client-visible answer to one POST.
#[derive(Debug, Clone)]
struct PostAnswer {
    status: u16,
    content_type: String,
    body: String,
}

impl PostAnswer {
    /// The single JSON-RPC message this POST's own event stream carried.
    ///
    /// Asserts the whole Streamable HTTP shape on the wire: a deferred request
    /// is answered `200 text/event-stream` on the POST that carried it, the
    /// stream opens with the broker greeting, carries exactly one
    /// `event: message` record, and then ends.
    fn post_stream_message(&self, label: &str) -> SseMessage {
        self.assert_post_stream(label);
        let body = &self.body;
        let mut cursor = SseCursor::default();
        cursor.feed(body.as_bytes());
        let mut message = None;
        while let Some(record) = cursor.take_record() {
            if is_comment_record(&record) {
                continue;
            }
            assert!(
                message.is_none(),
                "{label}: a POST-attached stream carries exactly one response: {body:?}"
            );
            message = Some(parse_sse_message(&record));
        }
        let Some(message) = message else {
            panic!("{label}: the POST-attached stream carried no response: {body:?}");
        };
        message
    }

    /// A cancelled request's POST stream opens and closes carrying no message.
    fn assert_suppressed(&self, label: &str) {
        self.assert_post_stream(label);
        assert_eq!(
            self.body, SSE_GREETING_RECORD_BODY,
            "{label}: a cancelled request must not be answered with its result"
        );
    }

    fn assert_post_stream(&self, label: &str) {
        let body = &self.body;
        assert_eq!(
            self.status, 200,
            "{label}: a deferred request answers on its own POST: {body:?}"
        );
        assert_eq!(
            self.content_type, "text/event-stream",
            "{label}: the POST must select the event-stream representation"
        );
        assert!(
            body.starts_with(SSE_GREETING_RECORD_BODY),
            "{label}: the POST stream must open with the broker greeting: {body:?}"
        );
    }
}

fn assert_response_identity(message: &SseMessage, expected_id: &Value, expected_kind: &str) {
    let payload = message.json();
    assert_eq!(
        payload.get("jsonrpc").and_then(Value::as_str),
        Some("2.0"),
        "the event must be a JSON-RPC response: {payload}"
    );
    assert_eq!(
        payload.get("id"),
        Some(expected_id),
        "the event must carry the exact JSON-RPC id, including its type: {payload}"
    );
    assert_eq!(
        payload
            .get("result")
            .and_then(|result| result.get("kind"))
            .and_then(Value::as_str),
        Some(expected_kind),
        "the upstream answer delivered on this POST must be the one for this id type: {payload}"
    );
}

// ===========================================================================
// HTTP/1.1: multiplexing, listener exclusivity, disconnect + reattach
// ===========================================================================

#[tokio::test]
#[ignore]
async fn functional_mcp_aggregate_sse_h1_multiplexes_concurrent_requests_and_permits_reattach() {
    let mut fixture = SseFixture::start().await;
    let port = fixture.http_port();
    let client = reqwest::Client::builder()
        .build()
        .expect("HTTP/1.1 client builds");

    let session_id = initialize_session(&client, port).await;
    let mut listener = attach_sse_h1_expect_attached(port, &session_id).await;
    listener.expect_greeting().await;

    // A second GET while a listener is attached is refused, so the session
    // really has exactly one event stream.
    match attach_sse_h1(port, &session_id, None).await {
        SseAttach::Refused { status, body } => {
            assert_eq!(status, 409, "a duplicate listener must be refused: {body}");
            assert!(
                body.contains("SSE listener already attached"),
                "refusal must name the duplicate-listener reason: {body}"
            );
        }
        SseAttach::Attached(_) => panic!("a session must not attach two event streams"),
    }

    // Two concurrent requests whose JSON-RPC ids differ only by TYPE.
    let string_id = json!("7");
    let number_id = json!(7);
    let string_post = tokio::spawn({
        let client = client.clone();
        let session_id = session_id.clone();
        let body = held_request_body(string_id.clone());
        async move { post_jsonrpc(&client, port, &session_id, body).await }
    });
    let number_post = tokio::spawn({
        let client = client.clone();
        let session_id = session_id.clone();
        let body = held_request_body(number_id.clone());
        async move { post_jsonrpc(&client, port, &session_id, body).await }
    });

    // Both requests are parked at the upstream at the same time before either
    // is answered: this is a real concurrent multiplex, not two sequential
    // exchanges.
    let first = next_arrival(&mut fixture.arrivals).await;
    let second = next_arrival(&mut fixture.arrivals).await;
    let (string_arrival, number_arrival) = if first.id == string_id {
        (first, second)
    } else {
        (second, first)
    };
    assert_eq!(
        (&string_arrival.id, &number_arrival.id),
        (&string_id, &number_id),
        "both id types must reach the upstream as separate requests"
    );

    // Release in a fixed order so the event order under assertion is decided by
    // the upstream, not by scheduling.
    string_arrival
        .release
        .send(())
        .expect("release the string-id request");
    number_arrival
        .release
        .send(())
        .expect("release the number-id request");

    // Each answer arrives on the POST that carried its request, as that POST's
    // own event stream. Neither one is on the listener.
    let string_answer = string_post.await.expect("string-id POST joined");
    let number_answer = number_post.await.expect("number-id POST joined");
    let string_message = string_answer.post_stream_message("string id");
    assert_eq!(
        string_message.event_id, 1,
        "the first delivered event carries the session cursor 1"
    );
    assert_response_identity(&string_message, &string_id, "string");
    let number_message = number_answer.post_stream_message("number id");
    assert_eq!(
        number_message.event_id, 2,
        "event cursors advance monotonically across the session's streams"
    );
    assert_response_identity(&number_message, &number_id, "number");

    // Client disconnect: dropping the socket must release the single-listener
    // slot so the same session can reattach. The configured keepalive bounds
    // when the gateway attempts its next write to the vanished peer, so the
    // release is guaranteed rather than dependent on read-side EOF detection.
    drop(listener);
    let mut reattached = reattach_with_bounded_poll(port, &session_id).await;
    reattached.expect_greeting().await;

    // The session is fully usable again, and its event cursor continues rather
    // than restarting.
    let resumed_id = json!("after-reattach");
    let resumed_post = tokio::spawn({
        let client = client.clone();
        let session_id = session_id.clone();
        let body = held_request_body(resumed_id.clone());
        async move { post_jsonrpc(&client, port, &session_id, body).await }
    });
    let resumed_arrival = next_arrival(&mut fixture.arrivals).await;
    assert_eq!(resumed_arrival.id, resumed_id);
    resumed_arrival
        .release
        .send(())
        .expect("release the post-reattach request");
    let resumed_answer = resumed_post.await.expect("post-reattach POST joined");
    let resumed_message = resumed_answer.post_stream_message("after reattach");
    assert_eq!(
        resumed_message.event_id, 3,
        "the session's one event cursor continues across streams"
    );
    assert_response_identity(&resumed_message, &resumed_id, "string");

    // Absence proved by ORDER, not by elapsed time: ending the session ends the
    // listener, and it must reach that end without ever having carried a
    // response to a request that arrived on a POST.
    delete_session(&client, port, &session_id).await;
    reattached.expect_end_without_message().await;

    fixture.shutdown().await;
}

/// End a downstream MCP session over HTTP/1.1.
async fn delete_session(client: &reqwest::Client, port: u16, session_id: &str) {
    let delete = client
        .delete(mcp_url(port))
        .header(SESSION_HEADER, session_id)
        .header("mcp-protocol-version", PROTOCOL_VERSION)
        .send()
        .await
        .expect("session DELETE");
    assert_eq!(delete.status().as_u16(), 200, "session DELETE succeeds");
}

// ===========================================================================
// HTTP/1.1: cancellation suppression and session DELETE
// ===========================================================================

#[tokio::test]
#[ignore]
async fn functional_mcp_aggregate_sse_cancel_suppresses_late_response_and_delete_ends() {
    let mut fixture = SseFixture::start().await;
    let port = fixture.http_port();
    let client = reqwest::Client::builder()
        .build()
        .expect("HTTP/1.1 client builds");

    let session_id = initialize_session(&client, port).await;
    let mut listener = attach_sse_h1_expect_attached(port, &session_id).await;
    listener.expect_greeting().await;

    // Park a request at the upstream so the cancellation lands while the stream
    // identity is genuinely open.
    let cancelled_id = json!("cancel-me");
    let cancelled_post = tokio::spawn({
        let client = client.clone();
        let session_id = session_id.clone();
        let body = held_request_body(cancelled_id.clone());
        async move { post_jsonrpc(&client, port, &session_id, body).await }
    });
    let cancelled_arrival = next_arrival(&mut fixture.arrivals).await;
    assert_eq!(cancelled_arrival.id, cancelled_id);

    let cancel_answer = post_jsonrpc(
        &client,
        port,
        &session_id,
        cancel_notification_body(cancelled_id.clone()),
    )
    .await;
    let cancel_body = &cancel_answer.body;
    assert_eq!(
        cancel_answer.status, 202,
        "a POST carrying only a notification keeps its 202: {cancel_body}"
    );

    // Now let the upstream answer. The response is late relative to the cancel,
    // so the POST's own stream must close carrying no message at all.
    cancelled_arrival
        .release
        .send(())
        .expect("release the cancelled request");
    let late = cancelled_post.await.expect("cancelled POST joined");
    late.assert_suppressed("cancelled request");

    // Absence is proved by ORDER, not by elapsed time: a later, uncancelled
    // request takes event cursor 1. If the cancelled response had been
    // delivered it would necessarily have consumed that cursor first.
    let surviving_id = json!("survivor");
    let surviving_post = tokio::spawn({
        let client = client.clone();
        let session_id = session_id.clone();
        let body = held_request_body(surviving_id.clone());
        async move { post_jsonrpc(&client, port, &session_id, body).await }
    });
    let surviving_arrival = next_arrival(&mut fixture.arrivals).await;
    assert_eq!(surviving_arrival.id, surviving_id);
    surviving_arrival
        .release
        .send(())
        .expect("release the surviving request");
    let surviving_answer = surviving_post.await.expect("surviving POST joined");
    let surviving_message = surviving_answer.post_stream_message("survivor");
    assert_response_identity(&surviving_message, &surviving_id, "string");
    assert_eq!(
        surviving_message.event_id, 1,
        "the cancelled response must never have consumed an event cursor"
    );

    // Session DELETE ends the listener's stream, which is also the ordered
    // proof that it never carried either POST's answer.
    delete_session(&client, port, &session_id).await;
    listener.expect_end_without_message().await;

    // The session is gone, so a fresh attach is refused rather than resurrecting
    // the deleted session's stream.
    match attach_sse_h1(port, &session_id, None).await {
        SseAttach::Refused { status, .. } => {
            assert_eq!(status, 404, "a deleted session cannot attach a listener")
        }
        SseAttach::Attached(_) => panic!("a deleted session must not attach an event stream"),
    }

    fixture.shutdown().await;
}

// ===========================================================================
// HTTP/2 (h2c prior knowledge)
// ===========================================================================

#[tokio::test]
#[ignore]
async fn functional_mcp_aggregate_sse_h2_multiplexes_concurrent_requests() {
    let mut fixture = SseFixture::start().await;
    let port = fixture.http_port();
    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .build()
        .expect("h2c client builds");

    let session_id = initialize_session(&client, port).await;

    let mut response = client
        .get(mcp_url(port))
        .header("accept", "text/event-stream")
        .header(SESSION_HEADER, &session_id)
        .header("mcp-protocol-version", PROTOCOL_VERSION)
        .send()
        .await
        .expect("h2c SSE GET");
    assert_eq!(
        response.version(),
        reqwest::Version::HTTP_2,
        "the listener must be served over HTTP/2"
    );
    assert_eq!(response.status().as_u16(), 200, "h2c listener attaches");
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream"),
        "h2c listener must be an event stream"
    );
    assert!(
        response.content_length().is_none(),
        "an event stream must not publish a content length for unwritten bytes"
    );

    let mut cursor = SseCursor::default();
    let greeting = next_record_h2(&mut response, &mut cursor)
        .await
        .expect("h2c listener must emit its opening comment");
    assert_eq!(greeting, SSE_GREETING_RECORD);

    let string_id = json!("h2");
    let number_id = json!(42);
    let string_post = tokio::spawn({
        let client = client.clone();
        let session_id = session_id.clone();
        let body = held_request_body(string_id.clone());
        async move { post_jsonrpc(&client, port, &session_id, body).await }
    });
    let number_post = tokio::spawn({
        let client = client.clone();
        let session_id = session_id.clone();
        let body = held_request_body(number_id.clone());
        async move { post_jsonrpc(&client, port, &session_id, body).await }
    });

    let first = next_arrival(&mut fixture.arrivals).await;
    let second = next_arrival(&mut fixture.arrivals).await;
    let (string_arrival, number_arrival) = if first.id == string_id {
        (first, second)
    } else {
        (second, first)
    };
    string_arrival.release.send(()).expect("release string id");
    number_arrival.release.send(()).expect("release number id");

    let string_answer = string_post.await.expect("h2 string POST joined");
    let number_answer = number_post.await.expect("h2 number POST joined");
    let string_message = string_answer.post_stream_message("h2 string id");
    assert_eq!(string_message.event_id, 1);
    assert_response_identity(&string_message, &string_id, "string");
    let number_message = number_answer.post_stream_message("h2 number id");
    assert_eq!(number_message.event_id, 2);
    assert_response_identity(&number_message, &number_id, "number");

    // Ending the session ends the listener, and it must reach that end without
    // ever having carried either answer.
    delete_session(&client, port, &session_id).await;
    while let Some(record) = next_record_h2(&mut response, &mut cursor).await {
        assert!(
            is_comment_record(&record),
            "the h2c listener must never carry a POST response: {record:?}"
        );
    }

    drop(response);
    fixture.shutdown().await;
}

async fn next_record_h2(
    response: &mut reqwest::Response,
    cursor: &mut SseCursor,
) -> Option<String> {
    loop {
        if let Some(record) = cursor.take_record() {
            return Some(record);
        }
        let chunk = tokio::time::timeout(READ_TIMEOUT, response.chunk())
            .await
            .expect("timed out reading the h2c event stream")
            .expect("h2c event stream read failed");
        match chunk {
            Some(bytes) => cursor.feed(&bytes),
            None => return cursor.take_record(),
        }
    }
}

// ===========================================================================
// Native HTTP/3
// ===========================================================================

#[tokio::test]
#[ignore]
async fn functional_mcp_aggregate_sse_h3_multiplexes_concurrent_requests() {
    let mut fixture = SseFixture::start().await;
    let https_port = fixture.https_port();
    let url = format!("https://localhost:{https_port}/mcp");

    let client = Http3Client::insecure().expect("h3 client");
    let initialize = client
        .post_bytes(
            &url,
            serde_json::to_vec(&initialize_body()).expect("initialize body"),
        )
        .await
        .expect("h3 initialize");
    assert_eq!(
        initialize.status.as_u16(),
        200,
        "h3 initialize must succeed: {}",
        initialize.body_text()
    );
    let session_id = initialize
        .headers
        .get(SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("h3 initialize mints a session id")
        .to_string();

    let listener_client = Http3Client::insecure().expect("h3 listener client");
    let mut stream = listener_client
        .open_response_stream(
            &url,
            GetOptions::default()
                .header("accept", "text/event-stream")
                .header(SESSION_HEADER, session_id.clone())
                .header("mcp-protocol-version", PROTOCOL_VERSION),
        )
        .await
        .expect("open h3 SSE listener");
    let (status, headers) = stream.recv_response().await.expect("h3 listener response");
    assert_eq!(status.as_u16(), 200, "h3 listener attaches");
    assert_eq!(
        headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream"),
        "h3 listener must be an event stream"
    );
    assert!(
        headers.get("content-length").is_none(),
        "native H3 must not publish a content length for an event stream"
    );

    let mut cursor = SseCursor::default();
    let greeting = next_record_h3(&mut stream, &mut cursor)
        .await
        .expect("h3 listener must emit its opening comment");
    assert_eq!(greeting, SSE_GREETING_RECORD);

    let string_id = json!("h3");
    let number_id = json!(3);
    let string_post = tokio::spawn({
        let url = url.clone();
        let session_id = session_id.clone();
        let body = held_request_body(string_id.clone());
        async move { post_jsonrpc_h3(&url, &session_id, body).await }
    });
    let number_post = tokio::spawn({
        let url = url.clone();
        let session_id = session_id.clone();
        let body = held_request_body(number_id.clone());
        async move { post_jsonrpc_h3(&url, &session_id, body).await }
    });

    let first = next_arrival(&mut fixture.arrivals).await;
    let second = next_arrival(&mut fixture.arrivals).await;
    let (string_arrival, number_arrival) = if first.id == string_id {
        (first, second)
    } else {
        (second, first)
    };
    string_arrival.release.send(()).expect("release string id");
    number_arrival.release.send(()).expect("release number id");

    let string_answer = string_post.await.expect("h3 string POST joined");
    let number_answer = number_post.await.expect("h3 number POST joined");
    let string_message = string_answer.post_stream_message("h3 string id");
    assert_eq!(string_message.event_id, 1);
    assert_response_identity(&string_message, &string_id, "string");
    let number_message = number_answer.post_stream_message("h3 number id");
    assert_eq!(number_message.event_id, 2);
    assert_response_identity(&number_message, &number_id, "number");

    // Ending the session ends the native H3 listener with a clean FIN, and it
    // must reach that end without ever having carried either answer.
    delete_session_h3(&url, &session_id).await;
    while let Some(record) = next_record_h3(&mut stream, &mut cursor).await {
        assert!(
            is_comment_record(&record),
            "the h3 listener must never carry a POST response: {record:?}"
        );
    }

    drop(stream);
    fixture.shutdown().await;
}

/// End a downstream MCP session over native HTTP/3.
async fn delete_session_h3(url: &str, session_id: &str) {
    let client = Http3Client::insecure().expect("h3 delete client");
    let options = GetOptions::default()
        .method(http::Method::DELETE)
        .header(SESSION_HEADER, session_id.to_string())
        .header("mcp-protocol-version", PROTOCOL_VERSION);
    let mut stream = client
        .open_response_stream(url, options)
        .await
        .expect("h3 session DELETE");
    let (status, _) = stream.recv_response().await.expect("h3 DELETE response");
    assert_eq!(status.as_u16(), 200, "h3 session DELETE succeeds");
    while stream.recv_data().await.expect("h3 DELETE body").is_some() {}
}

/// POST one JSON-RPC message over native HTTP/3. Each call uses its own client
/// so two requests can genuinely be in flight at once.
async fn post_jsonrpc_h3(url: &str, session_id: &str, body: Value) -> PostAnswer {
    let client = Http3Client::insecure().expect("h3 post client");
    let options = GetOptions::default()
        .method(http::Method::POST)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header(SESSION_HEADER, session_id.to_string())
        .header("mcp-protocol-version", PROTOCOL_VERSION)
        .body(bytes::Bytes::from(
            serde_json::to_vec(&body).expect("JSON-RPC body serializes"),
        ));
    let mut stream = client
        .open_response_stream(url, options)
        .await
        .expect("h3 JSON-RPC POST");
    let (status, headers) = stream.recv_response().await.expect("h3 POST response");
    let content_type = headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let mut collected = Vec::new();
    while let Some(chunk) = stream.recv_data().await.expect("h3 POST body") {
        collected.extend_from_slice(&chunk);
        assert!(
            collected.len() <= MAX_MESSAGE_BYTES,
            "h3 POST response body exceeded the test ceiling"
        );
    }
    PostAnswer {
        status: status.as_u16(),
        content_type,
        body: String::from_utf8_lossy(&collected).to_string(),
    }
}

async fn next_record_h3(
    stream: &mut Http3ResponseStream,
    cursor: &mut SseCursor,
) -> Option<String> {
    loop {
        if let Some(record) = cursor.take_record() {
            return Some(record);
        }
        match stream.recv_data().await.expect("h3 event stream read") {
            Some(bytes) => cursor.feed(&bytes),
            None => return cursor.take_record(),
        }
    }
}

fn wire_id(body: &str) -> String {
    let fields: std::collections::BTreeMap<String, &serde_json::value::RawValue> =
        serde_json::from_str(body).unwrap();
    fields["id"].get().to_string()
}

async fn post_raw_jsonrpc(
    client: &reqwest::Client,
    port: u16,
    session: &str,
    body: String,
) -> PostAnswer {
    let response = client
        .post(mcp_url(port))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header(SESSION_HEADER, session)
        .header("mcp-protocol-version", PROTOCOL_VERSION)
        .body(body)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    PostAnswer {
        status,
        content_type,
        body: response.text().await.unwrap(),
    }
}

#[tokio::test]
#[ignore]
async fn functional_mcp_aggregate_sse_endpoint_scope_never_forwards_descendants() {
    for mode in ["aggregate_router", "transparent_proxy"] {
        let mut fixture = SseFixture::start_mode(mode).await;
        let port = fixture.http_port();
        let client = reqwest::Client::builder()
            .timeout(READ_TIMEOUT)
            .build()
            .unwrap();
        for suffix in ["/", "//", "/child"] {
            for method in [
                reqwest::Method::POST,
                reqwest::Method::GET,
                reqwest::Method::DELETE,
            ] {
                let response = client
                    .request(method, format!("{}{suffix}", mcp_url(port)))
                    .header("content-type", "application/json")
                    .body(r#"{"jsonrpc":"2.0","id":1,"method":"session/echo"}"#)
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status().as_u16(), 404, "{mode} {suffix}");
                let body: Value = response.json().await.unwrap();
                assert_eq!(body["error"]["code"], -32600);
            }
        }
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 0);
        // Positive controls use the same gateway and backend. A query does
        // not alter endpoint selection, and the exact endpoint still routes.
        let session = if mode == "aggregate_router" {
            initialize_session(&client, port).await
        } else {
            "transparent-session".to_string()
        };
        for query in ["", "?x=1"] {
            let post = tokio::spawn({
                let client = client.clone();
                let session = session.clone();
                async move {
                    client
                        .post(format!("{}{query}", mcp_url(port)))
                        .header(SESSION_HEADER, session)
                        .json(&held_request_body(json!("path-control")))
                        .send()
                        .await
                        .unwrap()
                }
            });
            let arrival = next_arrival(&mut fixture.arrivals).await;
            assert_eq!(arrival.id, json!("path-control"));
            arrival.release.send(()).unwrap();
            let response = post.await.unwrap();
            assert_eq!(response.status().as_u16(), 200);
            assert_eq!(wire_id(&response.text().await.unwrap()), "\"path-control\"");
        }
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 2);
        fixture.shutdown().await;
    }
}

#[tokio::test]
#[ignore]
async fn functional_mcp_aggregate_sse_raw_numeric_correlation_and_cancellation() {
    let mut fixture = SseFixture::start().await;
    let port = fixture.http_port();
    let client = reqwest::Client::builder()
        .timeout(READ_TIMEOUT)
        .build()
        .unwrap();
    let session = initialize_session(&client, port).await;
    let mut listener = attach_sse_h1_expect_attached(port, &session).await;
    listener.expect_greeting().await;
    let first_id = "18446744073709551616";
    let second_id = "18446744073709551617";

    // A wrong numeric reply is neither published nor returned as a successful
    // inline answer. The held request proves it reached the real backend.
    let wrong = tokio::spawn({
        let client = client.clone();
        let session = session.clone();
        async move {
            let body = format!(
                r#"{{"jsonrpc":"2.0","id":{first_id},"method":"session/echo","params":{{"responseId":{second_id}}}}}"#
            );
            post_raw_jsonrpc(&client, port, &session, body).await
        }
    });
    let arrival = next_arrival(&mut fixture.arrivals).await;
    assert_eq!(arrival.raw_id, first_id);
    assert!(
        !wrong.is_finished(),
        "the upstream is withholding its answer"
    );
    arrival.release.send(()).unwrap();
    let refusal = wrong.await.unwrap();
    assert_eq!(
        refusal.content_type, "application/json",
        "a gateway refusal replaces the answer inline, never as a framed event"
    );
    let body = refusal.body;
    let error: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(error["error"]["code"], -32603);
    assert!(error.get("result").is_none());
    // The refusal replaces the upstream answer, so it has to name the request
    // the client is still waiting on — with that request's exact wire token,
    // not the id the upstream wrongly echoed and not `null`.
    assert_eq!(
        wire_id(&body),
        first_id,
        "a refusal carrying no id would leave the pending call unresolved"
    );

    // The adjacent id remains independently admissible. A different session's
    // cancellation cannot cancel it, even with the exact same numeric token.
    let other_session = initialize_session(&client, port).await;
    let exact = tokio::spawn({
        let client = client.clone();
        let session = session.clone();
        async move {
            let body = format!(r#"{{"jsonrpc":"2.0","id":{second_id},"method":"session/echo"}}"#);
            post_raw_jsonrpc(&client, port, &session, body).await
        }
    });
    let arrival = next_arrival(&mut fixture.arrivals).await;
    assert_eq!(arrival.raw_id, second_id);
    let cancellation = format!(
        r#"{{"jsonrpc":"2.0","method":"notifications/cancelled","params":{{"requestId":{second_id}}}}}"#
    );
    let acknowledged = post_raw_jsonrpc(&client, port, &other_session, cancellation).await;
    assert_eq!(acknowledged.status, 202);
    arrival.release.send(()).unwrap();
    let answer = exact.await.unwrap();
    let message = answer.post_stream_message("exact numeric id");
    assert_eq!(
        message.event_id, 1,
        "the mismatched reply consumed no cursor"
    );
    assert_eq!(wire_id(&message.data), second_id);

    // Fractional spellings with the same f64 value also remain distinct.
    // Cancel only one while both backend requests are held open.
    let mut held = Vec::new();
    for id in ["1.00000000000000001", "1.00000000000000002"] {
        let post = tokio::spawn({
            let client = client.clone();
            let session = session.clone();
            async move {
                let body = format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"session/echo"}}"#);
                post_raw_jsonrpc(&client, port, &session, body).await
            }
        });
        let arrival = next_arrival(&mut fixture.arrivals).await;
        assert_eq!(arrival.raw_id, id);
        held.push((post, arrival));
    }
    let cancellation = r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1.00000000000000001}}"#;
    let acknowledged = post_raw_jsonrpc(&client, port, &session, cancellation.to_string()).await;
    assert_eq!(acknowledged.status, 202);
    let mut delivered = Vec::new();
    for (post, arrival) in held {
        arrival.release.send(()).unwrap();
        delivered.push(post.await.unwrap());
    }
    delivered[0].assert_suppressed("cancelled fractional id");
    let message = delivered[1].post_stream_message("uncancelled fractional id");
    assert_eq!(
        message.event_id, 2,
        "only the uncancelled response consumed a cursor"
    );
    assert_eq!(wire_id(&message.data), "1.00000000000000002");

    // The listener carried none of it: ending the session ends its stream, and
    // it reaches that end without a single message record.
    delete_session(&client, port, &session).await;
    listener.expect_end_without_message().await;
    fixture.shutdown().await;
}

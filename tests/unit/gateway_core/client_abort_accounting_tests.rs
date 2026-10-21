//! Issue #6768: an admitted H1/H2 request whose handler hyper drops before it
//! produced a response still gets exactly one terminal record.
//!
//! hyper drops a pending service future when an HTTP/2 client resets the
//! stream and when an HTTP/1.1 client closes the connection. These tests drive
//! the production accept loop (`start_proxy_listener_with_bound_listener`) and
//! pin, for each cancellation point:
//!
//! * one terminal status, `499`, in the gateway's request/status counters;
//! * the admission count released;
//! * no second record, including when the cancellation races the handler's
//!   own client-disconnect terminal (a buffered upload reset);
//! * an ordinary completion still records its real status, once.
//!
//! The `ClientAbortScope` tests below pin the transaction record itself
//! (status, class, `client_disconnected`, `response_delivery`), and the cases
//! where the scope must stay silent: normal completion, a hand-off to a later
//! terminal owner, and a terminal log already in flight.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use ferrum_edge::_test_support::CLIENT_CLOSED_REQUEST_STATUS;
use ferrum_edge::config::types::{GatewayConfig, Proxy};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::plugins::{
    Plugin, RequestContext, ResponseDelivery, TransactionSummary, log_with_mirror,
    spawn_bounded_terminal_summary_log,
};
use ferrum_edge::proxy::client_abort_scope::{
    CLIENT_ABORT_REJECTION_PHASE, ClientAbortScope, GATEWAY_CLOSED_REQUEST_STATUS,
    PROTOCOL_RESET_REJECTION_PHASE, PROTOCOL_RESET_REQUEST_STATUS, TerminationCause,
};
use ferrum_edge::proxy::{ProxyState, start_proxy_listener_with_bound_listener};
use ferrum_edge::retry::ErrorClass;

const WAIT: Duration = Duration::from_secs(10);
/// How long a terminal count must stay unchanged to count as settled.
const SETTLE: Duration = Duration::from_millis(300);

// ── Production listener harness ─────────────────────────────────────────────

struct Gateway {
    addr: SocketAddr,
    state: ProxyState,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    server: tokio::task::JoinHandle<Result<(), anyhow::Error>>,
}

impl Gateway {
    /// One proxy at `/slow` to `backend_port`. `retry` makes the route
    /// collect the request body before dispatch.
    async fn start(backend_port: u16, retry: bool) -> Self {
        let env = ferrum_edge::config::EnvConfig {
            mode: ferrum_edge::config::env_config::OperatingMode::File,
            log_level: "error".into(),
            proxy_http_port: 0,
            proxy_https_port: 0,
            admin_http_port: 0,
            admin_https_port: 0,
            max_connections: 0,
            shutdown_drain_seconds: 1,
            ..ferrum_edge::config::EnvConfig::default()
        };
        let mut proxy = json!({
            "id": "client-abort",
            "listen_path": "/slow",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
            "backend_read_timeout_ms": 60_000
        });
        if retry {
            proxy["retry"] = json!({ "max_retries": 1 });
        }
        let proxy: Proxy = serde_json::from_value(proxy).expect("test proxy");
        let config = GatewayConfig {
            version: "1".to_string(),
            proxies: vec![proxy],
            loaded_at: Utc::now(),
            ..GatewayConfig::default()
        };
        let state = ProxyState::new(config, DnsCache::new(DnsConfig::default()), env, None, None)
            .expect("proxy state")
            .0;
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind proxy listener");
        let addr = listener.local_addr().expect("proxy listener addr");
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let listener_state = state.clone();
        let server = tokio::spawn(async move {
            start_proxy_listener_with_bound_listener(listener, listener_state, shutdown_rx, None)
                .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        Self {
            addr,
            state,
            shutdown_tx,
            server,
        }
    }

    fn status_count(&self, status: u16) -> u64 {
        self.state
            .status_counts
            .get(&status)
            .map(|count| count.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    fn request_count(&self) -> u64 {
        self.state.request_count.load(Ordering::Relaxed)
    }

    fn active_requests(&self) -> u64 {
        self.state.overload.active_requests.load(Ordering::Relaxed)
    }

    /// Wait until exactly one request has a terminal status and every
    /// admission is released, then confirm nothing else arrives.
    async fn settled_single_terminal(&self, case: &str) {
        let deadline = Instant::now() + WAIT;
        while (self.request_count() == 0 || self.active_requests() != 0)
            && Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(SETTLE).await;
        assert_eq!(
            self.request_count(),
            1,
            "{case}: exactly one terminal status for one admitted request"
        );
        assert_eq!(
            self.active_requests(),
            0,
            "{case}: the request's admission must be released"
        );
    }

    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), self.server).await;
    }
}

/// A backend that reads each request head, reports it, and never answers.
/// It holds the connection open so the gateway stays parked waiting for the
/// response headers.
async fn start_silent_backend() -> (u16, mpsc::UnboundedReceiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind silent backend");
    let port = listener.local_addr().expect("backend addr").port();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut seen = Vec::new();
                let mut buf = [0u8; 4096];
                let mut reported = false;
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            seen.extend_from_slice(&buf[..n]);
                            if !reported && seen.windows(4).any(|w| w == b"\r\n\r\n") {
                                reported = true;
                                let _ = tx.send(());
                            }
                        }
                    }
                }
            });
        }
    });
    (port, rx)
}

/// A backend that answers every request `200 ok`.
async fn start_ok_backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ok backend");
    let port = listener.local_addr().expect("backend addr").port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut seen = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            seen.extend_from_slice(&buf[..n]);
                            if seen.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                    }
                }
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\
                          content-length: 2\r\nconnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = stream.shutdown().await;
            });
        }
    });
    port
}

async fn backend_saw_request(rx: &mut mpsc::UnboundedReceiver<()>, case: &str) {
    tokio::time::timeout(WAIT, rx.recv())
        .await
        .unwrap_or_else(|_| panic!("{case}: the backend never received the request"))
        .unwrap_or_else(|| panic!("{case}: the backend stopped"));
}

/// Every client handle for one HTTP/2 request, held until the test ends so
/// h2 does not reset the stream on its own.
struct H2Request {
    _client: h2::client::SendRequest<Bytes>,
    _response: h2::client::ResponseFuture,
    stream: h2::SendStream<Bytes>,
    ping_pong: h2::PingPong,
}

impl H2Request {
    /// Barrier: the gateway has accepted this stream, so the request is
    /// admitted. HTTP/2 frames are processed in order. The first PING may be
    /// flushed ahead of the request's frames, but the second is sent after the
    /// first PONG arrived and so after those frames, and the server accepts a
    /// stream in the same connection poll that reads its HEADERS.
    async fn admitted(&mut self) {
        for _ in 0..2 {
            tokio::time::timeout(WAIT, self.ping_pong.ping(h2::Ping::opaque()))
                .await
                .expect("PONG before the deadline")
                .expect("PING round trip");
        }
    }
}

async fn h2_request(addr: SocketAddr, method: &str, end_of_stream: bool) -> H2Request {
    let io = TcpStream::connect(addr).await.expect("connect gateway");
    let (client, mut connection) = h2::client::handshake(io).await.expect("h2c handshake");
    let ping_pong = connection.ping_pong().expect("user PING handle");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut client = client.ready().await.expect("h2 client ready");
    let request = http::Request::builder()
        .method(method)
        .uri("http://edge.example/slow")
        .body(())
        .expect("request");
    let (response, stream) = client
        .send_request(request, end_of_stream)
        .expect("request HEADERS");
    H2Request {
        _client: client,
        _response: response,
        stream,
        ping_pong,
    }
}

// ── Production listener: cancellation matrix ────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_reset_while_waiting_for_response_headers_records_one_client_abort() {
    let (backend_port, mut backend_seen) = start_silent_backend().await;
    let gateway = Gateway::start(backend_port, false).await;

    let mut request = h2_request(gateway.addr, "GET", true).await;
    backend_saw_request(&mut backend_seen, "h2 response-header wait").await;
    request.stream.send_reset(h2::Reason::CANCEL);

    gateway
        .settled_single_terminal("h2 response-header wait")
        .await;
    assert_eq!(
        gateway.status_count(CLIENT_CLOSED_REQUEST_STATUS),
        1,
        "the cancelled request is recorded as a client abort"
    );
    gateway.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_reset_during_buffered_upload_records_one_client_abort() {
    // The route collects the body before dispatch. Once the stream is
    // admitted, every cancellation point ends as exactly one `499`: before the
    // collect and while hyper drops the handler, the client-abort scope
    // records it; when the collect reads the reset first, the handler's own
    // client-disconnect terminal does, and the scope settles silently.
    let (backend_port, _backend_seen) = start_silent_backend().await;
    let gateway = Gateway::start(backend_port, true).await;

    let mut request = h2_request(gateway.addr, "POST", false).await;
    request
        .stream
        .send_data(Bytes::from_static(b"partial upload"), false)
        .expect("partial DATA");
    request.admitted().await;
    request.stream.send_reset(h2::Reason::CANCEL);

    gateway.settled_single_terminal("h2 buffered upload").await;
    assert_eq!(
        gateway.status_count(CLIENT_CLOSED_REQUEST_STATUS),
        1,
        "an abandoned upload is one client abort"
    );
    gateway.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h1_close_while_waiting_for_response_headers_records_one_client_abort() {
    let (backend_port, mut backend_seen) = start_silent_backend().await;
    let gateway = Gateway::start(backend_port, false).await;

    let mut client = TcpStream::connect(gateway.addr)
        .await
        .expect("connect gateway");
    client
        .write_all(b"GET /slow HTTP/1.1\r\nhost: edge.example\r\n\r\n")
        .await
        .expect("request head");
    backend_saw_request(&mut backend_seen, "h1 response-header wait").await;
    drop(client);

    gateway
        .settled_single_terminal("h1 response-header wait")
        .await;
    assert_eq!(gateway.status_count(CLIENT_CLOSED_REQUEST_STATUS), 1);
    gateway.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h1_close_during_websocket_upgrade_handshake_records_one_client_abort() {
    // The upgrade handler dials the backend and awaits its handshake response
    // while borrowing the request context from the scope, so a client that
    // leaves first is still one terminal.
    let (backend_port, mut backend_seen) = start_silent_backend().await;
    let gateway = Gateway::start(backend_port, false).await;

    let mut client = TcpStream::connect(gateway.addr)
        .await
        .expect("connect gateway");
    client
        .write_all(
            b"GET /slow HTTP/1.1\r\nhost: edge.example\r\nconnection: Upgrade\r\n\
              upgrade: websocket\r\nsec-websocket-version: 13\r\n\
              sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        )
        .await
        .expect("upgrade request head");
    backend_saw_request(&mut backend_seen, "websocket handshake").await;
    drop(client);

    gateway.settled_single_terminal("websocket handshake").await;
    assert_eq!(gateway.status_count(CLIENT_CLOSED_REQUEST_STATUS), 1);
    gateway.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_drain_end_closes_pending_requests_and_settles_their_terminals() {
    // A connection gracefully shutting down keeps serving its in-flight
    // request. When the serving mode stops waiting, the connection closes and
    // the dropped request settles its one `444` before
    // `end_shutdown_drain_wait` returns, which is before the mode closes
    // observability delivery.
    let (backend_port, mut backend_seen) = start_silent_backend().await;
    let gateway = Gateway::start(backend_port, false).await;

    let _request = h2_request(gateway.addr, "GET", true).await;
    backend_saw_request(&mut backend_seen, "shutdown drain end").await;
    // The drain flag only, not `begin_shutdown_drain`, whose fault-delay
    // cancellation is process-global.
    gateway
        .state
        .overload
        .draining
        .store(true, Ordering::Release);
    let _ = gateway.shutdown_tx.send(true);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        gateway.request_count(),
        0,
        "graceful shutdown keeps waiting for the in-flight request"
    );

    ferrum_edge::overload::end_shutdown_drain_wait(&gateway.state.overload).await;
    assert_eq!(
        gateway.active_requests(),
        0,
        "the request was released before the wait returned"
    );
    assert_eq!(gateway.request_count(), 1);
    assert_eq!(gateway.status_count(GATEWAY_CLOSED_REQUEST_STATUS), 1);
    assert_eq!(gateway.status_count(CLIENT_CLOSED_REQUEST_STATUS), 0);
    gateway.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn completed_h2_request_records_its_status_once() {
    let backend_port = start_ok_backend().await;
    let gateway = Gateway::start(backend_port, false).await;

    let io = TcpStream::connect(gateway.addr)
        .await
        .expect("connect gateway");
    let (client, connection) = h2::client::handshake(io).await.expect("h2c handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut client = client.ready().await.expect("h2 client ready");
    let request = http::Request::builder()
        .method("GET")
        .uri("http://edge.example/slow")
        .body(())
        .expect("request");
    let (response, _stream) = client.send_request(request, true).expect("request");
    let response = tokio::time::timeout(WAIT, response)
        .await
        .expect("gateway answered")
        .expect("response head");
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    while let Some(chunk) = tokio::time::timeout(WAIT, body.data())
        .await
        .expect("response body")
    {
        let chunk = chunk.expect("body chunk");
        let _ = body.flow_control().release_capacity(chunk.len());
    }

    gateway.settled_single_terminal("h2 completion").await;
    assert_eq!(gateway.status_count(200), 1);
    assert_eq!(
        gateway.status_count(CLIENT_CLOSED_REQUEST_STATUS),
        0,
        "a completed request is never also a client abort"
    );
    gateway.shutdown().await;
}

// ── ClientAbortScope: the transaction record and its exactly-once rules ─────

struct CapturingPlugin {
    captured: Arc<Mutex<Vec<TransactionSummary>>>,
}

#[async_trait]
impl Plugin for CapturingPlugin {
    fn name(&self) -> &str {
        "client-abort-capture"
    }

    fn priority(&self) -> u16 {
        9000
    }

    async fn log(&self, summary: &TransactionSummary) {
        self.captured
            .lock()
            .expect("captured summaries")
            .push(summary.clone());
    }
}

/// A `ProxyState` for driving a `ClientAbortScope` directly.
pub(super) fn scope_state() -> Arc<ProxyState> {
    let env = ferrum_edge::config::EnvConfig {
        mode: ferrum_edge::config::env_config::OperatingMode::File,
        log_level: "error".into(),
        proxy_http_port: 0,
        proxy_https_port: 0,
        admin_http_port: 0,
        admin_https_port: 0,
        ..ferrum_edge::config::EnvConfig::default()
    };
    let state = ProxyState::new(
        GatewayConfig::default(),
        DnsCache::new(DnsConfig::default()),
        env,
        None,
        None,
    )
    .expect("proxy state")
    .0;
    Arc::new(state)
}

type PluginChain = Arc<Vec<Arc<dyn Plugin>>>;
type Captured = Arc<Mutex<Vec<TransactionSummary>>>;

fn capture() -> (PluginChain, Captured) {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let plugin: Arc<dyn Plugin> = Arc::new(CapturingPlugin {
        captured: Arc::clone(&captured),
    });
    (Arc::new(vec![plugin]), captured)
}

fn request_context() -> RequestContext {
    RequestContext::new(
        "203.0.113.7".to_string(),
        "POST".to_string(),
        "/orders".to_string(),
    )
}

pub(super) fn status_count(state: &ProxyState, status: u16) -> u64 {
    state
        .status_counts
        .get(&status)
        .map(|count| count.load(Ordering::Relaxed))
        .unwrap_or(0)
}

/// Wait for at least `expected` captured summaries, then let any straggler
/// arrive so a duplicate would be seen.
async fn captured_after(captured: &Captured, expected: usize) -> Vec<TransactionSummary> {
    let deadline = Instant::now() + WAIT;
    while captured.lock().expect("captured").len() < expected && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    captured.lock().expect("captured").clone()
}

#[tokio::test]
async fn dropped_scope_logs_one_client_abort_record() {
    let state = scope_state();
    let (plugins, captured) = capture();
    let mut scope = ClientAbortScope::new();
    {
        let (ctx, record) = scope.install(
            &state,
            Instant::now(),
            http::Version::HTTP_11,
            request_context(),
        );
        ctx.headers
            .insert("user-agent".to_string(), "abort-test".to_string());
        record.observe_plugins(&plugins);
    }
    drop(scope);

    let summaries = captured_after(&captured, 1).await;
    assert_eq!(summaries.len(), 1, "exactly one terminal record");
    let summary = &summaries[0];
    assert_eq!(summary.response_status_code, CLIENT_CLOSED_REQUEST_STATUS);
    assert_eq!(summary.error_class, Some(ErrorClass::ClientDisconnect));
    assert!(summary.client_disconnected);
    assert!(!summary.body_completed);
    assert_eq!(summary.response_delivery, ResponseDelivery::Observed);
    assert_eq!(summary.http_method, "POST");
    assert_eq!(summary.request_path, "/orders");
    assert_eq!(summary.client_ip, "203.0.113.7");
    assert_eq!(summary.request_user_agent.as_deref(), Some("abort-test"));
    assert_eq!(
        summary.rejection_phase(),
        Some(CLIENT_ABORT_REJECTION_PHASE)
    );
    assert!(summary.latency_total_ms >= 0.0);

    let serialized = serde_json::to_value(summary).expect("serialize summary");
    assert_eq!(serialized["response_delivery"], "observed");
    assert_eq!(serialized["client_disconnected"], true);
    assert_eq!(serialized["error_class"], "client_disconnect");

    assert_eq!(status_count(&state, CLIENT_CLOSED_REQUEST_STATUS), 1);
    assert_eq!(state.request_count.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn dropped_grpc_scope_records_cancelled() {
    let state = scope_state();
    let (plugins, captured) = capture();
    let mut scope = ClientAbortScope::new();
    {
        let (ctx, record) = scope.install(
            &state,
            Instant::now(),
            http::Version::HTTP_11,
            request_context(),
        );
        ctx.metadata
            .insert("request_protocol".to_string(), "grpc".to_string());
        record.observe_plugins(&plugins);
    }
    drop(scope);

    let summaries = captured_after(&captured, 1).await;
    assert_eq!(summaries.len(), 1);
    assert_eq!(
        summaries[0].grpc_status(),
        Some(1),
        "a cancelled gRPC call is CANCELLED, not UNKNOWN"
    );
    assert_eq!(
        summaries[0].response_status_code,
        CLIENT_CLOSED_REQUEST_STATUS
    );
}

#[tokio::test]
async fn retained_client_path_is_logged_after_a_route_override() {
    let state = scope_state();
    let (plugins, captured) = capture();
    let mut scope = ClientAbortScope::new();
    {
        let (ctx, record) = scope.install(
            &state,
            Instant::now(),
            http::Version::HTTP_11,
            request_context(),
        );
        record.observe_plugins(&plugins);
        ctx.path = "/backend/rewritten".to_string();
        record.retain_client_request_path("/orders");
    }
    drop(scope);

    let summaries = captured_after(&captured, 1).await;
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].request_path, "/orders");
}

#[tokio::test]
async fn dropped_scope_without_plugins_still_counts_the_abort() {
    let state = scope_state();
    let mut scope = ClientAbortScope::new();
    let _ = scope.install(
        &state,
        Instant::now(),
        http::Version::HTTP_11,
        request_context(),
    );
    drop(scope);

    assert_eq!(status_count(&state, CLIENT_CLOSED_REQUEST_STATUS), 1);
    assert_eq!(state.request_count.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn completed_scope_records_nothing() {
    let state = scope_state();
    let (plugins, captured) = capture();
    let mut scope = ClientAbortScope::new();
    {
        let (_ctx, record) = scope.install(
            &state,
            Instant::now(),
            http::Version::HTTP_11,
            request_context(),
        );
        record.observe_plugins(&plugins);
    }
    scope.complete();
    assert!(!scope.is_installed(), "completion releases the context");
    drop(scope);

    assert!(captured_after(&captured, 0).await.is_empty());
    assert_eq!(state.request_count.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn handed_off_context_is_not_recorded_by_the_scope() {
    let state = scope_state();
    let (plugins, captured) = capture();
    let mut scope = ClientAbortScope::new();
    {
        let (_ctx, record) = scope.install(
            &state,
            Instant::now(),
            http::Version::HTTP_11,
            request_context(),
        );
        record.observe_plugins(&plugins);
    }
    let ctx = scope.hand_off().expect("installed context");
    drop(scope);
    drop(ctx);

    assert!(captured_after(&captured, 0).await.is_empty());
    assert_eq!(state.request_count.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn abort_after_the_terminal_log_finished_adds_no_second_record() {
    // The race with completion: the handler's own terminal log has finished
    // when hyper drops the handler. The scope must not add a client-abort
    // record on top of it, nor count a status the handler counts itself.
    let state = scope_state();
    let (plugins, captured) = capture();
    let mut scope = ClientAbortScope::new();
    {
        let (ctx, record) = scope.install(
            &state,
            Instant::now(),
            http::Version::HTTP_11,
            request_context(),
        );
        record.observe_plugins(&plugins);
        let summary = TransactionSummary {
            response_status_code: 200,
            ..TransactionSummary::default()
        };
        log_with_mirror(plugins.as_slice(), &summary, ctx).await;
        assert!(ctx.terminal_record_started());
    }
    drop(scope);

    let summaries = captured_after(&captured, 1).await;
    assert_eq!(summaries.len(), 1, "only the handler's own record");
    assert_eq!(summaries[0].response_status_code, 200);
    assert_eq!(status_count(&state, CLIENT_CLOSED_REQUEST_STATUS), 0);
    assert_eq!(state.request_count.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn a_cloned_context_does_not_carry_the_terminal_latch() {
    let ctx = request_context();
    let (plugins, _captured) = capture();
    let summary = TransactionSummary::default();
    log_with_mirror(plugins.as_slice(), &summary, &ctx).await;
    assert!(ctx.terminal_record_started());
    assert!(
        !ctx.clone().terminal_record_started(),
        "a clone is never the authoritative request"
    );
}

#[tokio::test]
async fn detached_terminal_delivery_latches_the_authoritative_context() {
    // The bounded detached delivery logs a clone; the request's own context
    // must still record that its terminal is in flight.
    let ctx = request_context();
    let (plugins, captured) = capture();
    spawn_bounded_terminal_summary_log(plugins.as_slice(), TransactionSummary::default(), &ctx);
    assert!(ctx.terminal_record_started());
    assert_eq!(captured_after(&captured, 1).await.len(), 1);
}

/// A sink whose first `log` parks until released; later calls return at once.
struct ParkingPlugin {
    calls: Arc<Mutex<Vec<u16>>>,
    started: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

#[async_trait]
impl Plugin for ParkingPlugin {
    fn name(&self) -> &str {
        "client-abort-parking"
    }

    fn priority(&self) -> u16 {
        9000
    }

    async fn log(&self, summary: &TransactionSummary) {
        let first = {
            let mut calls = self.calls.lock().expect("parking calls");
            calls.push(summary.response_status_code);
            calls.len() == 1
        };
        if first {
            self.started.notify_one();
            self.release.notified().await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_while_a_sink_is_pending_still_delivers_and_counts_once() {
    // hyper drops the handler while the first logging sink is genuinely
    // pending. The interrupted sink is never invoked again (it may already
    // have persisted the record), the later sink still receives the summary
    // once, and the status the handler would have counted after its log is
    // counted exactly once, with no client-abort record.
    let state = scope_state();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let captured: Captured = Arc::new(Mutex::new(Vec::new()));
    let plugins: PluginChain = Arc::new(vec![
        Arc::new(ParkingPlugin {
            calls: Arc::clone(&calls),
            started: Arc::clone(&started),
            release: Arc::clone(&release),
        }),
        Arc::new(CapturingPlugin {
            captured: Arc::clone(&captured),
        }),
    ]);

    let handler_state = Arc::clone(&state);
    let handler_plugins = Arc::clone(&plugins);
    let handler = tokio::spawn(async move {
        let mut scope = ClientAbortScope::new();
        {
            let (ctx, record) = scope.install(
                &handler_state,
                Instant::now(),
                http::Version::HTTP_11,
                request_context(),
            );
            record.observe_plugins(&handler_plugins);
            let summary = TransactionSummary {
                response_status_code: 201,
                ..TransactionSummary::default()
            };
            log_with_mirror(handler_plugins.as_slice(), &summary, ctx).await;
        }
        scope.complete();
    });
    tokio::time::timeout(WAIT, started.notified())
        .await
        .expect("the first sink started");
    handler.abort();
    let _ = handler.await;

    let summaries = captured_after(&captured, 1).await;
    assert_eq!(
        summaries.len(),
        1,
        "the later sink still receives the summary"
    );
    assert_eq!(summaries[0].response_status_code, 201);
    assert_eq!(
        calls.lock().expect("parking calls").as_slice(),
        [201],
        "a sink whose invocation started is never invoked again"
    );
    assert_eq!(status_count(&state, 201), 1, "the handler's status, once");
    assert_eq!(state.request_count.load(Ordering::Relaxed), 1);
    assert_eq!(status_count(&state, CLIENT_CLOSED_REQUEST_STATUS), 0);
    release.notify_waiters();
}

#[tokio::test]
async fn cancelled_grpc_overrides_a_stale_backend_status() {
    // A buffered native-gRPC path copies the backend's trailers into the
    // context before its response hooks; a reset during those hooks means the
    // client never received that outcome.
    let state = scope_state();
    let (plugins, captured) = capture();
    let mut scope = ClientAbortScope::new();
    {
        let (ctx, record) = scope.install(
            &state,
            Instant::now(),
            http::Version::HTTP_11,
            request_context(),
        );
        ctx.metadata
            .insert("request_protocol".to_string(), "grpc".to_string());
        ctx.metadata
            .insert("grpc_status".to_string(), "0".to_string());
        record.observe_plugins(&plugins);
    }
    drop(scope);

    let summaries = captured_after(&captured, 1).await;
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].grpc_status(), Some(1));
    assert_eq!(
        summaries[0].response_status_code,
        CLIENT_CLOSED_REQUEST_STATUS
    );
}

#[tokio::test]
async fn shutdown_teardown_drop_is_a_gateway_close_not_a_client_abort() {
    // Once shutdown stops waiting for in-flight work, the gateway tears the
    // remaining handlers down itself.
    let state = scope_state();
    let (plugins, captured) = capture();
    let mut scope = ClientAbortScope::new();
    {
        let (_ctx, record) = scope.install(
            &state,
            Instant::now(),
            http::Version::HTTP_11,
            request_context(),
        );
        record.observe_plugins(&plugins);
    }
    state.overload.draining.store(true, Ordering::Release);
    ferrum_edge::overload::end_shutdown_drain_wait(&state.overload).await;
    drop(scope);

    let summaries = captured_after(&captured, 1).await;
    assert_eq!(summaries.len(), 1);
    let summary = &summaries[0];
    assert_eq!(summary.response_status_code, GATEWAY_CLOSED_REQUEST_STATUS);
    assert!(
        !summary.client_disconnected,
        "no client cancellation proven"
    );
    assert_eq!(summary.error_class, None);
    assert_eq!(
        summary.rejection_phase(),
        Some(TerminationCause::ShutdownTeardown.rejection_phase())
    );
    assert_eq!(status_count(&state, GATEWAY_CLOSED_REQUEST_STATUS), 1);
    assert_eq!(status_count(&state, CLIENT_CLOSED_REQUEST_STATUS), 0);
    assert_eq!(state.request_count.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn authorization_close_drops_a_sibling_stream_as_a_gateway_close() {
    // One stream's authorization lifetime closed the connection; a sibling
    // gRPC stream with valid credentials, still waiting on its backend, is
    // dropped by that close. Its own authentication never failed.
    let state = scope_state();
    let (plugins, captured) = capture();
    let closer = ferrum_edge::proxy::auth_lifetime::AuthorizationConnectionCloser::new();
    let mut scope = ClientAbortScope::new();
    {
        let (ctx, record) = scope.install(
            &state,
            Instant::now(),
            http::Version::HTTP_2,
            request_context(),
        );
        ctx.metadata
            .insert("request_protocol".to_string(), "grpc".to_string());
        ferrum_edge::_test_support::attach_authorization_connection_closer_for_test(
            ctx,
            closer.clone(),
        );
        record.observe_plugins(&plugins);
    }
    closer.request_close();
    drop(scope);

    let summaries = captured_after(&captured, 1).await;
    assert_eq!(summaries.len(), 1, "the sibling still gets one terminal");
    assert_eq!(
        summaries[0].response_status_code,
        GATEWAY_CLOSED_REQUEST_STATUS
    );
    assert_eq!(
        summaries[0].rejection_phase(),
        Some(TerminationCause::AuthorizationConnectionClose.rejection_phase())
    );
    assert_eq!(
        summaries[0].grpc_status(),
        Some(14),
        "collateral connection loss is UNAVAILABLE, never UNAUTHENTICATED"
    );
    assert_eq!(status_count(&state, GATEWAY_CLOSED_REQUEST_STATUS), 1);
    assert_eq!(status_count(&state, CLIENT_CLOSED_REQUEST_STATUS), 0);
}

#[tokio::test]
async fn http1_drop_during_graceful_drain_is_still_a_client_abort() {
    // During the drain wait the gateway only waits for in-flight work; an
    // HTTP/1.1 handler dropped then lost its client.
    let state = scope_state();
    let mut scope = ClientAbortScope::new();
    let _ = scope.install(
        &state,
        Instant::now(),
        http::Version::HTTP_11,
        request_context(),
    );
    state.overload.draining.store(true, Ordering::Release);
    drop(scope);

    assert_eq!(status_count(&state, CLIENT_CLOSED_REQUEST_STATUS), 1);
    assert_eq!(status_count(&state, GATEWAY_CLOSED_REQUEST_STATUS), 0);
}

#[tokio::test]
async fn unattributed_http2_drop_is_never_a_client_abort() {
    // An HTTP/2 handler dropped without a termination cause from hyper (none
    // was published for it) carries no evidence of the peer's cancellation.
    let state = scope_state();
    let (plugins, captured) = capture();
    let mut scope = ClientAbortScope::new();
    {
        let (_ctx, record) = scope.install(
            &state,
            Instant::now(),
            http::Version::HTTP_2,
            request_context(),
        );
        record.observe_plugins(&plugins);
    }
    drop(scope);

    let summaries = captured_after(&captured, 1).await;
    assert_eq!(summaries.len(), 1);
    assert_eq!(
        summaries[0].response_status_code,
        GATEWAY_CLOSED_REQUEST_STATUS
    );
    assert!(!summaries[0].client_disconnected);
    assert_eq!(
        summaries[0].rejection_phase(),
        Some(TerminationCause::Unattributed.rejection_phase())
    );
    assert_eq!(status_count(&state, CLIENT_CLOSED_REQUEST_STATUS), 0);
}

#[tokio::test]
async fn a_counted_request_is_not_counted_again() {
    // A handler that counted its status before an await it was dropped in
    // keeps that count; the scope logs the abort without counting twice.
    let state = scope_state();
    let (plugins, captured) = capture();
    let mut scope = ClientAbortScope::new();
    {
        let (ctx, record) = scope.install(
            &state,
            Instant::now(),
            http::Version::HTTP_11,
            request_context(),
        );
        record.observe_plugins(&plugins);
        ferrum_edge::_test_support::mark_terminal_status_counted_for_test(ctx);
    }
    drop(scope);

    assert_eq!(captured_after(&captured, 1).await.len(), 1);
    assert_eq!(state.request_count.load(Ordering::Relaxed), 0);
    assert_eq!(status_count(&state, CLIENT_CLOSED_REQUEST_STATUS), 0);
}

/// One HTTP/2 frame: 9-byte header, then `payload`.
fn h2_frame(kind: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut frame = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Serve one raw HTTP/2 connection whose handler installs a production
/// `ClientAbortScope` and then stays pending, open stream 1 (a POST declaring
/// `content-length: 1`), and wait until the handler runs. Returns the client's
/// write half for the frames that end the stream.
async fn open_pending_h2_stream(
    state: &Arc<ProxyState>,
    plugins: &PluginChain,
) -> tokio::io::WriteHalf<tokio::io::DuplexStream> {
    use std::convert::Infallible;

    use http_body_util::Empty;
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let (called_tx, mut called_rx) = mpsc::unbounded_channel::<()>();
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let service_state = Arc::clone(state);
    let service_plugins = Arc::clone(plugins);
    let service = service_fn(move |_request: Request<Incoming>| {
        let state = Arc::clone(&service_state);
        let plugins = Arc::clone(&service_plugins);
        let called = called_tx.clone();
        async move {
            let mut scope = ClientAbortScope::new();
            {
                let (_ctx, record) = scope.install(
                    &state,
                    Instant::now(),
                    http::Version::HTTP_2,
                    request_context(),
                );
                record.observe_plugins(&plugins);
            }
            let _ = called.send(());
            std::future::pending::<()>().await;
            scope.complete();
            Ok::<_, Infallible>(Response::new(Empty::<Bytes>::new()))
        }
    });
    tokio::spawn(async move {
        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(server_io), service)
            .await;
    });

    let (mut client_read, mut client_write) = tokio::io::split(client_io);
    // Drain whatever the server writes so it never blocks on the duplex.
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok(n) = client_read.read(&mut buf).await {
            if n == 0 {
                break;
            }
        }
    });
    let mut opening = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    opening.extend(h2_frame(0x4, 0, 0, &[]));
    // HPACK: :method POST, :scheme http, :path /, :authority x (literal,
    // indexed name 1), content-length: 1 (literal, indexed name 28).
    let headers = [0x83, 0x86, 0x84, 0x01, 0x01, b'x', 0x0F, 0x0D, 0x01, b'1'];
    opening.extend(h2_frame(0x1, 0x4, 1, &headers));
    client_write
        .write_all(&opening)
        .await
        .expect("preface and HEADERS");
    tokio::time::timeout(WAIT, called_rx.recv())
        .await
        .expect("the handler runs")
        .expect("handler signal");
    client_write
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_local_protocol_reset_is_a_protocol_error_not_a_client_abort() {
    // The client declares `content-length: 1` and sends five bytes. hyper's
    // HTTP/2 stack resets the stream with PROTOCOL_ERROR itself while the
    // handler is pending: a local protocol rejection, not the peer's
    // cancellation.
    let state = scope_state();
    let (plugins, captured) = capture();
    let mut client_write = open_pending_h2_stream(&state, &plugins).await;
    client_write
        .write_all(&h2_frame(0x0, 0, 1, b"hello"))
        .await
        .expect("DATA past content-length");

    let summaries = captured_after(&captured, 1).await;
    assert_eq!(summaries.len(), 1, "exactly one terminal record");
    let summary = &summaries[0];
    assert_eq!(summary.response_status_code, PROTOCOL_RESET_REQUEST_STATUS);
    assert!(!summary.client_disconnected);
    assert_eq!(summary.error_class, Some(ErrorClass::ProtocolError));
    assert_eq!(
        summary.rejection_phase(),
        Some(PROTOCOL_RESET_REJECTION_PHASE)
    );
    assert_eq!(status_count(&state, PROTOCOL_RESET_REQUEST_STATUS), 1);
    assert_eq!(status_count(&state, CLIENT_CLOSED_REQUEST_STATUS), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_peer_reset_during_shutdown_teardown_is_still_a_client_abort() {
    // Explicit stream evidence beats connection-close state: the client's own
    // RST_STREAM(CANCEL) after shutdown stopped waiting is its cancellation,
    // not the gateway's teardown.
    let state = scope_state();
    let (plugins, captured) = capture();
    let mut client_write = open_pending_h2_stream(&state, &plugins).await;
    state.overload.draining.store(true, Ordering::Release);
    // Nothing is in flight on this state's counters, so this returns at once.
    ferrum_edge::overload::end_shutdown_drain_wait(&state.overload).await;
    client_write
        .write_all(&h2_frame(0x3, 0, 1, &0x8u32.to_be_bytes()))
        .await
        .expect("RST_STREAM(CANCEL)");

    let summaries = captured_after(&captured, 1).await;
    assert_eq!(summaries.len(), 1, "exactly one terminal record");
    assert_eq!(
        summaries[0].response_status_code,
        CLIENT_CLOSED_REQUEST_STATUS
    );
    assert!(summaries[0].client_disconnected);
    assert_eq!(status_count(&state, CLIENT_CLOSED_REQUEST_STATUS), 1);
    assert_eq!(status_count(&state, GATEWAY_CLOSED_REQUEST_STATUS), 0);
}

#[test]
fn vendored_h2_exposes_the_reset_origin_hyper_patch_006_reads() {
    // Hyper patch 006 falls back to "origin unknown" against stock h2. Bind the
    // vendored h2 patch 004 accessor's exact signature so the gateway build
    // fails, rather than silently attributing nothing, if it goes missing.
    let accessor: fn(&h2::server::SendResponse<Bytes>) -> Option<bool> =
        h2::server::SendResponse::<Bytes>::reset_is_local;
    let _ = accessor;
}

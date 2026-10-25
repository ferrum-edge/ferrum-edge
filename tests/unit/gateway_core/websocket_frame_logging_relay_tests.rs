//! End-to-end `ws_frame_logging` behavior through the production framed relay
//! (`run_websocket_session`, shared by H1 Upgrade and H2/H3 Extended CONNECT).
//!
//! ws_frame_logging-SOL-1 / M1: every gateway-published policy Close —
//! whatever plugin or parser produced it and wherever the logger sits in
//! priority order — must produce exactly one `outcome=policy_close` record.
//! ws_frame_logging-SOL-2: a client-transport failure the H3 bridge observes
//! after the framer accepted the final Close must reach the disconnect record
//! instead of a clean terminal.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use ferrum_edge::_test_support::{StreamIoSide, make_ws_session_meta};
use ferrum_edge::plugins::ws_frame_logging::WsFrameLogging;
use ferrum_edge::plugins::ws_message_size_limiting::WsMessageSizeLimiting;
use ferrum_edge::plugins::{
    Direction, Plugin, ProxyProtocol, WS_ONLY_PROTOCOLS, WebSocketFrameDirection,
    WsDisconnectContext,
};
use ferrum_edge::retry::ErrorClass;
use futures_util::SinkExt;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::frame::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{Message, Role};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;

const MASK: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];
const RELAY_BOUND: Duration = Duration::from_secs(10);

// ── ws_frame_log capture ─────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
struct Record {
    outcome: Option<String>,
    event: Option<String>,
    direction: Option<String>,
    close_code: Option<u64>,
}

#[derive(Clone, Default)]
struct Capture {
    records: Arc<Mutex<Vec<Record>>>,
}

impl Capture {
    fn records(&self) -> Vec<Record> {
        self.records.lock().unwrap().clone()
    }

    fn with_outcome(&self, outcome: &str) -> Vec<Record> {
        self.records()
            .into_iter()
            .filter(|record| record.outcome.as_deref() == Some(outcome))
            .collect()
    }
}

struct CaptureLayer {
    records: Arc<Mutex<Vec<Record>>>,
}

impl<S> tracing_subscriber::Layer<S> for CaptureLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != "ws_frame_log" {
            return;
        }
        let mut record = Record::default();
        event.record(&mut RecordVisitor(&mut record));
        self.records.lock().unwrap().push(record);
    }
}

struct RecordVisitor<'a>(&'a mut Record);

impl tracing::field::Visit for RecordVisitor<'_> {
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        if field.name() == "close_code" {
            self.0.close_code = Some(value);
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        if value >= 0 {
            self.record_u64(field, value as u64);
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        match field.name() {
            "outcome" => self.0.outcome = Some(value.to_string()),
            "event" => self.0.event = Some(value.to_string()),
            "direction" => self.0.direction = Some(value.to_string()),
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let rendered = format!("{value:?}").trim_matches('"').to_string();
        match field.name() {
            "outcome" => self.0.outcome = Some(rendered),
            "event" => self.0.event = Some(rendered),
            "direction" => self.0.direction = Some(rendered),
            "close_code" => {
                if let Ok(parsed) = rendered.parse::<u64>() {
                    self.0.close_code = Some(parsed);
                }
            }
            _ => {}
        }
    }
}

fn install_capture(capture: &Capture) -> tracing::subscriber::DefaultGuard {
    crate::diagnostic_test_interest::ensure_interest_floor();
    let guard =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(CaptureLayer {
            records: Arc::clone(&capture.records),
        }));
    tracing::callsite::rebuild_interest_cache();
    guard
}

// ── Test plugins ─────────────────────────────────────────────────────────

/// Closes any Text longer than 8 bytes with 1009 from `on_ws_frame`.
struct SizeReject {
    invocations: AtomicU64,
}

#[async_trait]
impl Plugin for SizeReject {
    fn name(&self) -> &str {
        "test_relay_size_reject"
    }

    fn priority(&self) -> u16 {
        2810
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        WS_ONLY_PROTOCOLS
    }

    fn requires_ws_frame_hooks(&self) -> bool {
        true
    }

    async fn on_ws_frame(
        &self,
        _proxy_id: &str,
        _connection_id: u64,
        _direction: WebSocketFrameDirection,
        message: &Message,
    ) -> Option<Message> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        match message {
            Message::Text(text) if text.len() > 8 => Some(Message::Close(Some(CloseFrame {
                code: CloseCode::Size,
                reason: "too large".into(),
            }))),
            _ => None,
        }
    }
}

/// Refuses every reassembly-fragment batch with a 1008 policy Close.
struct FragmentReject;

#[async_trait]
impl Plugin for FragmentReject {
    fn name(&self) -> &str {
        "test_relay_fragment_reject"
    }

    fn priority(&self) -> u16 {
        2910
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        WS_ONLY_PROTOCOLS
    }

    fn requires_ws_frame_hooks(&self) -> bool {
        true
    }

    async fn on_ws_reassembly_frames(
        &self,
        _proxy_id: &str,
        _connection_id: u64,
        _direction: WebSocketFrameDirection,
        _fragment_frames: u64,
    ) -> Option<Message> {
        Some(Message::Close(Some(CloseFrame {
            code: CloseCode::Policy,
            reason: "fragment budget".into(),
        })))
    }
}

type DisconnectFacts = (
    Option<Direction>,
    Option<StreamIoSide>,
    Option<ErrorClass>,
    Option<String>,
);

/// Captures the attribution fields of every `on_ws_disconnect`.
#[derive(Default)]
struct DisconnectRecorder {
    seen: Mutex<Vec<DisconnectFacts>>,
}

#[async_trait]
impl Plugin for DisconnectRecorder {
    fn name(&self) -> &str {
        "test_relay_disconnect_recorder"
    }

    fn priority(&self) -> u16 {
        9500
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        WS_ONLY_PROTOCOLS
    }

    fn requires_ws_disconnect_hooks(&self) -> bool {
        true
    }

    async fn on_ws_disconnect(&self, ctx: &WsDisconnectContext) {
        self.seen.lock().unwrap().push((
            ctx.direction,
            ctx.io_side,
            ctx.error_class,
            ctx.metadata.get("websocket.termination_reason").cloned(),
        ));
    }
}

// ── Relay harness ────────────────────────────────────────────────────────

/// One masked client→gateway frame with an explicit first byte.
fn masked_client_frame(first: u8, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 126, "test frames use the 7-bit length form");
    let mut out = vec![first, 0x80 | payload.len() as u8];
    out.extend_from_slice(&MASK);
    out.extend(
        payload
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ MASK[index % 4]),
    );
    out
}

fn session_meta(connection_id: u64) -> ferrum_edge::proxy::WsSessionMeta {
    let mut meta = make_ws_session_meta(
        "ferrum".to_string(),
        Some("ws-relay".to_string()),
        "10.0.0.7".to_string(),
        "backend:9000".to_string(),
        8000,
        None,
        ferrum_edge::plugins::MetadataMap::default(),
        chrono::Utc::now(),
    );
    meta.connection_id = connection_id;
    meta
}

struct RelayEnds {
    /// The gateway's client-side transport (handed to the relay).
    gateway_client_io: DuplexStream,
    /// The test's raw client end of that transport.
    client_raw: DuplexStream,
    /// The gateway's client-role framer toward the backend (handed to the relay).
    gateway_backend: WebSocketStream<DuplexStream>,
    /// The test's server-role backend framer.
    backend_peer: WebSocketStream<DuplexStream>,
}

async fn relay_ends() -> RelayEnds {
    let (gateway_client_io, client_raw) = tokio::io::duplex(64 * 1024);
    let (gateway_backend_io, backend_peer_io) = tokio::io::duplex(64 * 1024);
    let gateway_backend =
        WebSocketStream::from_raw_socket(gateway_backend_io, Role::Client, None).await;
    let backend_peer = WebSocketStream::from_raw_socket(backend_peer_io, Role::Server, None).await;
    RelayEnds {
        gateway_client_io,
        client_raw,
        gateway_backend,
        backend_peer,
    }
}

/// Write `client_bytes` from the client, run the relay to completion, and
/// keep both peers alive until it returns.
async fn run_relay_with_client_bytes(
    plugins: &[Arc<dyn Plugin>],
    connection_id: u64,
    client_bytes: Vec<u8>,
) {
    let RelayEnds {
        gateway_client_io,
        mut client_raw,
        gateway_backend,
        backend_peer,
    } = relay_ends().await;
    let relay = ferrum_edge::_test_support::run_framed_websocket_relay_for_test(
        gateway_client_io,
        gateway_backend,
        "ws-proxy",
        connection_id,
        plugins,
        session_meta(connection_id),
        None,
    );
    let driver = async {
        client_raw
            .write_all(&client_bytes)
            .await
            .expect("client bytes reach the gateway");
    };
    let (result, ()) = tokio::time::timeout(RELAY_BOUND, async { tokio::join!(relay, driver) })
        .await
        .expect("the relay must end after a policy Close");
    result.expect("relay returns Ok");
    drop(backend_peer);
}

/// Send `message` from the backend, run the relay to completion, and keep
/// both peers alive until it returns.
async fn run_relay_with_backend_message(
    plugins: &[Arc<dyn Plugin>],
    connection_id: u64,
    message: Message,
) {
    let RelayEnds {
        gateway_client_io,
        client_raw,
        gateway_backend,
        mut backend_peer,
    } = relay_ends().await;
    let relay = ferrum_edge::_test_support::run_framed_websocket_relay_for_test(
        gateway_client_io,
        gateway_backend,
        "ws-proxy",
        connection_id,
        plugins,
        session_meta(connection_id),
        None,
    );
    let driver = async {
        backend_peer
            .send(message)
            .await
            .expect("backend message reaches the gateway");
    };
    let (result, ()) = tokio::time::timeout(RELAY_BOUND, async { tokio::join!(relay, driver) })
        .await
        .expect("the relay must end after a policy Close");
    result.expect("relay returns Ok");
    drop(client_raw);
}

fn logger() -> Arc<dyn Plugin> {
    Arc::new(WsFrameLogging::new(&json!({})).expect("valid logger config"))
}

fn assert_one_policy_close(capture: &Capture, code: u64, direction: &str) {
    let closes = capture.with_outcome("policy_close");
    assert_eq!(closes.len(), 1, "{:?}", capture.records());
    assert_eq!(closes[0].close_code, Some(code), "{closes:?}");
    assert_eq!(
        closes[0].direction.as_deref(),
        Some(direction),
        "{closes:?}"
    );
    assert!(
        capture.with_outcome("delivered").is_empty(),
        "a rejected message must not also be recorded as delivered: {:?}",
        capture.records()
    );
    assert_eq!(
        capture
            .records()
            .iter()
            .filter(|record| record.event.as_deref() == Some("disconnect"))
            .count(),
        1,
        "{:?}",
        capture.records()
    );
}

// ── Policy Close observation (SOL-1 / M1) ────────────────────────────────

/// A `priority_override` that orders the logger before the rejecting plugin
/// must not hide the rejection, in either relay direction.
#[tokio::test(flavor = "current_thread")]
async fn logger_before_rejecting_plugin_records_policy_close_client_to_backend() {
    let capture = Capture::default();
    let _guard = install_capture(&capture);
    let size = Arc::new(SizeReject {
        invocations: AtomicU64::new(0),
    });
    let plugins: Vec<Arc<dyn Plugin>> = vec![logger(), size.clone()];

    run_relay_with_client_bytes(&plugins, 101, masked_client_frame(0x81, b"oversized!")).await;

    assert_eq!(size.invocations.load(Ordering::SeqCst), 1);
    assert_one_policy_close(&capture, 1009, "client->backend");
}

#[tokio::test(flavor = "current_thread")]
async fn logger_before_rejecting_plugin_records_policy_close_backend_to_client() {
    let capture = Capture::default();
    let _guard = install_capture(&capture);
    let size = Arc::new(SizeReject {
        invocations: AtomicU64::new(0),
    });
    let plugins: Vec<Arc<dyn Plugin>> = vec![logger(), size.clone()];

    run_relay_with_backend_message(&plugins, 102, Message::Text("oversized!".into())).await;

    assert_eq!(size.invocations.load(Ordering::SeqCst), 1);
    assert_one_policy_close(&capture, 1009, "backend->client");
}

/// Parser-level `ws_message_size_limiting` rejections never enter the
/// `on_ws_frame` chain; they must still be recorded.
#[tokio::test(flavor = "current_thread")]
async fn parser_size_limit_rejection_records_policy_close() {
    let capture = Capture::default();
    let _guard = install_capture(&capture);
    let limiter: Arc<dyn Plugin> = Arc::new(
        WsMessageSizeLimiting::new(&json!({"max_frame_bytes": 16})).expect("valid limiter"),
    );
    let plugins: Vec<Arc<dyn Plugin>> = vec![limiter, logger()];

    run_relay_with_client_bytes(&plugins, 103, masked_client_frame(0x81, &[b'a'; 64])).await;

    assert_one_policy_close(&capture, 1009, "client->backend");
}

/// Fragment-budget Closes come from `on_ws_reassembly_frames`, which skips
/// observers; the decision must still reach the logger.
#[tokio::test(flavor = "current_thread")]
async fn fragment_budget_rejection_records_policy_close() {
    let capture = Capture::default();
    let _guard = install_capture(&capture);
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(FragmentReject), logger()];

    // A two-fragment Text: non-final Text frame, then a final continuation.
    let mut wire = masked_client_frame(0x01, b"ab");
    wire.extend(masked_client_frame(0x80, b"cd"));
    run_relay_with_client_bytes(&plugins, 104, wire).await;

    assert_one_policy_close(&capture, 1008, "client->backend");
}

// ── H3 bridge transport verdict (SOL-2) ──────────────────────────────────

/// Model the H3 send pump: drain everything the framer wrote until the relay
/// drops its client transport (EOF), then report `verdict`. If the relay
/// waited for this before releasing the transport, the test would time out.
fn pump_settle(
    mut client_raw: DuplexStream,
    verdict: Option<ferrum_edge::proxy::WsRelayFailure>,
) -> ferrum_edge::proxy::WsClientTransportSettle<'static> {
    Box::pin(async move {
        let mut sink = Vec::new();
        client_raw
            .read_to_end(&mut sink)
            .await
            .expect("drain the bridged client bytes");
        assert!(!sink.is_empty(), "the forwarded Close reaches the bridge");
        verdict
    })
}

async fn run_backend_close_with_settle(
    plugins: &[Arc<dyn Plugin>],
    connection_id: u64,
    verdict: Option<ferrum_edge::proxy::WsRelayFailure>,
) {
    let RelayEnds {
        gateway_client_io,
        client_raw,
        gateway_backend,
        mut backend_peer,
    } = relay_ends().await;
    let relay = ferrum_edge::_test_support::run_framed_websocket_relay_for_test(
        gateway_client_io,
        gateway_backend,
        "ws-proxy",
        connection_id,
        plugins,
        session_meta(connection_id),
        Some(pump_settle(client_raw, verdict)),
    );
    let driver = async {
        backend_peer
            .send(Message::Close(Some(CloseFrame {
                code: CloseCode::Normal,
                reason: "bye".into(),
            })))
            .await
            .expect("backend Close reaches the gateway");
    };
    let (result, ()) = tokio::time::timeout(RELAY_BOUND, async { tokio::join!(relay, driver) })
        .await
        .expect("the relay must release the client transport before settling the bridge");
    result.expect("relay returns Ok");
    drop(backend_peer);
}

/// The framer accepted the backend's clean 1000 Close, but the bridge then
/// failed to deliver it (e.g. client `STOP_SENDING`). The disconnect record
/// must carry that failure, not a clean close.
#[tokio::test(flavor = "current_thread")]
async fn h3_bridge_failure_after_final_close_reaches_disconnect_record() {
    let recorder = Arc::new(DisconnectRecorder::default());
    let plugins: Vec<Arc<dyn Plugin>> = vec![recorder.clone()];

    run_backend_close_with_settle(
        &plugins,
        105,
        Some((
            Direction::BackendToClient,
            ErrorClass::ClientDisconnect,
            Some(StreamIoSide::Write),
        )),
    )
    .await;

    let seen = recorder.seen.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![(
            Some(Direction::BackendToClient),
            Some(StreamIoSide::Write),
            Some(ErrorClass::ClientDisconnect),
            Some("relay_error".to_string()),
        )],
        "exactly one terminal record, attributed to the bridge write"
    );
}

/// A bridge that delivered everything leaves the clean classification alone.
#[tokio::test(flavor = "current_thread")]
async fn clean_h3_bridge_keeps_clean_disconnect_record() {
    let recorder = Arc::new(DisconnectRecorder::default());
    let plugins: Vec<Arc<dyn Plugin>> = vec![recorder.clone()];

    run_backend_close_with_settle(&plugins, 106, None).await;

    let seen = recorder.seen.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![(None, None, None, Some("normal_peer_close".to_string()))]
    );
}

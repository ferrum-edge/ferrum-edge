//! Physical WebSocket fragment metering for the shared H1/H2/H3 relay
//! (GHSA-qq94-2gv2-phh6).
//!
//! Tungstenite hands the relay only reassembled messages, so the initial
//! non-final Text/Binary frame and every intermediate Continuation frame —
//! including zero-length ones — are invisible to `on_ws_frame`. Before the fix
//! a peer could send an unbounded stream of empty continuation frames and pay
//! `ws_rate_limiting` for at most one logical message per completed reassembly.
//!
//! The relay now charges those fragments through `on_ws_reassembly_frames`
//! before admitting the completing message, and the parser independently bounds
//! how many frames and how long a message may stay incomplete.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use ferrum_edge::plugins::PluginHttpClient;
use ferrum_edge::plugins::ws_rate_limiting::WsRateLimiting;
use ferrum_edge::plugins::{Plugin, ProxyProtocol, WS_ONLY_PROTOCOLS, WebSocketFrameDirection};
use futures_util::StreamExt;
use serde_json::json;
use tokio::io::AsyncWriteExt;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::tungstenite::error::ProtocolError;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{FragmentMeter, Message, Role, WebSocketConfig};

const PROXY_ID: &str = "ws-fragment-proxy";

fn rate_limiter(frames_per_second: u64, burst_size: u64) -> Arc<dyn Plugin> {
    Arc::new(
        WsRateLimiting::new(
            &json!({ "frames_per_second": frames_per_second, "burst_size": burst_size }),
            PluginHttpClient::default(),
        )
        .expect("valid ws_rate_limiting config"),
    )
}

/// Observational plugins must never be asked to charge a fragment batch.
struct ObserverOnly {
    fragment_calls: AtomicU64,
}

#[async_trait]
impl Plugin for ObserverOnly {
    fn name(&self) -> &str {
        "test_fragment_observer"
    }

    fn priority(&self) -> u16 {
        2900
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        WS_ONLY_PROTOCOLS
    }

    fn requires_ws_frame_hooks(&self) -> bool {
        true
    }

    fn observes_ws_frame_decisions(&self) -> bool {
        true
    }

    async fn on_ws_reassembly_frames(
        &self,
        _proxy_id: &str,
        _connection_id: u64,
        _direction: WebSocketFrameDirection,
        _fragment_frames: u64,
    ) -> Option<Message> {
        self.fragment_calls.fetch_add(1, Ordering::SeqCst);
        None
    }
}

/// Records the batch sizes it was charged so the relay's no-double-charge
/// contract is observable.
struct RecordingCharger {
    batches: std::sync::Mutex<Vec<u64>>,
    messages: AtomicU64,
}

#[async_trait]
impl Plugin for RecordingCharger {
    fn name(&self) -> &str {
        "test_fragment_recorder"
    }

    fn priority(&self) -> u16 {
        2901
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
        _message: &Message,
    ) -> Option<Message> {
        self.messages.fetch_add(1, Ordering::SeqCst);
        None
    }

    async fn on_ws_reassembly_frames(
        &self,
        _proxy_id: &str,
        _connection_id: u64,
        _direction: WebSocketFrameDirection,
        fragment_frames: u64,
    ) -> Option<Message> {
        self.batches
            .lock()
            .expect("test mutex not poisoned")
            .push(fragment_frames);
        None
    }
}

/// Build a fragmented message: one initial non-final frame plus
/// `continuations` zero-length continuations, the last of which is final.
fn zero_length_fragment_chain(continuations: usize) -> Vec<u8> {
    let mut bytes = vec![0x01, 0x00];
    for _ in 0..continuations.saturating_sub(1) {
        bytes.extend_from_slice(&[0x00, 0x00]);
    }
    bytes.extend_from_slice(&[0x80, 0x00]);
    bytes
}

/// The core bypass: a chain of empty continuation frames accumulates zero bytes,
/// so no size ceiling fires, yet the meter still counts every wire frame the
/// relay would otherwise never charge.
#[test]
fn zero_length_fragment_flood_is_metered() {
    let meter = Arc::new(FragmentMeter::new());
    let bytes = zero_length_fragment_chain(200);
    let mut socket = tokio_tungstenite::tungstenite::protocol::WebSocket::from_raw_socket(
        std::io::Cursor::new(bytes),
        Role::Client,
        None,
    );
    socket.set_fragment_accounting(Some(Arc::clone(&meter)), None, None);

    assert_eq!(
        socket.read().expect("message reassembles"),
        Message::Text("".into())
    );
    // 1 initial + 199 non-final continuations; the final continuation is the
    // returned message and is charged once by the ordinary frame chain.
    assert_eq!(meter.take_reassembly_frames(), 200);
    assert_eq!(meter.take_reassembly_frames(), 0);
}

/// The completing message is charged exactly once, on top of its fragments —
/// never twice.
#[tokio::test]
async fn fragments_and_completing_message_are_charged_once_each() {
    let recorder = Arc::new(RecordingCharger {
        batches: std::sync::Mutex::new(Vec::new()),
        messages: AtomicU64::new(0),
    });
    let plugins: Vec<Arc<dyn Plugin>> = vec![recorder.clone()];

    let rejected = ferrum_edge::_test_support::apply_ws_fragment_plugins_for_test(
        &plugins,
        PROXY_ID,
        1,
        WebSocketFrameDirection::ClientToBackend,
        7,
    )
    .await;
    assert!(rejected.is_none(), "recorder never rejects");

    let forwarded = ferrum_edge::_test_support::apply_ws_frame_plugins_for_test(
        &plugins,
        PROXY_ID,
        1,
        WebSocketFrameDirection::ClientToBackend,
        Message::Text("done".into()),
    )
    .await;
    assert!(matches!(forwarded, Message::Text(_)));

    assert_eq!(
        recorder
            .batches
            .lock()
            .expect("test mutex not poisoned")
            .as_slice(),
        &[7]
    );
    assert_eq!(recorder.messages.load(Ordering::SeqCst), 1);
}

/// A zero-size batch is a no-op: the relay must not synthesize a free
/// admission or an empty charge.
#[tokio::test]
async fn empty_fragment_batch_is_not_charged() {
    let recorder = Arc::new(RecordingCharger {
        batches: std::sync::Mutex::new(Vec::new()),
        messages: AtomicU64::new(0),
    });
    let plugins: Vec<Arc<dyn Plugin>> = vec![recorder.clone()];

    let outcome = ferrum_edge::_test_support::apply_ws_fragment_plugins_for_test(
        &plugins,
        PROXY_ID,
        1,
        WebSocketFrameDirection::ClientToBackend,
        0,
    )
    .await;
    assert!(outcome.is_none());
    assert!(
        recorder
            .batches
            .lock()
            .expect("test mutex not poisoned")
            .is_empty()
    );
}

/// Observation-only plugins are skipped: they may not charge or veto.
#[tokio::test]
async fn observational_plugins_are_skipped_for_fragment_batches() {
    let observer = Arc::new(ObserverOnly {
        fragment_calls: AtomicU64::new(0),
    });
    let plugins: Vec<Arc<dyn Plugin>> = vec![observer.clone()];

    let outcome = ferrum_edge::_test_support::apply_ws_fragment_plugins_for_test(
        &plugins,
        PROXY_ID,
        1,
        WebSocketFrameDirection::BackendToClient,
        12,
    )
    .await;
    assert!(outcome.is_none());
    assert_eq!(observer.fragment_calls.load(Ordering::SeqCst), 0);
}

/// A fragment batch larger than the whole burst budget can never be admitted,
/// in either direction — that is the fail-closed answer for a hostile flood.
#[tokio::test]
async fn oversized_fragment_batch_closes_in_both_directions() {
    for direction in [
        WebSocketFrameDirection::ClientToBackend,
        WebSocketFrameDirection::BackendToClient,
    ] {
        let plugins: Vec<Arc<dyn Plugin>> = vec![rate_limiter(10, 10)];
        let outcome = ferrum_edge::_test_support::apply_ws_fragment_plugins_for_test(
            &plugins, PROXY_ID, 7, direction, 500,
        )
        .await;
        let close = outcome
            .expect("oversized batch must be refused")
            .expect("policy Close carries a frame");
        assert_eq!(close.code, CloseCode::Policy);
        assert_eq!(close.reason.as_str(), "Frame rate exceeded");
    }
}

/// A batch inside the budget is admitted, and the budget it consumed is real:
/// the next batch that no longer fits is refused.
#[tokio::test]
async fn fragment_batches_draw_down_the_shared_frame_budget() {
    let plugins: Vec<Arc<dyn Plugin>> = vec![rate_limiter(20, 20)];

    let first = ferrum_edge::_test_support::apply_ws_fragment_plugins_for_test(
        &plugins,
        PROXY_ID,
        11,
        WebSocketFrameDirection::ClientToBackend,
        15,
    )
    .await;
    assert!(first.is_none(), "15 frames fit inside a burst of 20");

    let second = ferrum_edge::_test_support::apply_ws_fragment_plugins_for_test(
        &plugins,
        PROXY_ID,
        11,
        WebSocketFrameDirection::ClientToBackend,
        15,
    )
    .await;
    assert!(
        second.is_some(),
        "the first batch must actually consume budget"
    );
}

/// The parser bound fires while the message is still incomplete, so a flood
/// that never finishes is still terminal.
#[test]
fn incomplete_message_frame_bound_fails_closed() {
    let mut bytes = vec![0x01, 0x00];
    for _ in 0..64 {
        bytes.extend_from_slice(&[0x00, 0x00]);
    }
    let mut socket = tokio_tungstenite::tungstenite::protocol::WebSocket::from_raw_socket(
        std::io::Cursor::new(bytes),
        Role::Client,
        None,
    );
    socket.set_fragment_accounting(None, Some(8), None);

    let error = socket.read().expect_err("frame bound must fail the read");
    assert!(matches!(
        error,
        WsError::Protocol(ProtocolError::IncompleteMessageFrameLimitExceeded)
    ));

    let (close, limit_kind) =
        ferrum_edge::_test_support::ws_fragment_policy_close_for_error_for_test(&error)
            .expect("bound maps to a policy Close");
    assert_eq!(close.code, CloseCode::Policy);
    assert_eq!(limit_kind, "fragment_frames");
    // Bounded, non-secret reason well inside the 123-byte control-frame budget.
    assert!(close.reason.as_str().len() <= 123);
}

/// Zero duration arms the timer on the initial non-final frame without failing.
#[test]
fn incomplete_message_duration_zero_arms_on_initial_frame() {
    let bytes = vec![0x01, 0x00];
    let mut socket = tokio_tungstenite::tungstenite::protocol::WebSocket::from_raw_socket(
        std::io::Cursor::new(bytes),
        Role::Client,
        None,
    );
    socket.set_fragment_accounting(None, None, Some(Duration::ZERO));

    let error = socket
        .read()
        .expect_err("peer must reset without completing");
    assert!(matches!(
        error,
        WsError::Protocol(ProtocolError::ResetWithoutClosingHandshake)
    ));
}

/// The duration bound is independent of the frame-count bound.
#[test]
fn incomplete_message_duration_bound_fails_closed() {
    let mut bytes = vec![0x01, 0x00];
    for _ in 0..64 {
        bytes.extend_from_slice(&[0x00, 0x00]);
    }
    let mut socket = tokio_tungstenite::tungstenite::protocol::WebSocket::from_raw_socket(
        std::io::Cursor::new(bytes),
        Role::Client,
        None,
    );
    socket.set_fragment_accounting(None, None, Some(Duration::ZERO));

    let error = socket
        .read()
        .expect_err("duration bound must fail the read");
    assert!(matches!(
        error,
        WsError::Protocol(ProtocolError::IncompleteMessageTimeout)
    ));
    let (_, limit_kind) =
        ferrum_edge::_test_support::ws_fragment_policy_close_for_error_for_test(&error)
            .expect("bound maps to a policy Close");
    assert_eq!(limit_kind, "fragment_duration");
}

/// A peer cannot bypass the duration bound by completing with only the final
/// continuation after stalling.
#[test]
fn incomplete_message_duration_rejects_final_continuation_bypass() {
    let bytes = vec![0x01, 0x00, 0x80, 0x00];
    let mut socket = tokio_tungstenite::tungstenite::protocol::WebSocket::from_raw_socket(
        std::io::Cursor::new(bytes),
        Role::Client,
        None,
    );
    socket.set_fragment_accounting(None, None, Some(Duration::ZERO));

    let error = socket
        .read()
        .expect_err("final continuation must not bypass duration bound");
    assert!(matches!(
        error,
        WsError::Protocol(ProtocolError::IncompleteMessageTimeout)
    ));
}

/// Interleaved Ping/Pong keepalives cannot extend an incomplete message past
/// the duration bound.
#[test]
fn incomplete_message_duration_rejects_interleaved_ping_pong() {
    for bytes in [vec![0x01, 0x00, 0x89, 0x00], vec![0x01, 0x00, 0x8a, 0x00]] {
        let mut socket = tokio_tungstenite::tungstenite::protocol::WebSocket::from_raw_socket(
            std::io::Cursor::new(bytes),
            Role::Client,
            None,
        );
        socket.set_fragment_accounting(None, None, Some(Duration::ZERO));

        let error = socket
            .read()
            .expect_err("interleaved control frame must not bypass duration bound");
        assert!(matches!(
            error,
            WsError::Protocol(ProtocolError::IncompleteMessageTimeout)
        ));
    }
}

/// Peer Close remains exempt from the incomplete-message duration bound.
#[test]
fn incomplete_message_close_bypasses_duration_bound() {
    let bytes = vec![0x01, 0x00, 0x88, 0x02, 0x03, 0xe8];
    let mut socket = tokio_tungstenite::tungstenite::protocol::WebSocket::from_raw_socket(
        std::io::Cursor::new(bytes),
        Role::Client,
        None,
    );
    socket.set_fragment_accounting(None, None, Some(Duration::ZERO));

    assert!(matches!(
        socket.read().expect("peer Close must surface"),
        Message::Close(_)
    ));
}

/// Ordinary capacity errors keep their own close selection; the fragment
/// mapper must not claim them.
#[test]
fn fragment_close_mapper_ignores_unrelated_errors() {
    let unrelated = WsError::Protocol(ProtocolError::UnexpectedContinueFrame);
    assert!(
        ferrum_edge::_test_support::ws_fragment_policy_close_for_error_for_test(&unrelated)
            .is_none()
    );
}

/// Control frames and unfragmented messages leave no reassembly charge behind,
/// and interleaved Ping/Pong stay transparent.
#[test]
fn interleaved_control_frames_carry_no_fragment_charge() {
    // Text non-final, Ping, Pong, final continuation.
    let bytes = vec![
        0x01, 0x02, b'h', b'i', 0x89, 0x01, 0x01, 0x8a, 0x01, 0x02, 0x80, 0x01, b'!',
    ];
    let meter = Arc::new(FragmentMeter::new());
    let mut socket = tokio_tungstenite::tungstenite::protocol::WebSocket::from_raw_socket(
        std::io::Cursor::new(bytes),
        Role::Client,
        Some(WebSocketConfig::default().auto_pong(false)),
    );
    socket.set_fragment_accounting(Some(Arc::clone(&meter)), None, None);

    assert_eq!(
        socket.read().expect("ping surfaces"),
        Message::Ping(vec![1].into())
    );
    // The initial non-final data frame was already metered before the Ping.
    assert_eq!(meter.take_reassembly_frames(), 1);
    assert_eq!(
        socket.read().expect("pong surfaces"),
        Message::Pong(vec![2].into())
    );
    assert_eq!(meter.take_reassembly_frames(), 0);
    assert_eq!(
        socket.read().expect("message completes"),
        Message::Text("hi!".into())
    );
    assert_eq!(meter.take_reassembly_frames(), 0);
}

/// The async delegator (`tokio-tungstenite` patch 004): accounting installed
/// on a `WebSocketStream` before `split()` keeps metering through the
/// `SplitStream` that hides the codec — the shape the relay uses.
#[tokio::test]
async fn async_delegator_meters_fragments_through_split_stream() {
    let (client, mut peer) = tokio::io::duplex(4096);
    let mut ws = WebSocketStream::from_raw_socket(client, Role::Client, None).await;
    let meter = Arc::new(FragmentMeter::new());
    ws.set_fragment_accounting(Some(Arc::clone(&meter)), None, None);
    let (_sink, mut stream) = ws.split();

    peer.write_all(&zero_length_fragment_chain(50))
        .await
        .expect("write fragment chain");

    let message = stream
        .next()
        .await
        .expect("stream yields a message")
        .expect("message reassembles");
    assert_eq!(message, Message::Text("".into()));
    assert_eq!(meter.take_reassembly_frames(), 50);
    assert_eq!(meter.take_reassembly_frames(), 0);
}

/// The delegator forwards the incomplete-message frame bound too, so an async
/// read fails closed while the message is still incomplete.
#[tokio::test]
async fn async_delegator_forwards_incomplete_message_frame_bound() {
    let (client, mut peer) = tokio::io::duplex(4096);
    let mut ws = WebSocketStream::from_raw_socket(client, Role::Client, None).await;
    ws.set_fragment_accounting(None, Some(8), None);

    let mut bytes = vec![0x01, 0x00];
    for _ in 0..64 {
        bytes.extend_from_slice(&[0x00, 0x00]);
    }
    peer.write_all(&bytes).await.expect("write fragment flood");

    let error = ws
        .next()
        .await
        .expect("stream yields a result")
        .expect_err("frame bound must fail the read");
    assert!(matches!(
        error,
        WsError::Protocol(ProtocolError::IncompleteMessageFrameLimitExceeded)
    ));
}

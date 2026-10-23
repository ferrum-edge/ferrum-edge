//! Shared relay delivery-observation composition for `ws_frame_logging`.
//!
//! Issues #2554 / #2556: frame events must describe the final post-plugin,
//! post-control-guard representation only after successful delivery. Peer Close
//! is observed on the delivery path (mutating hooks never see it). Plugin
//! policy Close is recorded once as `outcome=policy_close` inside the
//! applicator and is not double-counted as a delivered frame.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use ferrum_edge::plugins::ws_frame_logging::WsFrameLogging;
use ferrum_edge::plugins::{Plugin, ProxyProtocol, WS_ONLY_PROTOCOLS, WebSocketFrameDirection};
use serde_json::json;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::tungstenite::protocol::frame::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;

#[derive(Clone, Debug, Default)]
struct CapturedFrame {
    outcome: Option<String>,
    frame_type: Option<String>,
    close_code: Option<u64>,
    close_reason_len: Option<u64>,
    size_bytes: Option<u64>,
}

#[derive(Clone, Default)]
struct Capture {
    events: Arc<std::sync::Mutex<Vec<CapturedFrame>>>,
}

impl Capture {
    fn layer(&self) -> CaptureLayer {
        CaptureLayer {
            events: Arc::clone(&self.events),
        }
    }

    fn events(&self) -> Vec<CapturedFrame> {
        self.events.lock().unwrap().clone()
    }
}

struct CaptureLayer {
    events: Arc<std::sync::Mutex<Vec<CapturedFrame>>>,
}

impl<S> tracing_subscriber::Layer<S> for CaptureLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != "ws_frame_log" {
            return;
        }
        let mut visitor = Visitor::default();
        event.record(&mut visitor);
        self.events.lock().unwrap().push(CapturedFrame {
            outcome: visitor.outcome,
            frame_type: visitor.frame_type,
            close_code: visitor.close_code,
            close_reason_len: visitor.close_reason_len,
            size_bytes: visitor.size_bytes,
        });
    }
}

#[derive(Default)]
struct Visitor {
    outcome: Option<String>,
    frame_type: Option<String>,
    close_code: Option<u64>,
    close_reason_len: Option<u64>,
    size_bytes: Option<u64>,
}

impl tracing::field::Visit for Visitor {
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        match field.name() {
            "close_code" => self.close_code = Some(value),
            "close_reason_len" => self.close_reason_len = Some(value),
            "size_bytes" => self.size_bytes = Some(value),
            _ => {}
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        if value >= 0 {
            self.record_u64(field, value as u64);
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        match field.name() {
            "outcome" => self.outcome = Some(value.to_string()),
            "frame_type" => self.frame_type = Some(value.to_string()),
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let rendered = format!("{value:?}").trim_matches('"').to_string();
        match field.name() {
            "outcome" => self.outcome = Some(rendered),
            "frame_type" => self.frame_type = Some(rendered),
            "close_code" | "close_reason_len" | "size_bytes" => {
                if let Ok(parsed) = rendered.parse::<u64>() {
                    self.record_u64(field, parsed);
                }
            }
            _ => {}
        }
    }
}

/// Mutating hook that flips Ping → Pong (the control guard must restore Ping).
struct PingToPongFlip {
    invocations: AtomicU64,
}

#[async_trait]
impl Plugin for PingToPongFlip {
    fn name(&self) -> &str {
        "test_ping_to_pong"
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

    async fn on_ws_frame(
        &self,
        _proxy_id: &str,
        _connection_id: u64,
        _direction: WebSocketFrameDirection,
        message: &Message,
    ) -> Option<Message> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        match message {
            Message::Ping(payload) => Some(Message::Pong(payload.clone())),
            _ => None,
        }
    }
}

struct SizeReject {
    invocations: AtomicU64,
}

#[async_trait]
impl Plugin for SizeReject {
    fn name(&self) -> &str {
        "test_size_reject_delivery"
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

#[tokio::test(flavor = "current_thread")]
async fn delivery_log_sees_restored_ping_after_control_guard() {
    let capture = Capture::default();
    crate::diagnostic_test_interest::ensure_interest_floor();
    let _guard =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(capture.layer()));

    let flip = Arc::new(PingToPongFlip {
        invocations: AtomicU64::new(0),
    });
    let logger = Arc::new(WsFrameLogging::new(&json!({"log_ping_pong": true})).unwrap());
    let plugins: Vec<Arc<dyn Plugin>> = vec![flip.clone(), logger];

    let outgoing = ferrum_edge::_test_support::apply_ws_frame_plugins_and_emit_delivery_for_test(
        &plugins,
        "ws-proxy",
        1,
        WebSocketFrameDirection::ClientToBackend,
        Message::Ping(vec![1, 2, 3].into()),
    )
    .await;

    assert!(matches!(outgoing, Message::Ping(_)));
    assert_eq!(flip.invocations.load(Ordering::SeqCst), 1);

    let events = capture.events();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].outcome.as_deref(), Some("delivered"));
    assert_eq!(
        events[0].frame_type.as_deref(),
        Some("ping"),
        "logger must see the post-guard Ping, not the flipped Pong"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn policy_close_emits_once_without_delivered_duplicate() {
    let capture = Capture::default();
    crate::diagnostic_test_interest::ensure_interest_floor();
    let _guard =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(capture.layer()));

    let size = Arc::new(SizeReject {
        invocations: AtomicU64::new(0),
    });
    let logger = Arc::new(WsFrameLogging::new(&json!({})).unwrap());
    let plugins: Vec<Arc<dyn Plugin>> = vec![size, logger];

    let outgoing = ferrum_edge::_test_support::apply_ws_frame_plugins_and_emit_delivery_for_test(
        &plugins,
        "ws-proxy",
        2,
        WebSocketFrameDirection::BackendToClient,
        Message::Text("oversized!".into()),
    )
    .await;

    match outgoing {
        Message::Close(Some(cf)) => {
            assert_eq!(cf.code, CloseCode::Size);
            assert_eq!(cf.reason.as_str(), "too large");
        }
        other => panic!("expected policy Close, got {other:?}"),
    }

    let events = capture.events();
    assert_eq!(
        events.len(),
        1,
        "policy Close must not be double-counted: {events:?}"
    );
    assert_eq!(events[0].outcome.as_deref(), Some("policy_close"));
    assert_eq!(events[0].frame_type.as_deref(), Some("close"));
    assert_eq!(events[0].close_code, Some(1009));
    assert_eq!(events[0].close_reason_len, Some("too large".len() as u64));
    assert_eq!(events[0].size_bytes, Some(2 + "too large".len() as u64));
}

#[tokio::test(flavor = "current_thread")]
async fn peer_close_delivery_helper_logs_both_directions() {
    let capture = Capture::default();
    crate::diagnostic_test_interest::ensure_interest_floor();
    let _guard =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(capture.layer()));

    let logger = Arc::new(WsFrameLogging::new(&json!({})).unwrap());
    let plugins: Vec<Arc<dyn Plugin>> = vec![logger];

    for (connection_id, direction, code, reason) in [
        (
            10u64,
            WebSocketFrameDirection::ClientToBackend,
            CloseCode::Normal,
            "bye",
        ),
        (
            11u64,
            WebSocketFrameDirection::BackendToClient,
            CloseCode::Away,
            "going away",
        ),
    ] {
        let msg = Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        }));
        // Peer Close never enters apply_ws_frame_plugins; the relay prepares
        // and emits after a successful forward only.
        let prepared =
            ferrum_edge::_test_support::prepare_ws_frame_deliveries_for_test(&plugins, &msg);
        ferrum_edge::_test_support::emit_ws_frame_deliveries_for_test(
            &plugins,
            "ws-proxy",
            connection_id,
            direction,
            prepared,
        );
    }

    let events = capture.events();
    assert_eq!(events.len(), 2, "{events:?}");
    assert!(
        events
            .iter()
            .all(|e| e.outcome.as_deref() == Some("delivered"))
    );
    assert!(
        events
            .iter()
            .all(|e| e.frame_type.as_deref() == Some("close"))
    );
    assert_eq!(events[0].close_code, Some(1000));
    assert_eq!(events[1].close_code, Some(1001));
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_delivery_drops_prepared_observation() {
    let capture = Capture::default();
    crate::diagnostic_test_interest::ensure_interest_floor();
    let _guard =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(capture.layer()));

    let logger = Arc::new(WsFrameLogging::new(&json!({})).unwrap());
    let plugins: Vec<Arc<dyn Plugin>> = vec![logger];
    let outgoing = ferrum_edge::_test_support::apply_ws_frame_plugins_for_test(
        &plugins,
        "ws-proxy",
        5,
        WebSocketFrameDirection::ClientToBackend,
        Message::Text("will-cancel".into()),
    )
    .await;
    let prepared =
        ferrum_edge::_test_support::prepare_ws_frame_deliveries_for_test(&plugins, &outgoing);
    assert!(!prepared.is_empty());
    // Simulate cancel / write failure: discard without emit.
    drop(prepared);
    assert!(
        capture.events().is_empty(),
        "failed/cancelled sends must not emit delivered frame events"
    );
}

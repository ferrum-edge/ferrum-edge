//! Composition tests for the shared WebSocket `on_ws_frame` applicator.
//!
//! The first terminal Close from a priority-ordered admission/mutating plugin
//! must win: later rate limiters neither charge budget nor replace the Close,
//! while observational hooks still see the final decision. Both relay
//! directions use the same helper (H1 Upgrade, H2 Extended CONNECT, and H3
//! Extended CONNECT share that relay).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use ferrum_edge::plugins::PluginHttpClient;
use ferrum_edge::plugins::ws_frame_logging::WsFrameLogging;
use ferrum_edge::plugins::ws_rate_limiting::WsRateLimiting;
use ferrum_edge::plugins::{Plugin, ProxyProtocol, WS_ONLY_PROTOCOLS, WebSocketFrameDirection};
use serde_json::json;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::tungstenite::protocol::frame::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

struct SizeRejectPlugin {
    invocations: AtomicU64,
}

#[async_trait]
impl Plugin for SizeRejectPlugin {
    fn name(&self) -> &str {
        "test_size_reject"
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
            Message::Text(text) if text.len() > 16 => Some(Message::Close(Some(CloseFrame {
                code: CloseCode::Size,
                reason: "message too large".into(),
            }))),
            _ => None,
        }
    }
}

struct CountingObserver {
    seen_close: AtomicU64,
    replacements: AtomicU64,
    policy_closes: std::sync::Mutex<Vec<(WebSocketFrameDirection, Option<u16>)>>,
}

#[async_trait]
impl Plugin for CountingObserver {
    fn name(&self) -> &str {
        "test_close_observer"
    }

    fn priority(&self) -> u16 {
        9050
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

    async fn on_ws_frame(
        &self,
        _proxy_id: &str,
        _connection_id: u64,
        _direction: WebSocketFrameDirection,
        message: &Message,
    ) -> Option<Message> {
        if matches!(message, Message::Close(_)) {
            self.seen_close.fetch_add(1, Ordering::SeqCst);
        }
        // A buggy observational hook must never be allowed to replace either
        // an ordinary frame or an already-final Close.
        self.replacements.fetch_add(1, Ordering::SeqCst);
        Some(Message::Close(Some(CloseFrame {
            code: CloseCode::Policy,
            reason: "observer overwrite".into(),
        })))
    }

    fn on_ws_policy_close(
        &self,
        _proxy_id: &str,
        _connection_id: u64,
        direction: WebSocketFrameDirection,
        close: Option<&CloseFrame>,
    ) {
        self.policy_closes
            .lock()
            .unwrap()
            .push((direction, close.map(|cf| u16::from(cf.code))));
    }
}

struct MutatingLateReject {
    invocations: AtomicU64,
}

#[async_trait]
impl Plugin for MutatingLateReject {
    fn name(&self) -> &str {
        "test_late_reject"
    }

    fn priority(&self) -> u16 {
        2920
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
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Some(Message::Close(Some(CloseFrame {
            code: CloseCode::Policy,
            reason: "late policy close".into(),
        })))
    }
}

fn assert_size_close(message: Message) {
    match message {
        Message::Close(Some(cf)) => {
            assert_eq!(cf.code, CloseCode::Size);
            assert_eq!(cf.reason.as_str(), "message too large");
        }
        other => panic!("expected preserved 1009 Close, got {other:?}"),
    }
}

#[tokio::test]
async fn earlier_size_close_is_preserved_over_rate_limiter_both_directions() {
    let oversized = Message::Text("this payload is definitely too large".into());
    let small = Message::Text("ok".into());

    for (connection_id, direction) in [
        (1u64, WebSocketFrameDirection::ClientToBackend),
        (2u64, WebSocketFrameDirection::BackendToClient),
    ] {
        let size = Arc::new(SizeRejectPlugin {
            invocations: AtomicU64::new(0),
        });
        let rate = Arc::new(
            WsRateLimiting::new(
                &json!({
                    "frames_per_second": 1,
                    "burst_size": 1,
                    "close_reason": "frame rate exceeded"
                }),
                PluginHttpClient::default(),
            )
            .unwrap(),
        );
        let observer = Arc::new(CountingObserver {
            seen_close: AtomicU64::new(0),
            replacements: AtomicU64::new(0),
            policy_closes: std::sync::Mutex::new(Vec::new()),
        });
        let logger = Arc::new(WsFrameLogging::new(&json!({})).unwrap());
        let plugins: Vec<Arc<dyn Plugin>> =
            vec![size.clone(), rate.clone(), observer.clone(), logger];

        // Exhaust the sole rate token with a small frame first (mirrors the audit
        // reproduction), then violate size so a buggy rate limiter would otherwise
        // replace 1009 with 1008.
        let forwarded = ferrum_edge::_test_support::apply_ws_frame_plugins_for_test(
            &plugins,
            "ws-proxy",
            connection_id,
            direction,
            small.clone(),
        )
        .await;
        assert_eq!(forwarded, small);
        assert_eq!(rate.tracked_keys_count(), Some(1));
        let keys_before_reject = rate.tracked_keys_count();

        let outgoing = ferrum_edge::_test_support::apply_ws_frame_plugins_for_test(
            &plugins,
            "ws-proxy",
            connection_id,
            direction,
            oversized.clone(),
        )
        .await;
        assert_size_close(outgoing);
        assert_eq!(
            rate.tracked_keys_count(),
            keys_before_reject,
            "rate limiter must not charge after an earlier terminal Close ({direction:?})"
        );
        // The terminal Close ends the chain for every later plugin, observers
        // included; the decision reaches observers once, after the pass,
        // through `on_ws_policy_close`.
        assert_eq!(observer.seen_close.load(Ordering::SeqCst), 0);
        // The observer's replacement attempt on the admitted frame is ignored.
        assert_eq!(observer.replacements.load(Ordering::SeqCst), 1);
        assert_eq!(
            *observer.policy_closes.lock().unwrap(),
            vec![(direction, Some(1009))],
            "exactly one final-decision observation ({direction:?})"
        );
    }
}

#[tokio::test]
async fn later_mutating_plugin_is_skipped_after_terminal_close() {
    let size = Arc::new(SizeRejectPlugin {
        invocations: AtomicU64::new(0),
    });
    let late = Arc::new(MutatingLateReject {
        invocations: AtomicU64::new(0),
    });
    let plugins: Vec<Arc<dyn Plugin>> = vec![size.clone(), late.clone()];

    let outgoing = ferrum_edge::_test_support::apply_ws_frame_plugins_for_test(
        &plugins,
        "ws-proxy",
        3,
        WebSocketFrameDirection::ClientToBackend,
        Message::Text("this payload is definitely too large".into()),
    )
    .await;
    assert_size_close(outgoing);
    assert_eq!(size.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        late.invocations.load(Ordering::SeqCst),
        0,
        "later mutating plugins must not run after a terminal Close"
    );
}

#[tokio::test]
async fn multiple_rate_limiters_preserve_first_close_without_second_charge() {
    let first = Arc::new(
        WsRateLimiting::new(
            &json!({
                "frames_per_second": 1,
                "burst_size": 1,
                "close_reason": "first limiter"
            }),
            PluginHttpClient::default(),
        )
        .unwrap(),
    );
    let second = Arc::new(
        WsRateLimiting::new(
            &json!({
                "frames_per_second": 1,
                "burst_size": 1,
                "close_reason": "second limiter"
            }),
            PluginHttpClient::default(),
        )
        .unwrap(),
    );
    let plugins: Vec<Arc<dyn Plugin>> = vec![first.clone(), second.clone()];

    let msg = Message::Text("frame".into());
    assert!(
        ferrum_edge::_test_support::apply_ws_frame_plugins_for_test(
            &plugins,
            "ws-proxy",
            11,
            WebSocketFrameDirection::ClientToBackend,
            msg.clone(),
        )
        .await
            == msg
    );

    let denied = ferrum_edge::_test_support::apply_ws_frame_plugins_for_test(
        &plugins,
        "ws-proxy",
        11,
        WebSocketFrameDirection::ClientToBackend,
        msg,
    )
    .await;
    match denied {
        Message::Close(Some(cf)) => {
            assert_eq!(cf.code, CloseCode::Policy);
            assert_eq!(cf.reason.as_str(), "first limiter");
        }
        other => panic!("expected first limiter Close, got {other:?}"),
    }
    assert_eq!(first.tracked_keys_count(), Some(1));
    assert_eq!(
        second.tracked_keys_count(),
        Some(1),
        "second limiter charged the admitted first frame only"
    );

    // A third frame still produces the first limiter's Close; the second
    // instance must not be invoked again for that already-terminal frame.
    let again = ferrum_edge::_test_support::apply_ws_frame_plugins_for_test(
        &plugins,
        "ws-proxy",
        11,
        WebSocketFrameDirection::ClientToBackend,
        Message::Text("again".into()),
    )
    .await;
    match again {
        Message::Close(Some(cf)) => {
            assert_eq!(cf.reason.as_str(), "first limiter");
        }
        other => panic!("expected preserved first Close, got {other:?}"),
    }
}

#[tokio::test]
async fn empty_plugin_list_is_zero_cost_passthrough() {
    let msg = Message::Binary(vec![b'r', b'a', b'w'].into());
    let out = ferrum_edge::_test_support::apply_ws_frame_plugins_for_test(
        &[],
        "ws-proxy",
        1,
        WebSocketFrameDirection::BackendToClient,
        msg.clone(),
    )
    .await;
    assert_eq!(out, msg);
}

/// A composed terminal Close still publishes cancellation synchronously so the
/// opposite relay half can tear down before any bounded write begins.
#[tokio::test]
async fn composed_terminal_close_publishes_cancellation_for_teardown() {
    let size = Arc::new(SizeRejectPlugin {
        invocations: AtomicU64::new(0),
    });
    let rate = Arc::new(
        WsRateLimiting::new(
            &json!({
                "frames_per_second": 1,
                "burst_size": 1,
                "close_reason": "frame rate exceeded"
            }),
            PluginHttpClient::default(),
        )
        .unwrap(),
    );
    let plugins: Vec<Arc<dyn Plugin>> = vec![size, rate];

    let outgoing = ferrum_edge::_test_support::apply_ws_frame_plugins_for_test(
        &plugins,
        "ws-proxy",
        5,
        WebSocketFrameDirection::ClientToBackend,
        Message::Text("this payload is definitely too large".into()),
    )
    .await;
    let Message::Close(close_frame) = outgoing else {
        panic!("expected terminal Close from composition");
    };

    let policy_close = std::sync::OnceLock::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let selected = ferrum_edge::_test_support::publish_ws_policy_close_for_test(
        &policy_close,
        &cancel,
        close_frame.clone(),
    );
    assert!(cancel.is_cancelled());
    assert_eq!(selected, close_frame);

    let overwritten = ferrum_edge::_test_support::publish_ws_policy_close_for_test(
        &policy_close,
        &cancel,
        Some(CloseFrame {
            code: CloseCode::Policy,
            reason: "should not win".into(),
        }),
    );
    assert_eq!(overwritten, close_frame);
}

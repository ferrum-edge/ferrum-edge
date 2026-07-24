//! External regressions for WebSocket relay close/control-frame correctness.
//!
//! Covers:
//! - Global capacity overflows map to RFC 6455 1009 (not silent teardown)
//! - Idle-timeout policy Close is defined 1001 Away
//! - First published policy Close wins (shared with size/idle/plugin paths)
//! - Source invariants: Ping is not forwarded; idle publishes before break

use std::sync::Arc;

use ferrum_edge::plugins::ws_message_size_limiting::WsMessageSizeLimiting;
use ferrum_edge::plugins::Plugin;
use serde_json::json;
use tokio_tungstenite::tungstenite::error::CapacityError;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_util::sync::CancellationToken;

#[test]
fn test_global_frame_capacity_overflow_emits_1009_without_plugin() {
    let error = WsError::Capacity(CapacityError::FrameTooLong {
        size: 32,
        max_size: 16,
    });
    let (close, kind, size, max_size, plugin_enforced) =
        ferrum_edge::_test_support::ws_capacity_close_for_error_for_test(16, &[], &error)
            .expect("global frame overflow must produce a Close");
    assert_eq!(close.code, CloseCode::Size);
    assert!(
        close.reason.is_empty(),
        "global overflow uses an empty reason (no plugin text)"
    );
    assert_eq!(kind, "frame");
    assert_eq!(size, 32);
    assert_eq!(max_size, 16);
    assert!(!plugin_enforced);
}

#[test]
fn test_global_message_capacity_overflow_emits_1009_without_plugin() {
    let error = WsError::Capacity(CapacityError::MessageTooLong {
        size: 100,
        max_size: 64,
    });
    // Global message ceiling is 4× frame ceiling.
    let (close, kind, size, max_size, plugin_enforced) =
        ferrum_edge::_test_support::ws_capacity_close_for_error_for_test(16, &[], &error)
            .expect("global message overflow must produce a Close");
    assert_eq!(close.code, CloseCode::Size);
    assert!(close.reason.is_empty());
    assert_eq!(kind, "message");
    assert_eq!(size, 100);
    assert_eq!(max_size, 64);
    assert!(!plugin_enforced);
}

#[test]
fn test_plugin_capacity_overflow_preserves_configured_reason() {
    let plugin: Arc<dyn Plugin> = Arc::new(
        WsMessageSizeLimiting::new(&json!({
            "max_frame_bytes": 16,
            "close_reason": "plugin frame limit"
        }))
        .expect("valid size plugin"),
    );
    let error = WsError::Capacity(CapacityError::FrameTooLong {
        size: 32,
        max_size: 16,
    });
    let (close, kind, _size, _max_size, plugin_enforced) =
        ferrum_edge::_test_support::ws_capacity_close_for_error_for_test(1_048_576, &[plugin], &error)
            .expect("plugin frame overflow must produce a Close");
    assert_eq!(close.code, CloseCode::Size);
    assert_eq!(close.reason.as_str(), "plugin frame limit");
    assert_eq!(kind, "frame");
    assert!(plugin_enforced);
}

#[test]
fn test_capacity_close_ignores_mismatched_max_size() {
    let error = WsError::Capacity(CapacityError::FrameTooLong {
        size: 32,
        max_size: 99,
    });
    assert!(
        ferrum_edge::_test_support::ws_capacity_close_for_error_for_test(16, &[], &error).is_none(),
        "capacity errors whose max_size does not match the binding ceiling are not policy Closes"
    );
}

#[test]
fn test_idle_timeout_close_is_defined_away_1001() {
    let close = ferrum_edge::_test_support::ws_idle_timeout_close_frame_for_test();
    assert_eq!(close.code, CloseCode::Away);
    assert_eq!(u16::from(close.code), 1001);
    assert_eq!(close.reason.as_str(), "idle timeout");
}

#[test]
fn test_idle_timeout_close_publishes_first_and_cancels() {
    let policy_close = std::sync::OnceLock::new();
    let cancel = CancellationToken::new();
    let idle = ferrum_edge::_test_support::ws_idle_timeout_close_frame_for_test();
    let selected = ferrum_edge::_test_support::publish_ws_policy_close_for_test(
        &policy_close,
        &cancel,
        Some(idle.clone()),
    );
    assert!(cancel.is_cancelled());
    assert_eq!(selected, Some(idle.clone()));

    let later = tokio_tungstenite::tungstenite::protocol::CloseFrame {
        code: CloseCode::Size,
        reason: "should not win".into(),
    };
    let retained = ferrum_edge::_test_support::publish_ws_policy_close_for_test(
        &policy_close,
        &cancel,
        Some(later),
    );
    assert_eq!(
        retained,
        Some(idle),
        "first terminal Close (idle 1001) must win over a later size Close"
    );
}

#[test]
fn test_relay_skips_forwarding_ping_after_local_answer() {
    let source = include_str!("../../../src/proxy/mod.rs");
    for marker in [
        "Client -> Backend: Ping answered locally (not forwarded)",
        "Backend -> Client: Ping answered locally (not forwarded)",
    ] {
        assert!(
            source.contains(marker),
            "relay must keep Ping local after the framer auto-Pong ({marker})"
        );
    }
    // Ensure we did not regress to forwarding Ping on the hot path traces.
    assert!(
        !source.contains("Message::Ping(_) => trace!(\"Client -> Backend: Ping\")"),
        "client->backend must not forward Ping after the local auto-Pong"
    );
    assert!(
        !source.contains("Message::Ping(_) => trace!(\"Backend -> Client: Ping\")"),
        "backend->client must not forward Ping after the local auto-Pong"
    );
}

#[test]
fn test_idle_timeout_arms_publish_defined_close_before_break() {
    let source = include_str!("../../../src/proxy/mod.rs");
    for (half, end_marker) in [
        (
            "observed on client->backend half",
            "Client -> backend forwarding completed",
        ),
        (
            "observed on backend->client half",
            "Backend -> client forwarding completed",
        ),
    ] {
        let branch = source
            .split_once(half)
            .unwrap_or_else(|| panic!("missing idle half marker: {half}"))
            .1;
        let branch = branch
            .split_once(end_marker)
            .unwrap_or_else(|| panic!("missing relay branch end: {end_marker}"))
            .0;
        assert!(
            branch.contains("ws_idle_timeout_close_frame()"),
            "{half} must publish the idle 1001 Close before breaking"
        );
        assert!(
            branch.contains("publish_ws_policy_close"),
            "{half} must publish policy Close so the opposite cancel branch is symmetric"
        );
        assert!(
            branch.contains("send_bounded_ws_close"),
            "{half} must emit a bounded Close on its own sink before exit"
        );
    }
}

#[test]
fn test_capacity_err_arms_use_unified_close_helper() {
    let source = include_str!("../../../src/proxy/mod.rs");
    assert!(
        !source.contains("plugin_close_for_error"),
        "capacity Close selection must use close_for_capacity_error for plugin and global ceilings"
    );
    assert_eq!(
        source.matches("close_for_capacity_error").count(),
        3,
        "helper definition plus both relay Err arms"
    );
}

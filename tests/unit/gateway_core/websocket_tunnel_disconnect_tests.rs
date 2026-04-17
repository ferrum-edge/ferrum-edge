//! Unit tests for the WebSocket tunnel-mode disconnect-hook path.
//!
//! Codex P2: tunnel mode (enabled via `FERRUM_WEBSOCKET_TUNNEL_MODE=true` when
//! no frame-level plugins are configured) bypasses WebSocket frame parsing
//! and does raw `copy_bidirectional`. Before this fix, that path returned
//! immediately after the copy without firing `on_ws_disconnect` — any plugin
//! that opted into disconnect hooks would silently miss every tunnel-mode
//! session teardown, breaking the disconnect-observability contract used by
//! `ws_frame_logging` and `prometheus_metrics`.
//!
//! These tests exercise the helper the tunnel-mode path now calls:
//! `fire_ws_tunnel_disconnect_hooks`. They verify that:
//!
//! 1. The hook fires for every plugin in the slice.
//! 2. Frame counters are reported as 0 (tunnel mode doesn't parse frames).
//! 3. Failure info is preserved into `WsDisconnectContext.direction` and
//!    `.error_class`.
//! 4. Empty plugin slices skip the hook entirely (zero overhead when no
//!    plugin opts in).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use async_trait::async_trait;

use ferrum_edge::_test_support::{fire_ws_tunnel_disconnect_hooks, make_ws_session_meta};
use ferrum_edge::plugins::{Direction, Plugin, WsDisconnectContext};
use ferrum_edge::retry::ErrorClass;

/// Plugin that captures every `on_ws_disconnect` invocation.
struct CapturingDisconnectPlugin {
    captured: Arc<Mutex<Vec<CapturedDisconnect>>>,
}

#[derive(Clone)]
struct CapturedDisconnect {
    proxy_id: String,
    client_ip: String,
    frames_c2b: u64,
    frames_b2c: u64,
    direction: Option<Direction>,
    error_class: Option<ErrorClass>,
}

impl CapturingDisconnectPlugin {
    fn new() -> (Self, Arc<Mutex<Vec<CapturedDisconnect>>>) {
        let captured = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                captured: Arc::clone(&captured),
            },
            captured,
        )
    }
}

#[async_trait]
impl Plugin for CapturingDisconnectPlugin {
    fn name(&self) -> &str {
        "capturing_ws_disconnect"
    }

    fn priority(&self) -> u16 {
        9175
    }

    fn requires_ws_disconnect_hooks(&self) -> bool {
        true
    }

    async fn on_ws_disconnect(&self, ctx: &WsDisconnectContext) {
        self.captured.lock().unwrap().push(CapturedDisconnect {
            proxy_id: ctx.proxy_id.clone(),
            client_ip: ctx.client_ip.clone(),
            frames_c2b: ctx.frames_client_to_backend,
            frames_b2c: ctx.frames_backend_to_client,
            direction: ctx.direction,
            error_class: ctx.error_class,
        });
    }
}

fn session_meta() -> ferrum_edge::proxy::WsSessionMeta {
    make_ws_session_meta(
        "ferrum".to_string(),
        Some("ws-echo".to_string()),
        "10.0.0.7".to_string(),
        "backend:9000".to_string(),
        8000,
        Some("user-42".to_string()),
        HashMap::new(),
        chrono::Utc::now() - chrono::Duration::milliseconds(250),
    )
}

#[tokio::test]
async fn test_tunnel_disconnect_fires_for_every_plugin() {
    let (plugin_a, captured_a) = CapturingDisconnectPlugin::new();
    let (plugin_b, captured_b) = CapturingDisconnectPlugin::new();
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(plugin_a), Arc::new(plugin_b)];
    let meta = session_meta();

    fire_ws_tunnel_disconnect_hooks(&plugins, "proxy-abc", &meta, None).await;

    let a = captured_a.lock().unwrap();
    let b = captured_b.lock().unwrap();
    assert_eq!(a.len(), 1, "plugin A must receive exactly one disconnect");
    assert_eq!(b.len(), 1, "plugin B must receive exactly one disconnect");
    assert_eq!(a[0].proxy_id, "proxy-abc");
    assert_eq!(a[0].client_ip, "10.0.0.7");
}

#[tokio::test]
async fn test_tunnel_disconnect_reports_zero_frame_counts() {
    // Tunnel mode does raw TCP bidirectional copy — it never parses WebSocket
    // frames, so c2b / b2c frame counters are always 0. Operators who need
    // frame-level accounting must disable tunnel mode.
    let (plugin, captured) = CapturingDisconnectPlugin::new();
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(plugin)];
    let meta = session_meta();

    fire_ws_tunnel_disconnect_hooks(&plugins, "proxy-abc", &meta, None).await;

    let captured = captured.lock().unwrap();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].frames_c2b, 0);
    assert_eq!(captured[0].frames_b2c, 0);
}

#[tokio::test]
async fn test_tunnel_disconnect_graceful_close_has_no_failure() {
    // When the raw copy finishes cleanly (both halves EOF), the helper is
    // called with `failure: None`. The disconnect context surfaces both
    // direction and error_class as None — dashboards read that as "graceful".
    let (plugin, captured) = CapturingDisconnectPlugin::new();
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(plugin)];
    let meta = session_meta();

    fire_ws_tunnel_disconnect_hooks(&plugins, "proxy-abc", &meta, None).await;

    let captured = captured.lock().unwrap();
    assert!(captured[0].direction.is_none());
    assert!(captured[0].error_class.is_none());
}

#[tokio::test]
async fn test_tunnel_disconnect_propagates_direction_and_error_class() {
    // The drain-phase write-failure path attributes to `BackendToClient`
    // (client socket errored while we were pushing a buffered frame). The
    // copy_bidirectional error path attributes to `Direction::Unknown`
    // because the std::io::copy_bidirectional API doesn't report side.
    let (plugin, captured) = CapturingDisconnectPlugin::new();
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(plugin)];
    let meta = session_meta();

    fire_ws_tunnel_disconnect_hooks(
        &plugins,
        "proxy-abc",
        &meta,
        Some((Direction::BackendToClient, ErrorClass::ConnectionReset)),
    )
    .await;

    let captured = captured.lock().unwrap();
    assert_eq!(captured[0].direction, Some(Direction::BackendToClient));
    assert_eq!(captured[0].error_class, Some(ErrorClass::ConnectionReset),);
}

#[tokio::test]
async fn test_tunnel_disconnect_skips_when_no_plugins_opted_in() {
    // Empty slice → zero overhead: no allocation, no await, no hook fired.
    // This test mostly documents the contract — if it regresses to
    // `for plugin in &[] { plugin.on_ws_disconnect(...).await }` that's
    // semantically fine, but the branch must still be reached.
    let plugins: Vec<Arc<dyn Plugin>> = Vec::new();
    let meta = session_meta();

    // Should complete without panicking or awaiting on anything meaningful.
    fire_ws_tunnel_disconnect_hooks(
        &plugins,
        "proxy-abc",
        &meta,
        Some((Direction::Unknown, ErrorClass::RequestError)),
    )
    .await;
}

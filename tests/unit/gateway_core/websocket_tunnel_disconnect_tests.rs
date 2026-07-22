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
//! 3. Failure info is preserved into `WsDisconnectContext.direction`,
//!    `.io_side`, and `.error_class`.
//! 4. Empty plugin slices skip the hook entirely (zero overhead when no
//!    plugin opts in).
//!
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use async_trait::async_trait;

use std::time::Instant;

use ferrum_edge::_test_support::{
    StreamIoSide, fire_ws_framed_disconnect_hooks, fire_ws_tunnel_disconnect_hooks,
    make_ws_session_meta, make_ws_session_meta_with_mono,
};
use ferrum_edge::plugins::{Direction, Plugin, WsDisconnectContext};
use ferrum_edge::retry::ErrorClass;

/// Plugin that captures every `on_ws_disconnect` invocation.
struct CapturingDisconnectPlugin {
    captured: Arc<Mutex<Vec<CapturedDisconnect>>>,
}

#[derive(Clone)]
struct CapturedDisconnect {
    proxy_id: String,
    connection_id: u64,
    client_ip: String,
    frames_c2b: u64,
    frames_b2c: u64,
    bytes_c2b: u64,
    bytes_b2c: u64,
    duration_ms: f64,
    timestamp_connected: String,
    timestamp_disconnected: String,
    direction: Option<Direction>,
    io_side: Option<StreamIoSide>,
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
            connection_id: ctx.connection_id,
            client_ip: ctx.client_ip.clone(),
            frames_c2b: ctx.frames_client_to_backend,
            frames_b2c: ctx.frames_backend_to_client,
            bytes_c2b: ctx.bytes_client_to_backend,
            bytes_b2c: ctx.bytes_backend_to_client,
            duration_ms: ctx.duration_ms,
            timestamp_connected: ctx.timestamp_connected.clone(),
            timestamp_disconnected: ctx.timestamp_disconnected.clone(),
            direction: ctx.direction,
            io_side: ctx.io_side,
            error_class: ctx.error_class,
        });
    }
}

fn session_meta() -> ferrum_edge::proxy::WsSessionMeta {
    session_meta_with_id(0)
}

fn session_meta_with_id(connection_id: u64) -> ferrum_edge::proxy::WsSessionMeta {
    let mut meta = make_ws_session_meta(
        "ferrum".to_string(),
        Some("ws-echo".to_string()),
        "10.0.0.7".to_string(),
        "backend:9000".to_string(),
        8000,
        Some("user-42".to_string()),
        HashMap::new(),
        chrono::Utc::now() - chrono::Duration::seconds(2),
    );
    meta.connection_id = connection_id;
    meta
}

#[tokio::test]
async fn test_tunnel_disconnect_fires_for_every_plugin() {
    let (plugin_a, captured_a) = CapturingDisconnectPlugin::new();
    let (plugin_b, captured_b) = CapturingDisconnectPlugin::new();
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(plugin_a), Arc::new(plugin_b)];
    let meta = session_meta();

    fire_ws_tunnel_disconnect_hooks(&plugins, "proxy-abc", &meta, 12, 34, None).await;

    let a = captured_a.lock().unwrap();
    let b = captured_b.lock().unwrap();
    assert_eq!(a.len(), 1, "plugin A must receive exactly one disconnect");
    assert_eq!(b.len(), 1, "plugin B must receive exactly one disconnect");
    assert_eq!(a[0].proxy_id, "proxy-abc");
    assert_eq!(a[0].client_ip, "10.0.0.7");
    assert_eq!(a[0].bytes_c2b, 12);
    assert_eq!(a[0].bytes_b2c, 34);
    assert_eq!(a[0].timestamp_connected, meta.session_start.to_rfc3339());
    assert!(
        !a[0].timestamp_disconnected.is_empty(),
        "tunnel disconnect must carry a teardown wall-clock timestamp"
    );
    assert_ne!(a[0].timestamp_connected, a[0].timestamp_disconnected);
}

#[tokio::test]
async fn test_tunnel_disconnect_reports_zero_frame_counts() {
    // Tunnel mode does raw TCP bidirectional copy — it never parses WebSocket
    // frames, so c2b / b2c frame counters are always 0. Operators who need
    // frame-level accounting must disable tunnel mode.
    let (plugin, captured) = CapturingDisconnectPlugin::new();
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(plugin)];
    let meta = session_meta();

    fire_ws_tunnel_disconnect_hooks(&plugins, "proxy-abc", &meta, 0, 0, None).await;

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

    fire_ws_tunnel_disconnect_hooks(&plugins, "proxy-abc", &meta, 0, 0, None).await;

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
        0,
        0,
        Some((
            Direction::BackendToClient,
            ErrorClass::ConnectionReset,
            Some(StreamIoSide::Write),
        )),
    )
    .await;

    let captured = captured.lock().unwrap();
    assert_eq!(captured[0].direction, Some(Direction::BackendToClient));
    assert_eq!(captured[0].io_side, Some(StreamIoSide::Write));
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
        0,
        0,
        Some((Direction::Unknown, ErrorClass::RequestError, None)),
    )
    .await;
}

#[tokio::test]
async fn test_tunnel_disconnect_duration_ignores_wall_clock_skew() {
    // Wall connect is an hour in the past; monotonic start is "now". Duration
    // must follow Instant, not civil-clock subtraction (~3.6e6 ms).
    let (plugin, captured) = CapturingDisconnectPlugin::new();
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(plugin)];
    let meta = make_ws_session_meta_with_mono(
        "ferrum".to_string(),
        Some("ws-echo".to_string()),
        "10.0.0.7".to_string(),
        "backend:9000".to_string(),
        8000,
        None,
        HashMap::new(),
        chrono::Utc::now() - chrono::Duration::hours(1),
        Instant::now(),
    );

    fire_ws_tunnel_disconnect_hooks(&plugins, "proxy-abc", &meta, 0, 0, None).await;

    let captured = captured.lock().unwrap();
    assert_eq!(captured.len(), 1);
    assert!(
        captured[0].duration_ms < 5_000.0,
        "duration_ms must use Instant, not wall delta; got {}",
        captured[0].duration_ms
    );
    assert_eq!(
        captured[0].timestamp_connected,
        meta.session_start.to_rfc3339(),
        "wall connect timestamp is preserved for rendering"
    );
}

#[tokio::test]
async fn test_framed_disconnect_duration_ignores_wall_clock_skew() {
    // Framed path (H1/H2/H3 parsed relay) must match tunnel: Instant duration
    // with wall stamps used only for rendering. Backward and forward civil
    // skew must not clamp/inflate duration_ms; frame counters stay non-zero.
    let (plugin, captured) = CapturingDisconnectPlugin::new();
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(plugin)];
    let wall_connect = chrono::Utc::now() - chrono::Duration::hours(1);
    let meta = make_ws_session_meta_with_mono(
        "ferrum".to_string(),
        Some("ws-framed".to_string()),
        "10.0.0.8".to_string(),
        "backend:9001".to_string(),
        8443,
        None,
        HashMap::new(),
        wall_connect,
        Instant::now(),
    );
    let expected_connected = meta.session_start.to_rfc3339();

    fire_ws_framed_disconnect_hooks(&plugins, "proxy-framed", meta, 3, 5, 30, 50, None).await;

    // Drop the MutexGuard before the forward-skew await below (clippy::await_holding_lock).
    {
        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].frames_c2b, 3);
        assert_eq!(captured[0].frames_b2c, 5);
        assert_eq!(captured[0].bytes_c2b, 30);
        assert_eq!(captured[0].bytes_b2c, 50);
        assert!(
            captured[0].duration_ms < 5_000.0,
            "framed duration_ms must use Instant under wall rollback; got {}",
            captured[0].duration_ms
        );
        assert_eq!(
            captured[0].timestamp_connected, expected_connected,
            "wall connect timestamp is preserved for rendering"
        );
    }

    // Forward civil-clock skew: wall connect an hour in the future would make
    // a wall-delta path report zero/negative; Instant still reports near-zero
    // elapsed from session_start_mono = now.
    let (plugin_fwd, captured_fwd) = CapturingDisconnectPlugin::new();
    let plugins_fwd: Vec<Arc<dyn Plugin>> = vec![Arc::new(plugin_fwd)];
    let wall_forward = chrono::Utc::now() + chrono::Duration::hours(1);
    let meta_fwd = make_ws_session_meta_with_mono(
        "ferrum".to_string(),
        Some("ws-framed".to_string()),
        "10.0.0.8".to_string(),
        "backend:9001".to_string(),
        8443,
        None,
        HashMap::new(),
        wall_forward,
        Instant::now(),
    );
    let expected_fwd_connected = meta_fwd.session_start.to_rfc3339();

    fire_ws_framed_disconnect_hooks(&plugins_fwd, "proxy-framed", meta_fwd, 1, 1, 8, 8, None).await;

    let captured_fwd = captured_fwd.lock().unwrap();
    assert_eq!(captured_fwd.len(), 1);
    assert!(
        captured_fwd[0].duration_ms < 5_000.0,
        "framed duration_ms must not inflate under forward wall skew; got {}",
        captured_fwd[0].duration_ms
    );
    assert_eq!(
        captured_fwd[0].timestamp_connected, expected_fwd_connected,
        "forward-skewed wall connect timestamp is still rendered"
    );
}

#[tokio::test]
async fn test_tunnel_and_framed_disconnect_preserve_admission_connection_id() {
    // Issue #2560: tunnel residual/relay teardown, framed teardown, and the
    // H1/H2 upgrade-handoff failure path all build WsDisconnectContext from
    // WsSessionMeta.connection_id — the same process-local ID allocated at
    // admission and passed to on_ws_frame. Multiple plugins must observe it
    // without a per-frame lookup map.
    let (plugin_a, captured_a) = CapturingDisconnectPlugin::new();
    let (plugin_b, captured_b) = CapturingDisconnectPlugin::new();
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(plugin_a), Arc::new(plugin_b)];

    let tunnel_id = 1001u64;
    let framed_id = 1002u64;
    let handoff_id = 1003u64;

    fire_ws_tunnel_disconnect_hooks(
        &plugins,
        "proxy-tunnel",
        &session_meta_with_id(tunnel_id),
        8,
        16,
        None,
    )
    .await;

    fire_ws_framed_disconnect_hooks(
        &plugins,
        "proxy-framed",
        session_meta_with_id(framed_id),
        2,
        3,
        20,
        30,
        Some((
            Direction::ClientToBackend,
            ErrorClass::ConnectionReset,
            Some(StreamIoSide::Read),
        )),
    )
    .await;

    // Upgrade-handoff failure reuses the tunnel helper with zero counts and
    // ConnectionClosed / Unknown direction (see proxy/mod.rs handoff Err arm).
    fire_ws_tunnel_disconnect_hooks(
        &plugins,
        "proxy-handoff",
        &session_meta_with_id(handoff_id),
        0,
        0,
        Some((Direction::Unknown, ErrorClass::ConnectionClosed, None)),
    )
    .await;

    let a = captured_a.lock().unwrap();
    let b = captured_b.lock().unwrap();
    assert_eq!(a.len(), 3, "plugin A must see tunnel, framed, and handoff");
    assert_eq!(b.len(), 3, "plugin B must see the same three teardowns");

    assert_eq!(a[0].connection_id, tunnel_id);
    assert_eq!(a[0].proxy_id, "proxy-tunnel");
    assert_eq!(a[0].frames_c2b, 0);
    assert_eq!(a[0].frames_b2c, 0);

    assert_eq!(a[1].connection_id, framed_id);
    assert_eq!(a[1].proxy_id, "proxy-framed");
    assert_eq!(a[1].frames_c2b, 2);
    assert_eq!(a[1].frames_b2c, 3);
    assert_eq!(a[1].direction, Some(Direction::ClientToBackend));
    assert_eq!(a[1].error_class, Some(ErrorClass::ConnectionReset));

    assert_eq!(a[2].connection_id, handoff_id);
    assert_eq!(a[2].proxy_id, "proxy-handoff");
    assert_eq!(a[2].bytes_c2b, 0);
    assert_eq!(a[2].bytes_b2c, 0);
    assert_eq!(a[2].direction, Some(Direction::Unknown));
    assert_eq!(a[2].error_class, Some(ErrorClass::ConnectionClosed));

    // Every plugin instance receives the authoritative admission ID.
    for (idx, expected) in [tunnel_id, framed_id, handoff_id].into_iter().enumerate() {
        assert_eq!(b[idx].connection_id, expected);
        assert_eq!(b[idx].connection_id, a[idx].connection_id);
    }
}

#[tokio::test]
async fn test_session_meta_connection_id_survives_reload_style_plugin_resnapshot() {
    // Live sessions keep the admission plugin Arc list + WsSessionMeta captured
    // at upgrade. A later config reload may publish a new plugin generation, but
    // teardown still fires the original snapshot with the original connection_id.
    let admission_id = 7777u64;
    let (admission_plugin, admission_captured) = CapturingDisconnectPlugin::new();
    let admission_plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(admission_plugin)];
    let meta = session_meta_with_id(admission_id);

    // Simulate a reload that attaches a different disconnect plugin instance.
    let (reloaded_plugin, reloaded_captured) = CapturingDisconnectPlugin::new();
    let _reloaded_plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(reloaded_plugin)];

    fire_ws_framed_disconnect_hooks(&admission_plugins, "proxy-live", meta, 1, 1, 4, 4, None).await;

    let admission = admission_captured.lock().unwrap();
    let reloaded = reloaded_captured.lock().unwrap();
    assert_eq!(admission.len(), 1);
    assert_eq!(admission[0].connection_id, admission_id);
    assert!(
        reloaded.is_empty(),
        "reload-generation plugins must not observe a session accepted earlier"
    );
}

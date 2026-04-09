use ferrum_edge::overload::{ConnectionGuard, OverloadConfig, OverloadLevel, OverloadState};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

// ── OverloadState basics ──────────────────────────────────────────────

#[test]
fn new_state_is_normal_with_no_active_connections() {
    let state = OverloadState::new();
    assert_eq!(state.level(), OverloadLevel::Normal);
    assert!(!state.draining.load(Ordering::Relaxed));
    assert!(!state.disable_keepalive.load(Ordering::Relaxed));
    assert!(!state.reject_new_connections.load(Ordering::Relaxed));
    assert_eq!(state.active_connections.load(Ordering::Relaxed), 0);
}

#[test]
fn level_reflects_action_flags() {
    let state = OverloadState::new();

    // Pressure: keepalive disabled but still accepting
    state.disable_keepalive.store(true, Ordering::Relaxed);
    assert_eq!(state.level(), OverloadLevel::Pressure);

    // Critical: rejecting new connections (overrides pressure)
    state.reject_new_connections.store(true, Ordering::Relaxed);
    assert_eq!(state.level(), OverloadLevel::Critical);

    // Clear reject but keep disable_keepalive
    state.reject_new_connections.store(false, Ordering::Relaxed);
    assert_eq!(state.level(), OverloadLevel::Pressure);

    // Clear everything
    state.disable_keepalive.store(false, Ordering::Relaxed);
    assert_eq!(state.level(), OverloadLevel::Normal);
}

// ── ConnectionGuard ───────────────────────────────────────────────────

#[test]
fn connection_guard_tracks_concurrent_connections() {
    let state = Arc::new(OverloadState::new());

    let g1 = ConnectionGuard::new(&state);
    assert_eq!(state.active_connections.load(Ordering::Relaxed), 1);

    let g2 = ConnectionGuard::new(&state);
    assert_eq!(state.active_connections.load(Ordering::Relaxed), 2);

    let g3 = ConnectionGuard::new(&state);
    assert_eq!(state.active_connections.load(Ordering::Relaxed), 3);

    drop(g2);
    assert_eq!(state.active_connections.load(Ordering::Relaxed), 2);

    drop(g1);
    assert_eq!(state.active_connections.load(Ordering::Relaxed), 1);

    drop(g3);
    assert_eq!(state.active_connections.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn connection_guard_notifies_drain_on_last_drop() {
    let state = Arc::new(OverloadState::new());
    state.draining.store(true, Ordering::Relaxed);

    let g1 = ConnectionGuard::new(&state);
    let g2 = ConnectionGuard::new(&state);

    let state2 = state.clone();
    let waiter = tokio::spawn(async move {
        state2.drain_complete.notified().await;
    });

    // Dropping g1 should NOT notify (g2 still alive)
    drop(g1);
    assert_eq!(state.active_connections.load(Ordering::Relaxed), 1);

    // Give a brief moment to verify waiter is still pending
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(!waiter.is_finished());

    // Dropping g2 (last connection) SHOULD notify
    drop(g2);
    tokio::time::timeout(Duration::from_secs(1), waiter)
        .await
        .expect("drain notification timed out")
        .expect("waiter task panicked");
}

#[test]
fn connection_guard_does_not_notify_when_not_draining() {
    let state = Arc::new(OverloadState::new());
    // draining is false
    let guard = ConnectionGuard::new(&state);
    drop(guard);
    // No panic, no notification — just decrements
    assert_eq!(state.active_connections.load(Ordering::Relaxed), 0);
}

// ── Snapshot ──────────────────────────────────────────────────────────

#[test]
fn snapshot_captures_current_state() {
    let state = OverloadState::new();
    state.fd_current.store(500, Ordering::Relaxed);
    state.fd_max.store(1024, Ordering::Relaxed);
    state.conn_current.store(9000, Ordering::Relaxed);
    state.conn_max.store(10000, Ordering::Relaxed);
    state.loop_latency_us.store(42, Ordering::Relaxed);
    state.disable_keepalive.store(true, Ordering::Relaxed);

    let snap = state.snapshot();

    assert_eq!(snap.level, OverloadLevel::Pressure);
    assert_eq!(snap.pressure.file_descriptors.current, 500);
    assert_eq!(snap.pressure.file_descriptors.max, 1024);
    assert!((snap.pressure.file_descriptors.ratio - 500.0 / 1024.0).abs() < 0.001);
    assert_eq!(snap.pressure.connections.current, 9000);
    assert_eq!(snap.pressure.connections.max, 10000);
    assert!((snap.pressure.connections.ratio - 0.9).abs() < 0.001);
    assert_eq!(snap.pressure.event_loop_latency_us, 42);
    assert!(snap.actions.disable_keepalive);
    assert!(!snap.actions.reject_new_connections);
}

#[test]
fn snapshot_handles_zero_max_values() {
    let state = OverloadState::new();
    // fd_max and conn_max are 0 (default) — ratio should be 0.0, not NaN
    let snap = state.snapshot();
    assert_eq!(snap.pressure.file_descriptors.ratio, 0.0);
    assert_eq!(snap.pressure.connections.ratio, 0.0);
}

#[test]
fn snapshot_serializes_to_json() {
    let state = OverloadState::new();
    state.fd_current.store(100, Ordering::Relaxed);
    state.fd_max.store(1000, Ordering::Relaxed);

    let snap = state.snapshot();
    let json = serde_json::to_value(&snap).expect("snapshot should serialize");

    assert_eq!(json["level"], "normal");
    assert_eq!(json["pressure"]["file_descriptors"]["current"], 100);
    assert_eq!(json["pressure"]["file_descriptors"]["max"], 1000);
    assert!(json["actions"]["disable_keepalive"].is_boolean());
}

// ── wait_for_drain ───────────────────────────────────────────────────

#[tokio::test]
async fn drain_returns_true_immediately_when_no_connections() {
    let state = Arc::new(OverloadState::new());
    let result = ferrum_edge::overload::wait_for_drain(&state, Duration::from_secs(1)).await;
    assert!(result);
    assert!(state.draining.load(Ordering::Relaxed));
}

#[tokio::test]
async fn drain_waits_for_connections_to_complete() {
    let state = Arc::new(OverloadState::new());
    let guard = ConnectionGuard::new(&state);

    let state2 = state.clone();
    let drain_handle = tokio::spawn(async move {
        ferrum_edge::overload::wait_for_drain(&state2, Duration::from_secs(5)).await
    });

    // Give the drain waiter time to start
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(state.draining.load(Ordering::Relaxed));

    // Drop the connection — should trigger drain completion
    drop(guard);

    let result = tokio::time::timeout(Duration::from_secs(2), drain_handle)
        .await
        .expect("drain handle timed out")
        .expect("drain task panicked");
    assert!(result); // all drained
}

#[tokio::test]
async fn drain_times_out_with_remaining_connections() {
    let state = Arc::new(OverloadState::new());
    let _guard = ConnectionGuard::new(&state); // held for the duration

    let result = ferrum_edge::overload::wait_for_drain(&state, Duration::from_millis(50)).await;
    assert!(!result); // timed out
    assert_eq!(state.active_connections.load(Ordering::Relaxed), 1);
}

// ── OverloadConfig ──────────────────────────────────────────────────

#[test]
fn overload_config_default_thresholds() {
    let config = OverloadConfig::default();
    assert_eq!(config.check_interval_ms, 1000);
    assert!((config.fd_pressure_threshold - 0.80).abs() < f64::EPSILON);
    assert!((config.fd_critical_threshold - 0.95).abs() < f64::EPSILON);
    assert!((config.conn_pressure_threshold - 0.85).abs() < f64::EPSILON);
    assert!((config.conn_critical_threshold - 0.95).abs() < f64::EPSILON);
    assert_eq!(config.loop_warn_us, 10_000);
    assert_eq!(config.loop_critical_us, 500_000);
}

// ── EnvConfig integration ────────────────────────────────────────────

#[test]
fn env_config_default_overload_values() {
    let config = ferrum_edge::config::EnvConfig::default();
    assert_eq!(config.overload_check_interval_ms, 1000);
    assert!((config.overload_fd_pressure_threshold - 0.80).abs() < f64::EPSILON);
    assert!((config.overload_fd_critical_threshold - 0.95).abs() < f64::EPSILON);
    assert!((config.overload_conn_pressure_threshold - 0.85).abs() < f64::EPSILON);
    assert!((config.overload_conn_critical_threshold - 0.95).abs() < f64::EPSILON);
    assert_eq!(config.overload_loop_warn_us, 10_000);
    assert_eq!(config.overload_loop_critical_us, 500_000);
    assert_eq!(config.shutdown_drain_seconds, 30);
}

#[test]
fn env_config_overload_config_conversion() {
    let env = ferrum_edge::config::EnvConfig::default();
    let overload = env.overload_config();
    assert_eq!(overload.check_interval_ms, env.overload_check_interval_ms);
    assert_eq!(
        overload.fd_pressure_threshold,
        env.overload_fd_pressure_threshold
    );
    assert_eq!(
        overload.fd_critical_threshold,
        env.overload_fd_critical_threshold
    );
    assert_eq!(
        overload.conn_pressure_threshold,
        env.overload_conn_pressure_threshold
    );
    assert_eq!(
        overload.conn_critical_threshold,
        env.overload_conn_critical_threshold
    );
    assert_eq!(overload.loop_warn_us, env.overload_loop_warn_us);
    assert_eq!(overload.loop_critical_us, env.overload_loop_critical_us);
}

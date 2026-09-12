use ferrum_edge::overload::{
    ConnectionGuard, NodeWaypointDropReason, OverloadConfig, OverloadLevel, OverloadState,
    RED_PROBABILITY_SCALE, RequestGuard,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

// ── OverloadState basics ──────────────────────────────────────────────

#[test]
fn new_state_is_normal_with_no_active_connections() {
    let state = OverloadState::new();
    assert_eq!(state.level(), OverloadLevel::Normal);
    assert!(!state.draining.load(Ordering::Relaxed));
    assert!(!state.disable_keepalive.load(Ordering::Relaxed));
    assert!(!state.reject_new_connections.load(Ordering::Relaxed));
    assert!(!state.reject_new_requests.load(Ordering::Relaxed));
    assert_eq!(state.active_connections.load(Ordering::Relaxed), 0);
    assert_eq!(state.active_requests.load(Ordering::Relaxed), 0);
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

// ── RequestGuard ─────────────────────────────────────────────────────

#[test]
fn request_guard_tracks_concurrent_requests() {
    let state = Arc::new(OverloadState::new());

    let g1 = RequestGuard::new(&state);
    assert_eq!(state.active_requests.load(Ordering::Relaxed), 1);

    let g2 = RequestGuard::new(&state);
    assert_eq!(state.active_requests.load(Ordering::Relaxed), 2);

    let g3 = RequestGuard::new(&state);
    assert_eq!(state.active_requests.load(Ordering::Relaxed), 3);

    drop(g2);
    assert_eq!(state.active_requests.load(Ordering::Relaxed), 2);

    drop(g1);
    assert_eq!(state.active_requests.load(Ordering::Relaxed), 1);

    drop(g3);
    assert_eq!(state.active_requests.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn request_guard_notifies_drain_on_last_drop() {
    let state = Arc::new(OverloadState::new());
    state.draining.store(true, Ordering::Relaxed);

    let g1 = RequestGuard::new(&state);
    let g2 = RequestGuard::new(&state);

    let state2 = state.clone();
    let waiter = tokio::spawn(async move {
        state2.drain_complete.notified().await;
    });

    // Dropping g1 should NOT notify (g2 still alive)
    drop(g1);
    assert_eq!(state.active_requests.load(Ordering::Relaxed), 1);

    // Give a brief moment to verify waiter is still pending
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(!waiter.is_finished());

    // Dropping g2 (last request) SHOULD notify
    drop(g2);
    tokio::time::timeout(Duration::from_secs(1), waiter)
        .await
        .expect("drain notification timed out")
        .expect("waiter task panicked");
}

#[test]
fn reject_new_requests_sets_critical_level() {
    let state = OverloadState::new();
    assert_eq!(state.level(), OverloadLevel::Normal);

    state.reject_new_requests.store(true, Ordering::Relaxed);
    assert_eq!(state.level(), OverloadLevel::Critical);

    state.reject_new_requests.store(false, Ordering::Relaxed);
    assert_eq!(state.level(), OverloadLevel::Normal);
}

// ── Snapshot ──────────────────────────────────────────────────────────

#[test]
fn snapshot_captures_current_state() {
    let state = OverloadState::new();
    state.fd_current.store(500, Ordering::Relaxed);
    state.fd_max.store(1024, Ordering::Relaxed);
    state.conn_current.store(9000, Ordering::Relaxed);
    state.conn_max.store(10000, Ordering::Relaxed);
    state.req_current.store(5000, Ordering::Relaxed);
    state.req_max.store(20000, Ordering::Relaxed);
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
    assert_eq!(snap.pressure.requests.current, 5000);
    assert_eq!(snap.pressure.requests.max, 20000);
    assert!((snap.pressure.requests.ratio - 0.25).abs() < 0.001);
    assert_eq!(snap.pressure.event_loop_latency_us, 42);
    assert!(snap.actions.disable_keepalive);
    assert!(!snap.actions.reject_new_connections);
    assert!(!snap.actions.reject_new_requests);
}

#[test]
fn snapshot_handles_zero_max_values() {
    let state = OverloadState::new();
    // fd_max, conn_max, and req_max are 0 (default) — ratio should be 0.0, not NaN
    let snap = state.snapshot();
    assert_eq!(snap.pressure.file_descriptors.ratio, 0.0);
    assert_eq!(snap.pressure.connections.ratio, 0.0);
    assert_eq!(snap.pressure.requests.ratio, 0.0);
}

#[test]
fn snapshot_serializes_to_json() {
    let state = OverloadState::new();
    state.fd_current.store(100, Ordering::Relaxed);
    state.fd_max.store(1000, Ordering::Relaxed);
    state.req_current.store(42, Ordering::Relaxed);
    state.req_max.store(500, Ordering::Relaxed);

    let snap = state.snapshot();
    let json = serde_json::to_value(&snap).expect("snapshot should serialize");

    assert_eq!(json["level"], "normal");
    assert_eq!(json["pressure"]["file_descriptors"]["current"], 100);
    assert_eq!(json["pressure"]["file_descriptors"]["max"], 1000);
    assert_eq!(json["pressure"]["requests"]["current"], 42);
    assert_eq!(json["pressure"]["requests"]["max"], 500);
    assert!(json["actions"]["disable_keepalive"].is_boolean());
    assert!(json["actions"]["reject_new_requests"].is_boolean());
    assert!(json["active_requests"].is_number());
}

// ── begin_drain ──────────────────────────────────────────────────────

#[test]
fn begin_drain_sets_draining_and_reject_new_requests() {
    let state = Arc::new(OverloadState::new());
    assert!(!state.draining.load(Ordering::Acquire));
    assert!(!state.reject_new_requests.load(Ordering::Acquire));

    ferrum_edge::overload::begin_drain(&state);

    assert!(
        state.draining.load(Ordering::Acquire),
        "begin_drain must set draining=true so HTTP/1.1 responses get \
         Connection: close even when shutdown_drain_seconds=0",
    );
    assert!(
        state.reject_new_requests.load(Ordering::Acquire),
        "begin_drain must set reject_new_requests=true so new requests on \
         existing keepalive H1 / multiplexed H2/H3 connections get 503'd \
         during drain rather than continuing to be admitted",
    );
}

#[test]
fn begin_drain_promotes_state_to_critical() {
    let state = Arc::new(OverloadState::new());
    assert_eq!(state.level(), OverloadLevel::Normal);

    ferrum_edge::overload::begin_drain(&state);

    // reject_new_requests=true makes level Critical (see level()).
    assert_eq!(state.level(), OverloadLevel::Critical);
}

#[test]
fn begin_drain_is_idempotent() {
    let state = Arc::new(OverloadState::new());
    ferrum_edge::overload::begin_drain(&state);
    ferrum_edge::overload::begin_drain(&state);
    assert!(state.draining.load(Ordering::Acquire));
    assert!(state.reject_new_requests.load(Ordering::Acquire));
}

// ── wait_for_drain ───────────────────────────────────────────────────

#[tokio::test]
async fn drain_returns_true_immediately_when_no_connections() {
    let state = Arc::new(OverloadState::new());
    ferrum_edge::overload::begin_drain(&state);
    let result = ferrum_edge::overload::wait_for_drain(&state, Duration::from_secs(1)).await;
    assert!(result);
    assert!(state.draining.load(Ordering::Acquire));
}

#[tokio::test]
async fn drain_waits_for_connections_to_complete() {
    let state = Arc::new(OverloadState::new());
    ferrum_edge::overload::begin_drain(&state);
    let guard = ConnectionGuard::new(&state);

    let state2 = state.clone();
    let drain_handle = tokio::spawn(async move {
        ferrum_edge::overload::wait_for_drain(&state2, Duration::from_secs(5)).await
    });

    // Give the drain waiter time to start
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(state.draining.load(Ordering::Acquire));

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
    ferrum_edge::overload::begin_drain(&state);
    let _guard = ConnectionGuard::new(&state); // held for the duration

    let result = ferrum_edge::overload::wait_for_drain(&state, Duration::from_millis(50)).await;
    assert!(!result); // timed out
    assert_eq!(state.active_connections.load(Ordering::Relaxed), 1);
}

#[test]
fn wait_for_drain_does_not_clear_begin_drain_flags() {
    // Regression: `begin_drain` is the unconditional shutdown signal; the
    // wait loop must not be the only place those flags get set, otherwise
    // FERRUM_SHUTDOWN_DRAIN_SECONDS=0 (which skips wait_for_drain entirely
    // in every mode) would leave keepalive connections without the close
    // hint and admit new H2/H3 streams during drain.
    let state = Arc::new(OverloadState::new());
    ferrum_edge::overload::begin_drain(&state);
    // Synchronously verify both flags are observable without invoking the
    // async wait loop — the modes call `begin_drain` BEFORE the gated
    // `if drain_seconds > 0 { wait_for_drain(...) }` block.
    assert!(state.draining.load(Ordering::Acquire));
    assert!(state.reject_new_requests.load(Ordering::Acquire));
}

#[tokio::test]
async fn overload_monitor_preserves_reject_new_requests_during_drain() {
    let state = Arc::new(OverloadState::new());
    let _conn_guard = ConnectionGuard::new(&state);
    ferrum_edge::overload::begin_drain(&state);

    let config = OverloadConfig {
        check_interval_ms: 1,
        ..OverloadConfig::default()
    };
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let monitor =
        ferrum_edge::overload::start_monitor(state.clone(), config, 1000, 10, shutdown_rx);

    tokio::time::timeout(Duration::from_secs(1), async {
        while state.conn_current.load(Ordering::Relaxed) != 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("overload monitor did not tick");

    assert!(
        state.draining.load(Ordering::Acquire),
        "monitor tick must not clear draining",
    );
    assert!(
        state.reject_new_requests.load(Ordering::Acquire),
        "monitor tick must preserve request rejection while draining, even \
         when request pressure is below the critical threshold",
    );

    shutdown_tx
        .send(true)
        .expect("monitor shutdown receiver should still be alive");
    tokio::time::timeout(Duration::from_secs(1), monitor)
        .await
        .expect("overload monitor did not stop")
        .expect("overload monitor task panicked");
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
    assert!((config.overload_req_pressure_threshold - 0.85).abs() < f64::EPSILON);
    assert!((config.overload_req_critical_threshold - 0.95).abs() < f64::EPSILON);
    assert_eq!(config.overload_loop_warn_us, 10_000);
    assert_eq!(config.overload_loop_critical_us, 500_000);
    assert_eq!(config.shutdown_drain_seconds, 30);
    assert_eq!(config.max_requests, 0);
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
    assert_eq!(
        overload.req_pressure_threshold,
        env.overload_req_pressure_threshold
    );
    assert_eq!(
        overload.req_critical_threshold,
        env.overload_req_critical_threshold
    );
    assert_eq!(overload.loop_warn_us, env.overload_loop_warn_us);
    assert_eq!(overload.loop_critical_us, env.overload_loop_critical_us);
}

// ── Threshold boundary tests ─────────────────────────────────────────

#[test]
fn red_probability_at_edge_values() {
    let state = Arc::new(OverloadState::new());

    // prob = 1 (lowest non-zero): should almost never trigger
    state.red_drop_probability.store(1, Ordering::Relaxed);
    let mut triggered = 0;
    for _ in 0..10_000 {
        if state.should_disable_keepalive_red() {
            triggered += 1;
        }
    }
    // prob=1 out of RED_PROBABILITY_SCALE ~ 0.1%, expect ~10 out of 10000
    assert!(
        triggered < 100,
        "prob=1 should trigger rarely, got {}",
        triggered
    );

    // prob = 1023 (just below max): should almost always trigger
    state.red_drop_probability.store(1023, Ordering::Relaxed);
    let mut triggered = 0;
    for _ in 0..10_000 {
        if state.should_disable_keepalive_red() {
            triggered += 1;
        }
    }
    assert!(
        triggered > 9000,
        "prob=1023 should trigger almost always, got {}",
        triggered
    );
}

#[test]
fn red_zero_probability_never_triggers() {
    let state = Arc::new(OverloadState::new());
    state.red_drop_probability.store(0, Ordering::Relaxed);
    for _ in 0..1000 {
        assert!(
            !state.should_disable_keepalive_red(),
            "prob=0 should never trigger"
        );
    }
}

#[test]
fn red_max_probability_always_triggers() {
    let state = Arc::new(OverloadState::new());
    state
        .red_drop_probability
        .store(RED_PROBABILITY_SCALE, Ordering::Relaxed);
    for _ in 0..1000 {
        assert!(
            state.should_disable_keepalive_red(),
            "prob=RED_PROBABILITY_SCALE should always trigger"
        );
    }
}

#[test]
fn reject_new_requests_flag_sets_critical() {
    let state = OverloadState::new();
    state.reject_new_requests.store(true, Ordering::Relaxed);
    assert_eq!(state.level(), OverloadLevel::Critical);
}

#[test]
fn snapshot_req_ratio_zero_when_max_is_zero() {
    let state = Arc::new(OverloadState::new());
    state.req_current.store(100, Ordering::Relaxed);
    state.req_max.store(0, Ordering::Relaxed);

    let snap = state.snapshot();
    assert!(
        (snap.pressure.requests.ratio - 0.0).abs() < f64::EPSILON,
        "req_ratio should be 0.0 when max is 0, got {}",
        snap.pressure.requests.ratio
    );
}

#[test]
fn snapshot_ratios_correct() {
    let state = Arc::new(OverloadState::new());
    state.fd_current.store(80, Ordering::Relaxed);
    state.fd_max.store(100, Ordering::Relaxed);
    state.conn_current.store(85, Ordering::Relaxed);
    state.conn_max.store(100, Ordering::Relaxed);
    state.req_current.store(950, Ordering::Relaxed);
    state.req_max.store(1000, Ordering::Relaxed);

    let snap = state.snapshot();
    assert!((snap.pressure.file_descriptors.ratio - 0.8).abs() < 0.001);
    assert!((snap.pressure.connections.ratio - 0.85).abs() < 0.001);
    assert!((snap.pressure.requests.ratio - 0.95).abs() < 0.001);
}

// ── Concurrent guard creation during drain ───────────────────────────

#[tokio::test]
async fn drain_with_concurrent_guard_creation() {
    let state = Arc::new(OverloadState::new());
    ferrum_edge::overload::begin_drain(&state);

    // Create a guard, then spawn drain waiter
    let g1 = ConnectionGuard::new(&state);

    let state2 = state.clone();
    let handle = tokio::spawn(async move {
        ferrum_edge::overload::wait_for_drain(&state2, Duration::from_secs(5)).await
    });

    // Create another guard while drain is waiting
    let g2 = ConnectionGuard::new(&state);
    assert_eq!(state.active_connections.load(Ordering::Relaxed), 2);

    // Drop first guard — drain should NOT complete yet
    drop(g1);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!handle.is_finished());

    // Drop second guard — drain should complete
    drop(g2);
    let result = handle.await.unwrap();
    assert!(result, "Drain should succeed after all guards drop");
}

// ── Both connection and request guards must drain ────────────────────

#[tokio::test]
async fn drain_waits_for_both_connections_and_requests() {
    let state = Arc::new(OverloadState::new());
    ferrum_edge::overload::begin_drain(&state);

    let conn_guard = ConnectionGuard::new(&state);
    let req_guard = RequestGuard::new(&state);

    let state2 = state.clone();
    let handle = tokio::spawn(async move {
        ferrum_edge::overload::wait_for_drain(&state2, Duration::from_secs(5)).await
    });

    // Drop connection guard — request still active
    drop(conn_guard);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!handle.is_finished(), "Should still wait for requests");

    // Drop request guard
    drop(req_guard);
    let result = handle.await.unwrap();
    assert!(result, "Drain should complete when both reach zero");
}

// ── Port exhaustion counter ─────────────────────────────────────────

#[test]
fn port_exhaustion_counter_starts_at_zero() {
    let state = OverloadState::new();
    assert_eq!(state.port_exhaustion_events.load(Ordering::Relaxed), 0);
}

#[test]
fn port_exhaustion_counter_increments() {
    let state = OverloadState::new();
    state.record_port_exhaustion();
    state.record_port_exhaustion();
    assert_eq!(state.port_exhaustion_events.load(Ordering::Relaxed), 2);
}

#[test]
fn snapshot_includes_red_probability() {
    let state = OverloadState::new();
    // half of RED_PROBABILITY_SCALE = 50%
    state
        .red_drop_probability
        .store(RED_PROBABILITY_SCALE / 2, Ordering::Relaxed);
    let snap = state.snapshot();
    assert!((snap.red_drop_probability_pct - 50.0).abs() < 0.1);
}

#[test]
fn snapshot_includes_port_exhaustion_events() {
    let state = OverloadState::new();
    state.fd_max.store(1024, Ordering::Relaxed);
    state.record_port_exhaustion();
    state.record_port_exhaustion();
    state.record_port_exhaustion();
    let snap = state.snapshot();
    assert_eq!(snap.port_exhaustion_events, 3);
}

#[test]
fn snapshot_includes_node_waypoint_drop_counters() {
    let state = OverloadState::new();
    state.record_node_waypoint_drop(NodeWaypointDropReason::UnknownCookie);
    state.record_node_waypoint_drop(NodeWaypointDropReason::MissingWorkloadHash);
    state.record_node_waypoint_drop(NodeWaypointDropReason::MissingWorkloadHash);

    let snap = state.snapshot();

    assert_eq!(snap.node_waypoint_drops.unknown_cookie, 1);
    assert_eq!(snap.node_waypoint_drops.missing_workload_hash, 2);
    assert_eq!(snap.node_waypoint_drops.hash_mismatch, 0);
}

/// FD sampling must never run on the thread driving the runtime. The monitor
/// now takes its sample through the bounded `sample_open_fd_count` helper
/// (issue #4786) instead of calling `spawn_blocking(count_open_fds)` inline, so
/// this asserts the behaviour — the closure observes a different thread — plus
/// the fact that the monitor still feeds `count_open_fds` into that helper.
#[tokio::test]
async fn overload_fd_sample_runs_on_blocking_pool() {
    // `#[tokio::test]` builds a current-thread runtime, so the async body runs
    // on this very thread: a matching thread id would mean the count blocked
    // the runtime worker rather than the blocking pool.
    let worker = std::thread::current().id();
    let (sampled_on_tx, sampled_on_rx) = std::sync::mpsc::channel();
    let mut in_flight = None;
    let sample = sample_open_fd_count(&mut in_flight, Duration::from_secs(5), 7, move || {
        let _ = sampled_on_tx.send(std::thread::current().id());
        42
    })
    .await;
    assert_eq!(sample.current, 42);
    assert!(!sample.timed_out);
    let sampled_on = sampled_on_rx
        .recv()
        .expect("the counting closure must run and report its thread");
    assert_ne!(
        sampled_on, worker,
        "FD sampling must leave the tokio worker via spawn_blocking"
    );

    let src = include_str!("../../../src/overload.rs");
    assert!(
        src.contains("&mut fd_count_in_flight"),
        "the monitor must take its FD sample through the bounded blocking-pool helper"
    );
    assert!(
        src.contains("linux_fd_count_from_stat"),
        "Linux must prefer the kernel open-FD aggregate when procfs reports it"
    );
    assert!(
        src.contains("linux_fd_count_from_walk"),
        "Linux must keep a directory-walk fallback when the aggregate is unavailable"
    );
}

#[test]
fn system_sampler_runs_on_blocking_pool() {
    let src = include_str!("../../../src/system_metrics.rs");
    assert!(
        src.contains("tokio::task::spawn_blocking(SystemSampler::new)"),
        "system sampler construction must not block a worker"
    );
    assert!(
        src.contains("tokio::task::spawn_blocking(move ||"),
        "system sampler ticks must not block a worker"
    );
    assert!(
        src.contains("read_line"),
        "/proc/stat must be consumed by read_line, not a full-file read_to_string"
    );
    assert!(
        !src.contains("read_to_string(\"/proc/stat\")"),
        "must not slurp all of /proc/stat just to parse the first line"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn overload_monitor_publishes_fd_current() {
    let state = Arc::new(OverloadState::new());
    let config = OverloadConfig {
        check_interval_ms: 1,
        ..OverloadConfig::default()
    };
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let monitor = ferrum_edge::overload::start_monitor(state.clone(), config, 1000, 0, shutdown_rx);

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let fd_current = state.fd_current.load(Ordering::Relaxed);
            if fd_current > 0 && fd_current < u64::MAX {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("overload monitor did not publish a live fd_current");

    shutdown_tx
        .send(true)
        .expect("monitor shutdown receiver should still be alive");
    tokio::time::timeout(Duration::from_secs(1), monitor)
        .await
        .expect("overload monitor did not stop")
        .expect("overload monitor task panicked");
}

// ── FD limit classification (issue #4787) ─────────────────────────────

use ferrum_edge::overload::FD_LIMIT_MAX_ENFORCEABLE;
use ferrum_edge::overload::FdLimitVerdict;
use ferrum_edge::overload::ShutdownSignalAction;
use ferrum_edge::overload::begin_drain;
use ferrum_edge::overload::classify_fd_limit_with_ceiling;
use ferrum_edge::overload::classify_shutdown_signal;
use ferrum_edge::overload::fd_count_timeout_warn_should_fire;
use ferrum_edge::overload::sample_open_fd_count;
use ferrum_edge::overload::wait_for_drain_with_escalation;
use tokio_util::sync::CancellationToken;

#[test]
fn finite_fd_limit_is_enforced_directly() {
    let verdict = classify_fd_limit_with_ceiling(65_536, None);
    assert_eq!(verdict, FdLimitVerdict::Enforced(65_536));
    assert_eq!(verdict.fd_max(), 65_536);
    assert!(verdict.is_enforced());
}

#[test]
fn zero_fd_limit_is_not_enforceable() {
    // `getrlimit` failed, or a platform with no RLIMIT_NOFILE.
    let verdict = classify_fd_limit_with_ceiling(0, Some(1_048_576));
    assert_eq!(verdict, FdLimitVerdict::NotEnforceable);
    assert_eq!(verdict.fd_max(), 0);
    assert!(!verdict.is_enforced());
}

#[test]
fn unlimited_fd_hard_cap_without_a_platform_ceiling_disables_the_tier() {
    // RLIM_INFINITY: `raise_fd_limit()` raises the soft cap to it, which used
    // to publish `fd_max = i64::MAX` and a ratio that could never reach the
    // 0.80 pressure or 0.95 critical threshold.
    for limit in [u64::MAX, i64::MAX as u64, FD_LIMIT_MAX_ENFORCEABLE] {
        let verdict = classify_fd_limit_with_ceiling(limit, None);
        assert_eq!(
            verdict,
            FdLimitVerdict::NotEnforceable,
            "limit {limit} should not be enforceable"
        );
        assert_eq!(verdict.fd_max(), 0);
    }
}

#[test]
fn unlimited_fd_hard_cap_clamps_to_a_published_platform_ceiling() {
    let verdict = classify_fd_limit_with_ceiling(u64::MAX, Some(1_048_576));
    assert_eq!(verdict, FdLimitVerdict::ClampedToPlatformCeiling(1_048_576));
    assert_eq!(verdict.fd_max(), 1_048_576);
    assert!(verdict.is_enforced());
}

#[test]
fn implausible_platform_ceiling_does_not_rescue_an_unlimited_cap() {
    for ceiling in [Some(0u64), Some(u64::MAX)] {
        let verdict = classify_fd_limit_with_ceiling(u64::MAX, ceiling);
        assert_eq!(verdict, FdLimitVerdict::NotEnforceable);
    }
}

#[test]
fn disabled_fd_tier_reports_enforced_false_in_the_snapshot() {
    let state = OverloadState::new();
    state.fd_current.store(45, Ordering::Relaxed);
    // `fd_max = 0` is how the monitor publishes "not enforceable".
    state.fd_max.store(0, Ordering::Relaxed);
    let snapshot = state.snapshot();
    assert!(!snapshot.pressure.file_descriptors.enforced);
    assert_eq!(snapshot.pressure.file_descriptors.max, 0);
    assert_eq!(snapshot.pressure.file_descriptors.ratio, 0.0);

    state.fd_max.store(65_536, Ordering::Relaxed);
    let snapshot = state.snapshot();
    assert!(snapshot.pressure.file_descriptors.enforced);
    assert!(snapshot.pressure.file_descriptors.ratio > 0.0);
}

// ── Monitor FD-count timeout (issue #4786) ────────────────────────────

#[tokio::test]
async fn fd_count_sample_returns_the_measured_count_when_it_completes() {
    let mut in_flight = None;
    let sample = sample_open_fd_count(&mut in_flight, Duration::from_secs(5), 7, || 42);
    let sample = sample.await;
    assert_eq!(sample.current, 42);
    assert!(!sample.timed_out);
}

#[tokio::test]
async fn fd_count_sample_keeps_the_previous_count_when_the_blocking_pool_is_saturated() {
    // Failing closed to u64::MAX here would drive fd_ratio to 1.0 and latch
    // the gateway into permanent rejection — the outage the timeout prevents.
    let stalled = || {
        std::thread::sleep(Duration::from_secs(3));
        99
    };
    let mut in_flight = None;
    let sample = sample_open_fd_count(&mut in_flight, Duration::from_millis(20), 1234, stalled);
    let sample = sample.await;
    assert_eq!(sample.current, 1234);
    assert!(sample.timed_out);
}

#[tokio::test]
async fn fd_count_sample_is_single_flight_after_timeout() {
    let submissions = Arc::new(AtomicU64::new(0));
    let first_submissions = Arc::clone(&submissions);
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let mut in_flight = None;

    let first = sample_open_fd_count(&mut in_flight, Duration::from_millis(10), 7, move || {
        first_submissions.fetch_add(1, Ordering::Relaxed);
        release_rx
            .recv()
            .expect("the test must release the retained blocking task");
        42
    })
    .await;
    assert!(first.timed_out);

    let duplicate_submissions = Arc::clone(&submissions);
    let second = sample_open_fd_count(
        &mut in_flight,
        Duration::from_millis(10),
        first.current,
        move || {
            duplicate_submissions.fetch_add(1, Ordering::Relaxed);
            99
        },
    )
    .await;
    assert!(second.timed_out);
    assert_eq!(submissions.load(Ordering::Relaxed), 1);

    release_tx
        .send(())
        .expect("the retained blocking task must still be running");
    let completed = sample_open_fd_count(&mut in_flight, Duration::from_secs(1), 7, || 99).await;
    assert_eq!(completed.current, 42);
    assert!(!completed.timed_out);
}

#[test]
fn fd_count_timeout_warning_is_rate_limited() {
    assert!(fd_count_timeout_warn_should_fire(10, None));
    assert!(!fd_count_timeout_warn_should_fire(11, Some(10)));
    assert!(!fd_count_timeout_warn_should_fire(69, Some(10)));
    assert!(fd_count_timeout_warn_should_fire(70, Some(10)));
}

// ── Repeated shutdown signal escalation (issue #4829) ─────────────────

#[test]
fn repeated_shutdown_signals_escalate_then_acknowledge() {
    assert_eq!(
        classify_shutdown_signal(1),
        ShutdownSignalAction::InitiateDrain
    );
    assert_eq!(classify_shutdown_signal(2), ShutdownSignalAction::Escalate);
    assert_eq!(
        classify_shutdown_signal(3),
        ShutdownSignalAction::AlreadyEscalated
    );
    assert_eq!(
        classify_shutdown_signal(9),
        ShutdownSignalAction::AlreadyEscalated
    );
    // Defensive: the counter is incremented before classification, so 0 is
    // unreachable, but it must not panic on the shutdown path.
    assert_eq!(
        classify_shutdown_signal(0),
        ShutdownSignalAction::InitiateDrain
    );
}

#[tokio::test]
async fn escalation_cuts_the_drain_wait_short() {
    let state = Arc::new(OverloadState::new());
    let conn = ConnectionGuard::new(&state);
    begin_drain(&state);

    // A local token, not the process-global latch: escalating that one would
    // make every later drain in this test binary observe a cut-short wait.
    let escalation = CancellationToken::new();
    let escalation_signal = escalation.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        escalation_signal.cancel();
    });

    let started = std::time::Instant::now();
    let wait = wait_for_drain_with_escalation(&state, Duration::from_secs(30), escalation);
    let drained = wait.await;
    assert!(!drained, "an escalated drain did not complete");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "escalation should skip the remaining 30s drain budget"
    );
    // The connection is still tracked: escalation force-closes, it does not
    // pretend the drain finished.
    assert_eq!(state.active_connections.load(Ordering::Relaxed), 1);
    drop(conn);
}

#[tokio::test]
async fn an_already_escalated_shutdown_does_not_wait_at_all() {
    let state = Arc::new(OverloadState::new());
    let conn = ConnectionGuard::new(&state);
    begin_drain(&state);

    let escalation = CancellationToken::new();
    escalation.cancel();

    let started = std::time::Instant::now();
    let wait = wait_for_drain_with_escalation(&state, Duration::from_secs(30), escalation);
    let drained = wait.await;
    assert!(!drained);
    assert!(started.elapsed() < Duration::from_secs(1));
    drop(conn);
}

#[tokio::test]
async fn a_single_signal_still_performs_the_full_drain() {
    let state = Arc::new(OverloadState::new());
    let conn = ConnectionGuard::new(&state);
    begin_drain(&state);

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(conn);
    });

    // No escalation: the wait runs to completion, not to its timeout.
    let escalation = CancellationToken::new();
    let wait = wait_for_drain_with_escalation(&state, Duration::from_secs(10), escalation);
    let drained = wait.await;
    assert!(drained, "an unescalated drain should complete normally");
    assert_eq!(state.active_connections.load(Ordering::Relaxed), 0);
}

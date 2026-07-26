//! Supervision and exit classification for database/CP config poll tasks.
//!
//! The DB poll task in `database` and `cp` modes is long-lived and must not die
//! silently: operators need a freshness signal (`last_poll_completed_at`) and
//! the process must not remain `/health`-green with permanently stale config.
//!
//! Exit semantics (issue #2986):
//!
//! * **Ordinary shutdown** — the shared shutdown watch is already set (or becomes
//!   set while joining). Expected; no respawn and no serving degradation.
//! * **Panic** — `JoinError::is_panic()`. Unexpected.
//! * **Abort** — task cancelled without shutdown requested. Unexpected.
//! * **Unexpected completion** — task returned `Ok(())` without shutdown.
//!   Defensive; today's loops only return on shutdown.
//!
//! Mode policy on unexpected exit:
//!
//! * **database** — error-log and respawn a new poll generation after a bounded,
//!   shutdown-aware delay (keep serving last-known-good config). The delay
//!   prevents a tight spawn/panic/log loop under deterministic regressions.
//! * **cp** — sticky `serving_degraded` (mirrors listener-failure handling) so
//!   `/health` becomes not-ready; do not respawn.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::{JoinError, JoinHandle};
use tracing::error;

/// Fixed delay before respawning a database-mode poll generation after an
/// unexpected exit. Caps spawn/panic churn; interruptible by shutdown so drain
/// stays prompt. Normal operation (healthy generations) is not delayed — the
/// wait runs only after an unexpected exit, before the next `spawn_poll`.
pub const DATABASE_POLL_RESPAWN_DELAY: Duration = Duration::from_secs(1);

/// Classified outcome of awaiting a DB/CP config poll [`JoinHandle`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbPollTaskExitKind {
    /// Shutdown was already requested; exit is expected.
    OrdinaryShutdown,
    /// Task panicked.
    Panic,
    /// Task was aborted/cancelled without shutdown requested.
    Abort,
    /// Task returned successfully without shutdown requested.
    UnexpectedCompletion,
}

impl DbPollTaskExitKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OrdinaryShutdown => "ordinary_shutdown",
            Self::Panic => "panic",
            Self::Abort => "abort",
            Self::UnexpectedCompletion => "unexpected_completion",
        }
    }

    pub fn is_unexpected(self) -> bool {
        !matches!(self, Self::OrdinaryShutdown)
    }
}

/// Classify a poll-task join result against the shutdown watch.
///
/// When `shutdown_requested` is true, every join outcome is
/// [`DbPollTaskExitKind::OrdinaryShutdown`] — including panic/abort during
/// drain — so shutdown ownership stays bounded and operator-initiated stop is
/// never mistaken for a liveness failure.
pub fn classify_db_poll_task_exit(
    join_result: Result<(), JoinError>,
    shutdown_requested: bool,
) -> DbPollTaskExitKind {
    if shutdown_requested {
        return DbPollTaskExitKind::OrdinaryShutdown;
    }
    match join_result {
        Ok(()) => DbPollTaskExitKind::UnexpectedCompletion,
        Err(err) if err.is_panic() => DbPollTaskExitKind::Panic,
        Err(_) => DbPollTaskExitKind::Abort,
    }
}

/// Sticky CP degradation when the config poll task exits unexpectedly.
///
/// Reuses the same Release stores as listener-failure handling so `/health`
/// Acquire loads observe not-ready immediately and durably.
pub fn record_unexpected_cp_poll_task_exit(
    startup_ready: &AtomicBool,
    serving_degraded: &AtomicBool,
    kind: DbPollTaskExitKind,
) {
    debug_assert!(kind.is_unexpected());
    serving_degraded.store(true, Ordering::Release);
    startup_ready.store(false, Ordering::Release);
    error!(
        exit = kind.as_str(),
        "Control-plane database config poll task exited unexpectedly; marked serving degraded and flipped readiness to not-ready"
    );
}

/// Supervise the database-mode poll task: respawn on unexpected exit until
/// shutdown is requested.
///
/// Uses [`DATABASE_POLL_RESPAWN_DELAY`] between unexpected exits and the next
/// spawn. See [`supervise_database_mode_poll_task_with_delay`].
pub async fn supervise_database_mode_poll_task<F>(spawn_poll: F, shutdown_rx: watch::Receiver<bool>)
where
    F: FnMut() -> JoinHandle<()>,
{
    supervise_database_mode_poll_task_with_delay(
        spawn_poll,
        shutdown_rx,
        DATABASE_POLL_RESPAWN_DELAY,
    )
    .await
}

/// Supervise the database-mode poll task with an explicit respawn delay.
///
/// `spawn_poll` must clone whatever state each generation needs. The supervisor
/// owns shutdown observation and never leaves a finished handle unawaited.
///
/// After an unexpected exit, waits `respawn_delay` (via `tokio::time::sleep`)
/// before the next spawn. Shutdown during that wait returns immediately without
/// spawning another generation. A zero delay skips the wait (tests only).
pub async fn supervise_database_mode_poll_task_with_delay<F>(
    mut spawn_poll: F,
    mut shutdown_rx: watch::Receiver<bool>,
    respawn_delay: Duration,
) where
    F: FnMut() -> JoinHandle<()>,
{
    loop {
        if *shutdown_rx.borrow() {
            return;
        }

        let mut handle = spawn_poll();
        tokio::select! {
            result = &mut handle => {
                let shutdown_requested = *shutdown_rx.borrow();
                let kind = classify_db_poll_task_exit(result, shutdown_requested);
                if !kind.is_unexpected() {
                    return;
                }
                error!(
                    exit = kind.as_str(),
                    respawn_delay_ms = respawn_delay.as_millis() as u64,
                    "Database-mode config poll task exited unexpectedly; respawning poll loop after bounded delay while continuing to serve last-known-good config"
                );

                if wait_for_respawn_delay_or_shutdown(&mut shutdown_rx, respawn_delay).await {
                    return;
                }
            }
            changed = shutdown_rx.changed() => {
                // Poll task observes the same watch and should exit; await so
                // shutdown ownership stays with this supervisor (not a detached
                // orphan). Sender drop still drains the handle as shutdown.
                let _ = changed;
                let result = handle.await;
                let _ = classify_db_poll_task_exit(result, true);
                return;
            }
        }
    }
}

/// Wait `delay` before respawn, or return `true` if shutdown was requested
/// (including sender drop). Zero delay is a no-op success.
async fn wait_for_respawn_delay_or_shutdown(
    shutdown_rx: &mut watch::Receiver<bool>,
    delay: Duration,
) -> bool {
    if *shutdown_rx.borrow() {
        return true;
    }
    if delay.is_zero() {
        return false;
    }
    tokio::select! {
        _ = tokio::time::sleep(delay) => {
            *shutdown_rx.borrow()
        }
        changed = shutdown_rx.changed() => {
            let _ = changed;
            true
        }
    }
}

/// Watch a single CP poll handle until shutdown or unexpected exit.
///
/// On unexpected exit, flips sticky serving degradation and returns after the
/// handle has been joined. Does not respawn.
pub async fn supervise_control_plane_poll_task(
    mut handle: JoinHandle<()>,
    startup_ready: Arc<AtomicBool>,
    serving_degraded: Arc<AtomicBool>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    if *shutdown_rx.borrow() {
        let result = handle.await;
        let _ = classify_db_poll_task_exit(result, true);
        return;
    }

    tokio::select! {
        result = &mut handle => {
            let shutdown_requested = *shutdown_rx.borrow();
            let kind = classify_db_poll_task_exit(result, shutdown_requested);
            if kind.is_unexpected() {
                record_unexpected_cp_poll_task_exit(
                    &startup_ready,
                    &serving_degraded,
                    kind,
                );
            }
        }
        changed = shutdown_rx.changed() => {
            let _ = changed;
            let result = handle.await;
            let _ = classify_db_poll_task_exit(result, true);
        }
    }
}

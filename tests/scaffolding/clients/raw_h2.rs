//! Deterministic shutdown for a raw `h2` client connection driver.
//!
//! An h2 client `Connection` closes itself (GOAWAY, then EOF) once it has no
//! open streams and every `SendRequest`, `ResponseFuture`, `SendStream`, and
//! `RecvStream` is gone. Waiting for that after dropping the last handle can
//! hang, because h2 0.4.19 and earlier could lose the one wakeup the drop
//! delivers (fixed upstream in h2 0.4.20 by hyperium/h2#956, which Ferrum now
//! vendors; the PING below stays as a cheap guard against a regression):
//!
//! - `Connection::poll` (h2 0.4.19 `src/client.rs`) read
//!   "anything still held?" three times, each under its own lock: (1)
//!   `maybe_close_connection_if_no_streams` closes if nothing is held, (2) it
//!   records the answer as `had_streams_or_refs`, (3) after polling it wakes
//!   itself again if (2) saw something held and nothing is held now.
//! - Dropping the last handle wakes the driver only through the waker parked by
//!   `poll_complete` (`Drop for Streams` in `src/proto/streams/streams.rs`).
//!   The wake that started the current poll took that waker, and the poll does
//!   not park a new one until after (2).
//!
//! If the last handle drops between (1) and (2), then (1) saw it held and did
//! not close, (2) and (3) both see nothing held so the recheck does not fire,
//! and the drop found no waker to wake. The driver then waits on a socket the
//! idle server has no reason to write to. The race is rare, but it caused the
//! intermittent `bounded frontend cleanup: Elapsed` functional failures.
//!
//! [`join_idle_h2_driver`] sends one user PING after the caller has dropped every
//! handle. The PING wakes the driver through the waker its last poll parked in
//! `send_pending_ping`, so the driver polls again after the drop, finds nothing
//! held, and closes without sending the PING. A real leak still fails the
//! caller's bound: a held stream keeps the connection open after the pong.

use tokio::task::{JoinError, JoinSet};

/// Join the driver of a raw `h2` client connection whose request handles the
/// caller has ALREADY dropped. `ping_pong` must come from that connection
/// (`h2::client::Connection::ping_pong`, taken before the driver was spawned).
///
/// Returns the `JoinSet::join_next` result, so the caller keeps its own
/// timeout and the assertion that the driver closed cleanly.
pub async fn join_idle_h2_driver(
    mut ping_pong: h2::PingPong,
    driver: &mut JoinSet<Result<(), h2::Error>>,
) -> Option<Result<Result<(), h2::Error>, JoinError>> {
    // The result is ignored on purpose. `Err` means the driver had already
    // closed, or closed instead of sending the PING. A pong means the connection
    // stayed open, and `join_next` below then fails the caller's bound.
    let _ = ping_pong.ping(h2::Ping::opaque()).await;
    driver.join_next().await
}

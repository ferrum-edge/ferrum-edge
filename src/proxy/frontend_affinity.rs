//! Backend-shard affinity for a frontend connection (issue #5588).
//!
//! The direct HTTP/2 and gRPC pools keep `http2_connections_per_host` backend
//! connections (shards) per host. Each request used to pick its starting
//! shard round-robin, so the streams of one multiplexed frontend connection
//! were spread across every backend connection. Their responses then arrived
//! on different backend connections at different times, and the frontend
//! connection wrote them to the client one at a time. The client and the
//! backend did more reads, wakeups and decryptions per request than behind a
//! gateway that keeps a downstream connection's streams on one upstream
//! connection (as Envoy does per worker).
//!
//! Each accepted HTTP/1.1 or HTTP/2 frontend connection now takes a
//! connection number, and its requests run with that number in a task-local.
//! The pools start their shard probe at `number % shards`, so the streams of
//! one frontend connection share a backend connection and their responses
//! arrive, and leave, together. Connection numbers are assigned in order, so
//! frontend connections spread evenly over the shards. The probe still moves
//! on to the next shard when the preferred one is not immediately ready, and a
//! request with no frontend connection in scope (HTTP/3, spawned work) keeps
//! the round-robin start.

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_FRONTEND_CONNECTION: AtomicUsize = AtomicUsize::new(0);

tokio::task_local! {
    static FRONTEND_CONNECTION: usize;
}

/// The number for a newly accepted frontend connection.
pub fn next_frontend_connection() -> usize {
    NEXT_FRONTEND_CONNECTION.fetch_add(1, Ordering::Relaxed)
}

/// Run one request of frontend connection `connection` with its number in
/// scope for the backend pools.
pub async fn with_frontend_connection<F: Future>(connection: usize, request: F) -> F::Output {
    FRONTEND_CONNECTION.scope(connection, request).await
}

/// The shard a pool's probe starts at: the current frontend connection's
/// shard when one is in scope, otherwise the next round-robin position.
pub fn start_shard(round_robin: &AtomicUsize, shard_count: usize) -> usize {
    let shard_count = shard_count.max(1);
    FRONTEND_CONNECTION
        .try_with(|connection| *connection % shard_count)
        .unwrap_or_else(|_| round_robin.fetch_add(1, Ordering::Relaxed) % shard_count)
}

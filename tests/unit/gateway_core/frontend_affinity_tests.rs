//! Backend-shard affinity for a frontend connection (issue #5588): requests of
//! one HTTP/1.1 or HTTP/2 frontend connection start the direct HTTP/2 and gRPC
//! pools' shard probe at that connection's shard; anything else keeps the
//! round-robin start.

use ferrum_edge::proxy::frontend_affinity::{
    next_frontend_connection, start_shard, with_frontend_connection,
};
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn without_a_frontend_connection_the_start_is_round_robin() {
    let rr = AtomicUsize::new(5);
    assert_eq!(start_shard(&rr, 4), 1);
    assert_eq!(start_shard(&rr, 4), 2);
    assert_eq!(rr.load(Ordering::Relaxed), 7);
}

#[tokio::test]
async fn a_frontend_connection_always_starts_at_its_own_shard() {
    let rr = AtomicUsize::new(0);
    let starts = with_frontend_connection(6, async {
        [
            start_shard(&rr, 4),
            start_shard(&rr, 4),
            start_shard(&rr, 4),
        ]
    })
    .await;
    assert_eq!(starts, [2, 2, 2]);
    // The round-robin position is left for requests without a connection.
    assert_eq!(rr.load(Ordering::Relaxed), 0);
    // Outside the scope the start is round-robin again.
    assert_eq!(start_shard(&rr, 4), 0);
}

#[tokio::test]
async fn a_zero_shard_count_is_one_shard() {
    let rr = AtomicUsize::new(3);
    assert_eq!(start_shard(&rr, 0), 0);
    assert_eq!(
        with_frontend_connection(9, async { start_shard(&rr, 0) }).await,
        0
    );
}

#[test]
fn frontend_connection_numbers_increase() {
    // Numbers are handed out in accept order, so consecutive connections map
    // to consecutive shards (other tests may take numbers in between).
    let first = next_frontend_connection();
    let second = next_frontend_connection();
    assert!(second > first);
}

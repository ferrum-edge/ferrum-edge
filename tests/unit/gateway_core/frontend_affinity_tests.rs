//! Backend-shard affinity for a frontend connection (issue #5588): requests of
//! one HTTP/1.1 or HTTP/2 frontend connection start the gRPC pool's shard
//! probe at that connection's shard; anything else keeps the
//! round-robin start.

use ferrum_edge::proxy::frontend_affinity::{SlotTable, start_shard, with_frontend_connection};
use std::sync::atomic::{AtomicUsize, Ordering};

fn table() -> &'static SlotTable {
    Box::leak(Box::new(SlotTable::new()))
}

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
fn live_connections_spread_evenly_over_any_shard_count() {
    let table = table();
    let held: Vec<_> = (0..21).map(|_| table.acquire()).collect();
    for shard_count in [1, 2, 3, 4, 6, 8, 16] {
        let mut per_shard = vec![0usize; shard_count];
        for slot in &held {
            per_shard[slot.slot() % shard_count] += 1;
        }
        let (min, max) = (per_shard.iter().min(), per_shard.iter().max());
        assert!(
            max.zip(min).is_some_and(|(max, min)| max - min <= 1),
            "{shard_count} shards: {per_shard:?}"
        );
    }
}

#[test]
fn short_lived_connections_do_not_skew_long_lived_ones() {
    // A probe connection between two long-lived ones releases its slot, so the
    // next long-lived connection reuses it instead of shifting every later
    // connection onto another shard.
    let table = table();
    let mut held = Vec::new();
    for _ in 0..8 {
        held.push(table.acquire());
        drop(table.acquire());
        drop(table.acquire());
    }
    let mut per_shard = [0usize; 4];
    for slot in &held {
        per_shard[slot.slot() % 4] += 1;
    }
    assert_eq!(per_shard, [2, 2, 2, 2]);
}

#[test]
fn a_closed_connection_releases_its_slot() {
    let table = table();
    let first = table.acquire();
    let slot = first.slot();
    assert_eq!(table.live(slot), 1);
    drop(first);
    assert_eq!(table.live(slot), 0);
    // The freed slot is the least loaded again, so it is reused.
    assert_eq!(table.acquire().slot(), slot);
}

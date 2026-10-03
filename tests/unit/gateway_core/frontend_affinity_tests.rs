//! gRPC backend-shard affinity for an HTTP/2 frontend connection (issue #5588):
//! the slot table, the per-connection open-stream bound, the shard start the
//! gRPC pool reads, and a source guard on the frontend wiring. The pool-level
//! behaviour is covered against a real pool in
//! `tests/integration/http2_pool_tests.rs`.

use ferrum_edge::proxy::frontend_affinity::{
    AFFINITY_MAX_OPEN_STREAMS, FrontendConnectionAffinity, SLOTS, ShardStart, SlotTable,
    shard_start,
};

fn table() -> &'static SlotTable {
    Box::leak(Box::new(SlotTable::new()))
}

#[test]
fn without_a_frontend_stream_the_start_is_unscoped() {
    assert_eq!(shard_start(4), ShardStart::Unscoped);
}

#[test]
fn a_connection_takes_its_slot_on_its_first_stream_only() {
    let table = table();
    let connection = FrontendConnectionAffinity::with_table(table);
    assert_eq!(connection.slot(), None);
    assert_eq!(table.live(0), 0);
    let stream = connection.open_stream();
    assert_eq!(connection.slot(), Some(0));
    let second = connection.open_stream();
    assert_eq!(connection.slot(), Some(0));
    assert_eq!(table.live(0), 1, "one slot per connection, not per stream");
    drop((stream, second));
    drop(connection);
    assert_eq!(table.live(0), 0, "the slot is released with the connection");
}

#[tokio::test]
async fn a_stream_starts_at_its_connection_shard_until_the_bound() {
    let table = table();
    let _first = FrontendConnectionAffinity::with_table(table).open_stream();
    let connection = FrontendConnectionAffinity::with_table(table);
    let stream = connection.open_stream();
    assert_eq!(connection.slot(), Some(1));
    assert_eq!(
        stream.run(async { shard_start(4) }).await,
        ShardStart::Affinity(1)
    );
    assert_eq!(
        stream.run(async { shard_start(1) }).await,
        ShardStart::Affinity(0)
    );
    assert_eq!(
        stream.run(async { shard_start(0) }).await,
        ShardStart::Affinity(0)
    );

    // Up to the bound (this stream included) the connection keeps its shard.
    let mut more: Vec<_> = (1..AFFINITY_MAX_OPEN_STREAMS)
        .map(|_| connection.open_stream())
        .collect();
    assert_eq!(connection.open_streams(), AFFINITY_MAX_OPEN_STREAMS);
    assert_eq!(
        stream.run(async { shard_start(4) }).await,
        ShardStart::Affinity(1)
    );

    // One more open stream and its calls spill round-robin.
    more.push(connection.open_stream());
    assert_eq!(
        stream.run(async { shard_start(4) }).await,
        ShardStart::Spill
    );

    // Closing streams (each exactly once) brings it back under the bound.
    more.pop();
    assert_eq!(connection.open_streams(), AFFINITY_MAX_OPEN_STREAMS);
    assert_eq!(
        stream.run(async { shard_start(4) }).await,
        ShardStart::Affinity(1)
    );
    drop(more);
    assert_eq!(connection.open_streams(), 1);
}

#[tokio::test]
async fn a_pool_wider_than_the_slot_table_spills() {
    let connection = FrontendConnectionAffinity::with_table(table());
    let stream = connection.open_stream();
    assert_eq!(
        stream.run(async { shard_start(SLOTS) }).await,
        ShardStart::Affinity(0)
    );
    assert_eq!(
        stream.run(async { shard_start(SLOTS + 1) }).await,
        ShardStart::Spill
    );
}

#[tokio::test]
async fn a_cancelled_request_closes_its_stream() {
    let connection = FrontendConnectionAffinity::with_table(table());
    let stream = connection.open_stream();
    let request = tokio::spawn(async move {
        stream.run(std::future::pending::<()>()).await;
    });
    tokio::task::yield_now().await;
    assert_eq!(connection.open_streams(), 1);
    request.abort();
    let _ = request.await;
    assert_eq!(connection.open_streams(), 0);
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
fn both_frontends_open_a_stream_per_http2_request_and_keep_it_with_the_body() {
    let proxy = include_str!("../../../src/proxy/mod.rs");
    for needle in [
        ".filter(|_| req.version() == hyper::Version::HTTP_2)",
        ".map(frontend_affinity::FrontendConnectionAffinity::open_stream);",
        "Some(stream) => stream.run(request).await,",
        "response.map(|response| response.map(|body| body.with_frontend_stream(stream)));",
    ] {
        assert_eq!(
            proxy.matches(needle).count(),
            2,
            "plaintext and TLS frontends must both carry `{needle}`"
        );
    }
    assert!(
        proxy.contains("tls_alpn_h2.then(frontend_affinity::FrontendConnectionAffinity::new);")
    );
    let grpc = include_str!("../../../src/proxy/grpc_proxy.rs");
    assert!(grpc.contains("match shard_start(shard_count) {"));
}

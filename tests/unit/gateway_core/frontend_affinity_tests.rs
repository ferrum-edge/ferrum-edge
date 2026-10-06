//! gRPC backend-shard affinity for an HTTP/2 frontend connection (issue #5588):
//! the slot table, the per-connection open-stream bound, the shard start the
//! gRPC pool reads, and the upload/response terminal join. The pool-level
//! behaviour is covered against a real pool in
//! `tests/integration/http2_pool_tests.rs`.

use ferrum_edge::proxy::frontend_affinity::{
    AFFINITY_MAX_OPEN_STREAMS, FrontendConnectionAffinity, LazyConnectionAffinity, SLOTS,
    ShardStart, SlotTable, shard_start,
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
fn http1_requests_allocate_no_affinity_state() {
    let connection = LazyConnectionAffinity::new();
    assert!(connection.open_stream(hyper::Version::HTTP_11).is_none());
    assert!(connection.open_stream(hyper::Version::HTTP_10).is_none());
    let stream = connection.open_stream(hyper::Version::HTTP_2);
    assert!(stream.is_some());
}

/// Measure the concrete state machines, not just the pointer the service
/// sees. An async trampoline still stores its awaited child, so pointer size
/// alone cannot guard the routing and backend poll boundaries. Real H1/H2
/// listener requests also run on ordinary Tokio stacks in the lib suite.
#[test]
fn frontend_and_backend_future_state_stays_within_the_stack_budget() {
    let [boxed_frontend, frontend, handler, backend] =
        ferrum_edge::proxy::request_stack_test_support::future_sizes();
    assert_eq!(boxed_frontend, std::mem::size_of::<usize>());
    // These are coroutine-state ceilings, not measurements of poll frames.
    // Keep ample room on a default worker stack for debug-build temporaries,
    // the Hyper driver, task-local scopes, and the selected transport's poll.
    for (name, actual, ceiling) in [
        ("frontend", frontend, 8 * 1024),
        ("routing handler", handler, 128 * 1024),
        ("backend attempt", backend, 64 * 1024),
    ] {
        assert!(
            actual <= ceiling,
            "{name} future is {actual} bytes, exceeding its {ceiling}-byte state budget"
        );
    }
}

#[tokio::test]
async fn early_responses_keep_uploads_counted_until_both_halves_terminate() {
    use ferrum_edge::proxy::frontend_affinity::retain_backend_stream;

    let connection = FrontendConnectionAffinity::with_table(table());
    let mut uploads = Vec::new();
    for _ in 0..AFFINITY_MAX_OPEN_STREAMS {
        let (upload, response) = connection
            .open_stream()
            .run_request(async { retain_backend_stream().expect("backend owner") })
            .await;
        drop(response);
        uploads.push(upload);
    }
    assert_eq!(connection.open_streams(), AFFINITY_MAX_OPEN_STREAMS);
    let next = connection.open_stream();
    assert_eq!(next.run(async { shard_start(4) }).await, ShardStart::Spill);
    drop(next);

    for upload in uploads {
        let clone = upload.clone();
        drop(upload);
        drop(clone);
    }
    assert_eq!(connection.open_streams(), 0, "each join releases once");
}

#[tokio::test]
async fn every_retry_attempt_and_the_response_retain_one_count() {
    use ferrum_edge::proxy::frontend_affinity::retain_backend_stream;

    let connection = FrontendConnectionAffinity::with_table(table());
    let ((first, retry), response) = connection
        .open_stream()
        .run_request(async {
            (
                retain_backend_stream().expect("first backend owner"),
                retain_backend_stream().expect("retry backend owner"),
            )
        })
        .await;
    assert_eq!(connection.open_streams(), 1);
    drop(first);
    assert_eq!(connection.open_streams(), 1);
    drop(response);
    assert_eq!(connection.open_streams(), 1, "retry still owns queued DATA");
    drop(retry);
    assert_eq!(connection.open_streams(), 0, "all owners release once");

    let (upload, response) = connection
        .open_stream()
        .run_request(async { retain_backend_stream().expect("backend owner") })
        .await;
    drop(upload);
    assert_eq!(connection.open_streams(), 1, "response still owns the call");
    drop(response);
    assert_eq!(connection.open_streams(), 0);
}

#[tokio::test]
async fn handler_cancellation_joins_the_still_owned_upload() {
    use ferrum_edge::proxy::frontend_affinity::retain_backend_stream;

    let connection = FrontendConnectionAffinity::with_table(table());
    let stream = connection.open_stream();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let handler = tokio::spawn(async move {
        stream
            .run_request(async move {
                let upload = retain_backend_stream().expect("backend owner");
                assert!(tx.send(upload).is_ok());
                std::future::pending::<()>().await;
            })
            .await
    });
    let upload = rx.await.expect("registered upload");
    handler.abort();
    let _ = handler.await;
    assert_eq!(connection.open_streams(), 1);
    drop(upload);
    assert_eq!(connection.open_streams(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_upload_and_response_termination_releases_each_stream_once() {
    use ferrum_edge::proxy::frontend_affinity::retain_backend_stream;
    use std::sync::Arc;

    let connection = FrontendConnectionAffinity::with_table(table());
    let barrier = Arc::new(tokio::sync::Barrier::new(2 * AFFINITY_MAX_OPEN_STREAMS + 1));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..AFFINITY_MAX_OPEN_STREAMS {
        let (upload, response) = connection
            .open_stream()
            .run_request(async { retain_backend_stream().expect("backend owner") })
            .await;
        let upload_barrier = Arc::clone(&barrier);
        tasks.spawn(async move {
            upload_barrier.wait().await;
            let clone = upload.clone();
            drop(upload);
            drop(clone);
        });
        let response_barrier = Arc::clone(&barrier);
        tasks.spawn(async move {
            response_barrier.wait().await;
            drop(response);
        });
    }
    assert_eq!(connection.open_streams(), AFFINITY_MAX_OPEN_STREAMS);
    barrier.wait().await;
    while let Some(result) = tasks.join_next().await {
        result.expect("terminal task");
    }
    assert_eq!(connection.open_streams(), 0);
}

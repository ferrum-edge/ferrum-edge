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

#[tokio::test]
async fn early_responses_keep_uploads_counted_until_both_halves_terminate() {
    use ferrum_edge::proxy::frontend_affinity::retain_upload;

    let connection = FrontendConnectionAffinity::with_table(table());
    let mut uploads = Vec::new();
    for _ in 0..AFFINITY_MAX_OPEN_STREAMS {
        let (upload, response) = connection
            .open_stream()
            .run_request(async { retain_upload(None, None).expect("upload observer") })
            .await;
        drop(response);
        uploads.push(upload);
    }
    assert_eq!(connection.open_streams(), AFFINITY_MAX_OPEN_STREAMS);
    let next = connection.open_stream();
    assert_eq!(next.run(async { shard_start(4) }).await, ShardStart::Spill);
    drop(next);

    for upload in uploads {
        upload.on_upload_terminated();
        upload.on_upload_terminated();
    }
    assert_eq!(connection.open_streams(), 0, "each join releases once");
}

#[tokio::test]
async fn upload_completion_waits_for_the_response_and_preserves_the_previous_observer() {
    use ferrum_edge::proxy::frontend_affinity::retain_upload;
    use ferrum_edge::proxy::grpc_proxy::GrpcUploadTerminationObserver;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Observer(AtomicUsize);
    impl GrpcUploadTerminationObserver for Observer {
        fn on_upload_terminated(&self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let observed = Arc::new(Observer(AtomicUsize::new(0)));
    let observer: Arc<dyn GrpcUploadTerminationObserver> = observed.clone();
    let connection = FrontendConnectionAffinity::with_table(table());
    let latch = Arc::new(ferrum_edge::proxy::body::DirectH2BytesLatch::new());
    let (upload, response) = connection
        .open_stream()
        .run_request(async {
            retain_upload(Some(observer), Some(&latch)).expect("joined observer")
        })
        .await;
    let reused: Arc<dyn GrpcUploadTerminationObserver> = latch.clone();
    assert!(
        Arc::ptr_eq(&upload, &reused),
        "reuse the request-byte latch allocation"
    );
    upload.on_upload_terminated();
    upload.on_upload_terminated();
    assert_eq!(observed.0.load(Ordering::Relaxed), 1);
    assert_eq!(connection.open_streams(), 1);
    drop(response);
    assert_eq!(connection.open_streams(), 0);
    upload.on_upload_terminated();
    assert_eq!(connection.open_streams(), 0);
}

#[tokio::test]
async fn handler_cancellation_joins_the_still_owned_upload() {
    use ferrum_edge::proxy::frontend_affinity::retain_upload;

    let connection = FrontendConnectionAffinity::with_table(table());
    let stream = connection.open_stream();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let handler = tokio::spawn(async move {
        stream
            .run_request(async move {
                let upload = retain_upload(None, None).expect("upload observer");
                assert!(tx.send(upload).is_ok());
                std::future::pending::<()>().await;
            })
            .await
    });
    let upload = rx.await.expect("registered upload");
    handler.abort();
    let _ = handler.await;
    assert_eq!(connection.open_streams(), 1);
    upload.on_upload_terminated();
    assert_eq!(connection.open_streams(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_upload_and_response_termination_releases_each_stream_once() {
    use ferrum_edge::proxy::frontend_affinity::retain_upload;
    use std::sync::Arc;

    let connection = FrontendConnectionAffinity::with_table(table());
    let barrier = Arc::new(tokio::sync::Barrier::new(2 * AFFINITY_MAX_OPEN_STREAMS + 1));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..AFFINITY_MAX_OPEN_STREAMS {
        let (upload, response) = connection
            .open_stream()
            .run_request(async { retain_upload(None, None).expect("upload observer") })
            .await;
        let upload_barrier = Arc::clone(&barrier);
        tasks.spawn(async move {
            upload_barrier.wait().await;
            upload.on_upload_terminated();
            upload.on_upload_terminated();
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

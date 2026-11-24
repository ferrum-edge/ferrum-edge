//! gRPC backend-shard affinity for an HTTP/2 frontend connection (issue #5588):
//! the slot table, the per-connection open-stream bound, the shard start the
//! gRPC pool reads, and how long a stream counts. The pool-level behaviour is
//! covered against a real pool in `tests/integration/http2_pool_tests.rs`.

use std::sync::Arc;

use ferrum_edge::proxy::frontend_affinity::{
    AFFINITY_MAX_OPEN_STREAMS, FrontendConnectionAffinity, LazyConnectionAffinity, SLOTS,
    ShardStart, SlotTable, affinity_stream_limit, shard_start,
};

fn table() -> Arc<SlotTable> {
    Arc::new(SlotTable::new())
}

/// The affinity shard of a start, ignoring its open-stream count.
fn affinity_shard(start: ShardStart) -> Option<usize> {
    match start {
        ShardStart::Affinity { shard, .. } => Some(shard),
        ShardStart::Spill | ShardStart::Unscoped => None,
    }
}

#[test]
fn without_a_frontend_stream_the_start_is_unscoped() {
    assert_eq!(shard_start(4), ShardStart::Unscoped);
}

#[test]
fn a_connection_takes_its_slot_on_its_first_stream_only() {
    let table = table();
    let connection = FrontendConnectionAffinity::with_table(&table);
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
    let _first = FrontendConnectionAffinity::with_table(&table).open_stream();
    let connection = FrontendConnectionAffinity::with_table(&table);
    let stream = connection.open_stream();
    assert_eq!(connection.slot(), Some(1));
    assert_eq!(
        stream.run(async { shard_start(4) }).await,
        ShardStart::Affinity {
            shard: 1,
            open_streams: 1,
        }
    );
    assert_eq!(
        affinity_shard(stream.run(async { shard_start(1) }).await),
        Some(0)
    );
    assert_eq!(
        affinity_shard(stream.run(async { shard_start(0) }).await),
        Some(0)
    );

    // Up to the bound (this stream included) the connection keeps its shard.
    let mut more: Vec<_> = (1..AFFINITY_MAX_OPEN_STREAMS)
        .map(|_| connection.open_stream())
        .collect();
    assert_eq!(connection.open_streams(), AFFINITY_MAX_OPEN_STREAMS);
    assert_eq!(
        stream.run(async { shard_start(4) }).await,
        ShardStart::Affinity {
            shard: 1,
            open_streams: AFFINITY_MAX_OPEN_STREAMS,
        }
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
        affinity_shard(stream.run(async { shard_start(4) }).await),
        Some(1)
    );
    drop(more);
    assert_eq!(connection.open_streams(), 1);
}

#[tokio::test]
async fn a_pool_wider_than_the_slot_table_spills() {
    let connection = FrontendConnectionAffinity::with_table(&table());
    let stream = connection.open_stream();
    assert_eq!(
        affinity_shard(stream.run(async { shard_start(SLOTS) }).await),
        Some(0)
    );
    assert_eq!(
        stream.run(async { shard_start(SLOTS + 1) }).await,
        ShardStart::Spill
    );
}

#[tokio::test]
async fn a_cancelled_request_closes_its_stream() {
    let connection = FrontendConnectionAffinity::with_table(&table());
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
    let table = table();
    let connection = LazyConnectionAffinity::new(Arc::clone(&table));
    assert!(connection.open_stream(hyper::Version::HTTP_11).is_none());
    assert!(connection.open_stream(hyper::Version::HTTP_10).is_none());
    assert_eq!(table.live(0), 0, "HTTP/1.x takes no slot");
    let stream = connection.open_stream(hyper::Version::HTTP_2);
    assert!(stream.is_some());
    assert_eq!(table.live(0), 1);
}

#[test]
fn separate_slot_tables_do_not_share_balance_state() {
    // Each gateway's gRPC pool owns its table, so in-process gateways (and
    // tests) never see each other's live connections.
    let first = table();
    let second = table();
    let held = LazyConnectionAffinity::new(Arc::clone(&first));
    let _held = held.open_stream(hyper::Version::HTTP_2);
    assert_eq!(first.live(0), 1);
    let other = LazyConnectionAffinity::new(Arc::clone(&second));
    let _other = other.open_stream(hyper::Version::HTTP_2);
    assert_eq!(second.live(0), 1, "the second table starts at slot 0");
    assert_eq!(first.live(1), 0);
}

#[test]
fn the_affinity_bound_follows_the_backend_stream_limit() {
    let max = AFFINITY_MAX_OPEN_STREAMS;
    assert_eq!(affinity_stream_limit(usize::MAX), max);
    assert_eq!(affinity_stream_limit(100), max);
    assert_eq!(affinity_stream_limit(max), max);
    assert_eq!(affinity_stream_limit(4), 4);
    assert_eq!(affinity_stream_limit(1), 1);
    assert_eq!(
        affinity_stream_limit(0),
        0,
        "a backend allowing none pins none"
    );
}

#[tokio::test]
async fn a_stream_counts_until_its_response_side_guard_drops() {
    // The frontend hands the guard to the response body, so the stream counts
    // until the response terminates, and not past it.
    let connection = FrontendConnectionAffinity::with_table(&table());
    let (start, response) = connection
        .open_stream()
        .run_request(async { shard_start(4) })
        .await;
    assert_eq!(affinity_shard(start), Some(0));
    assert_eq!(connection.open_streams(), 1, "the response still owns it");
    drop(response);
    assert_eq!(connection.open_streams(), 0);
}

#[tokio::test]
async fn a_cancelled_handler_closes_its_stream() {
    let connection = FrontendConnectionAffinity::with_table(&table());
    let stream = connection.open_stream();
    let handler = tokio::spawn(async move {
        stream.run_request(std::future::pending::<()>()).await;
    });
    tokio::task::yield_now().await;
    assert_eq!(connection.open_streams(), 1);
    handler.abort();
    let _ = handler.await;
    assert_eq!(connection.open_streams(), 0);
}

/// Measure the concrete state machines, not just the pointer the service
/// sees. An async trampoline still stores its awaited child, so pointer size
/// alone cannot guard the routing and backend poll boundaries. Real H1/H2
/// listener requests also run on ordinary Tokio stacks in the lib suite.
#[test]
fn frontend_and_backend_future_state_stays_within_the_stack_budget() {
    let [frontend_boundary, frontend, handler, backend] =
        ferrum_edge::proxy::request_stack_test_support::future_sizes();
    // These are coroutine-state ceilings, not measurements of poll frames.
    // Keep ample room on a default worker stack for debug-build temporaries,
    // the Hyper driver, task-local scopes, and the selected transport's poll.
    for (name, actual, ceiling) in [
        ("frontend boundary", frontend_boundary, 8 * 1024),
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

/// The listener's service future stores the frontend future, and the affinity
/// scopes pass it along by value. It must stay a pointer: stored inline, its
/// state was copied by each of those layers, and the service future that
/// carried the copies was itself copied twice more per request, when hyper and
/// the runtime spawn the HTTP/2 stream.
#[test]
fn the_frontend_boundary_future_is_a_pointer_to_the_frontend_state() {
    let [frontend_boundary, frontend, ..] =
        ferrum_edge::proxy::request_stack_test_support::future_sizes();
    assert_eq!(
        frontend_boundary,
        std::mem::size_of::<usize>(),
        "the frontend future the listeners store must be boxed, not {frontend_boundary} bytes inline"
    );
    assert!(
        frontend > frontend_boundary,
        "the concrete frontend state ({frontend} bytes) is what the pointer keeps out of the service future"
    );
}

/// A bounded child the handler keeps inline is written straight into its slot
/// of the handler's state. A factory that returns the child by value makes the
/// caller copy the whole state machine out of a stack temporary: 18 KiB per
/// request for the backend attempt.
#[test]
fn bounded_inline_children_are_constructed_in_their_final_slot() {
    // Code only: a comment that names one of the counted calls must not
    // change a count.
    fn squeezed(source: &str) -> String {
        source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .flat_map(str::split_whitespace)
            .collect::<Vec<_>>()
            .join(" ")
    }
    fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
        let (_, after_start) = source
            .split_once(start)
            .unwrap_or_else(|| panic!("`{start}` must exist"));
        let (region, _) = after_start
            .split_once(end)
            .unwrap_or_else(|| panic!("`{start}` must be bounded by `{end}`"));
        region
    }

    let src = include_str!("../../../src/proxy/mod.rs");
    assert!(
        !src.contains("fn construct_proxy_future<"),
        "an inline child must not be returned by value from an out-of-line factory"
    );
    // The same shape under any other name: a factory that takes a constructor
    // and returns what it built by value.
    let by_value_factory = "impl FnOnce() -> F) -> F {";
    assert!(
        !src.contains(by_value_factory),
        "no factory in the HTTP/1.1 and HTTP/2 proxy path may return its child by value"
    );
    // The HTTP/3 backend client keeps the one remaining by-value factory: its
    // exchange futures have not been profiled, so it is named here instead of
    // converted. Converting it, or adding another, has to update this.
    let h3_client = include_str!("../../../src/http3/client.rs");
    assert_eq!(
        h3_client.matches(by_value_factory).count(),
        1,
        "construct_h3_future is the only known by-value child factory left"
    );
    assert!(
        h3_client.contains(
            "fn construct_h3_future<F: std::future::Future>(construct: impl FnOnce() -> F) -> F {"
        ),
        "the remaining by-value factory is construct_h3_future"
    );
    assert!(
        src.contains("#[inline(never)]\nfn construct_proxy_future_in<"),
        "construct_proxy_future_in must stay an out-of-line factory"
    );
    let factory = between(src, "fn construct_proxy_future_in<", "\n}\n");
    assert!(
        factory.contains("slot.set(Some(construct()));"),
        "the factory must write the child through the caller's slot"
    );

    let handler = squeezed(between(
        src,
        "\nasync fn handle_proxy_request_inner(",
        "\nasync fn proxy_to_backend(",
    ));
    let attempt_in_slot = "construct_proxy_future_in(attempt_slot.as_mut(), || { proxy_to_backend(";
    assert_eq!(
        handler.matches(attempt_in_slot).count(),
        2,
        "the retry-configured and the single-attempt dispatch each build their attempt in a slot"
    );
    assert_eq!(
        handler.matches("proxy_to_backend(").count(),
        2,
        "the handler awaits exactly those two backend attempts inline; another call site needs its own slot"
    );

    let dispatch = squeezed(between(
        src,
        "\nasync fn proxy_to_backend(",
        "\nasync fn proxy_to_backend_direct_h1(",
    ));
    for child in ["proxy_to_backend_http2(", "proxy_to_backend_direct_h1("] {
        let child_in_slot =
            format!("construct_proxy_future_in(dispatch_slot.as_mut(), || {{ {child}");
        assert_eq!(
            dispatch.matches(child_in_slot.as_str()).count(),
            1,
            "{child} must be built in its slot of the backend attempt"
        );
        assert_eq!(
            dispatch.matches(child).count(),
            1,
            "{child} must not also be awaited by value in the backend attempt"
        );
    }

    assert!(
        src.contains("#[inline(never)]\nfn construct_frontend_proxy_request("),
        "construct_frontend_proxy_request must stay an out-of-line factory"
    );
    let frontend = between(src, "fn construct_frontend_proxy_request(", "\n}\n");
    assert!(
        frontend.contains("Box::pin(handle_proxy_request_on_frontend_port("),
        "the frontend future must be built directly in its box"
    );
}

/// A final-request-body hook context is a whole `RequestContext`, about 3 KiB.
/// The handler keeps several of them across awaits and moves them between
/// slots with `Option::take`. In the release build that move was a copy of
/// the full value on every request, including when the slot is empty: the
/// normal case, with no body-hook plugin. Boxed, an empty slot is a null
/// pointer and a move is eight bytes whatever the optimizer does.
#[test]
fn body_hook_contexts_are_boxed_in_the_request_handler() {
    let src = include_str!("../../../src/proxy/mod.rs");
    let (_, after_start) = src
        .split_once("\nasync fn handle_proxy_request_inner(")
        .expect("handle_proxy_request_inner must exist");
    let (handler, _) = after_start
        .split_once("\nasync fn proxy_to_backend(")
        .expect("handle_proxy_request_inner must be bounded by proxy_to_backend");
    assert_eq!(
        handler
            .matches(".then(|| Box::new(ctx.clone_for_final_request_body_hooks()))")
            .count(),
        3,
        "the handler's three body-hook contexts are created boxed"
    );
    assert_eq!(
        handler
            .matches("clone_for_final_request_body_hooks()")
            .count(),
        3,
        "a body-hook context the handler creates must not be stored inline"
    );
    assert!(
        std::mem::size_of::<Option<Box<ferrum_edge::plugins::RequestContext>>>()
            < std::mem::size_of::<ferrum_edge::plugins::RequestContext>() / 100,
        "an inline slot costs a whole RequestContext; a boxed one a pointer"
    );
}

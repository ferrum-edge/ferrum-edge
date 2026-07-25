//! Criterion p99 fixture for the AI semantic-cache request hot path at the
//! 10k/100k entry cardinalities required by issue #3075.
//!
//! The fixture intentionally does not start lifecycle maintenance workers.
//! Each measured request is an exact local miss, so the timed path covers
//! request classification/keying, the DashMap lookup, and the cheap cleanup
//! interval signal without allowing an O(N) sweep or oldest-entry selection to
//! run on the request future.

use std::collections::HashMap;
use std::future::Future;
use std::hint::black_box;
use std::task::{Context, Poll, Waker};

use criterion::{Criterion, criterion_group, criterion_main};
use ferrum_edge::plugins::ai_semantic_cache::AiSemanticCache;
use ferrum_edge::plugins::{Plugin, PluginHttpClient, PluginResult, RequestContext};
use serde_json::json;

const CACHE_CARDINALITIES: [usize; 2] = [10_000, 100_000];
const RESPONSE_BODY: &[u8] = br#"{"ok":true}"#;

/// Poll a hook that is required to remain immediately ready in local,
/// exact-only mode. A newly introduced await fails the benchmark loudly rather
/// than silently measuring an executor that is unrelated to the hot path.
fn poll_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = Box::pin(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("exact-only local semantic-cache hook unexpectedly yielded"),
    }
}

fn request_context(body: String) -> (RequestContext, HashMap<String, String>) {
    let mut context = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    context.metadata.insert("request_body".to_string(), body);
    let headers = HashMap::from([(
        "content-type".to_string(),
        "application/json".to_string(),
    )]);
    (context, headers)
}

fn populated_cache(entry_count: usize) -> AiSemanticCache {
    let plugin = AiSemanticCache::new(
        &json!({
            "ttl_seconds": 3600,
            "max_entries": entry_count,
            "max_entry_size_bytes": 1024,
            "max_total_size_bytes": 1_073_741_824_u64,
        }),
        PluginHttpClient::default(),
    )
    .expect("benchmark config must be valid");
    let response_headers = HashMap::from([(
        "content-type".to_string(),
        "application/json".to_string(),
    )]);

    for index in 0..entry_count {
        let body = format!(
            r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"seed {index}"}}]}}"#
        );
        let (mut context, mut headers) = request_context(body);
        assert!(matches!(
            poll_ready(plugin.before_proxy(&mut context, &mut headers)),
            PluginResult::Continue
        ));
        assert!(matches!(
            poll_ready(plugin.on_final_response_body(
                &mut context,
                200,
                &response_headers,
                RESPONSE_BODY,
            )),
            PluginResult::Continue
        ));
    }

    plugin
}

fn bench_ai_semantic_cache_cleanup_hot_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("ai_semantic_cache_cleanup_hot_path");
    for entry_count in CACHE_CARDINALITIES {
        let plugin = populated_cache(entry_count);
        let miss_body =
            r#"{"model":"gpt-4o","messages":[{"role":"user","content":"benchmark miss"}]}"#;

        group.bench_function(format!("{entry_count}_entries"), |b| {
            b.iter(|| {
                let (mut context, mut headers) = request_context(miss_body.to_string());
                let result = poll_ready(plugin.before_proxy(&mut context, &mut headers));
                assert!(matches!(black_box(result), PluginResult::Continue));
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_ai_semantic_cache_cleanup_hot_path);
criterion_main!(benches);

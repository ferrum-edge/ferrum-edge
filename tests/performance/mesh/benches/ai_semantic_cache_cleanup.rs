//! Criterion fixture for the AI semantic-cache request hot path at the
//! 10k/100k retained-entry cardinalities required by issue #3075.
//!
//! The fixture drives the plugin through the hooks production uses: lookup and
//! miss-key staging run in `on_final_request_body_with_context`, and retention
//! runs in `on_final_response_body`. The inherited `before_proxy` default does
//! no cache work, so neither seeding nor measurement may go through it.
//!
//! The fixture intentionally does not start lifecycle maintenance workers.
//! Each measured request is an exact local miss, so the timed path covers
//! request classification/keying, the DashMap lookup, and the cheap cleanup
//! interval signal without allowing an O(N) sweep or oldest-entry selection to
//! run on the request future.
//!
//! Before any timing the fixture proves it measures that workload (issue
//! #6291): every seed must stage a miss key and replay as a retained HIT, and
//! the measured body must be an exact local MISS that stages its key. Negative
//! fixtures check that a skipped seed and a `before_proxy` substitution fail
//! those checks. When `AI_SEMANTIC_CACHE_FIXTURE_EVIDENCE` names a file, the
//! verified facts are written there for the CI evaluator, which refuses
//! Criterion samples without them.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::hint::black_box;
use std::task::{Context, Poll, Waker};

use criterion::{Criterion, criterion_group, criterion_main};
use ferrum_edge::plugins::ai_semantic_cache::AiSemanticCache;
use ferrum_edge::plugins::{Plugin, PluginHttpClient, PluginResult, RequestContext};
use serde_json::json;

const CACHE_CARDINALITIES: [usize; 2] = [10_000, 100_000];
const RESPONSE_BODY: &[u8] = br#"{"ok":true}"#;
const MEASURED_MISS_BODY: &str =
    r#"{"model":"gpt-4o","messages":[{"role":"user","content":"benchmark miss"}]}"#;
const NEGATIVE_FIXTURE_ENTRIES: usize = 16;
const BENCHMARK_GROUP: &str = "ai_semantic_cache_cleanup_hot_path";
const EVIDENCE_PATH_ENV: &str = "AI_SEMANTIC_CACHE_FIXTURE_EVIDENCE";
const REQUEST_HOOK: &str = "on_final_request_body_with_context";
const STORE_HOOK: &str = "on_final_response_body";
const MEASURED_PATH: &str = "exact_local_miss";

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

/// How a fixture request reaches the plugin. Only `FinalRequestBody` is the
/// production lookup hook; `InheritedBeforeProxy` exists so the negative
/// fixtures can prove the checks reject the old default-hook shape.
#[derive(Clone, Copy)]
enum RequestHook {
    FinalRequestBody,
    InheritedBeforeProxy,
}

fn seed_body(index: usize) -> String {
    format!(r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"seed {index}"}}]}}"#)
}

fn request_context() -> RequestContext {
    let mut context = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    // Stand in for the protocol entry path, which copies the static
    // response-presentation digest from the plugin-cache view; without one the
    // cache treats the response policy as unprovable and bypasses.
    ferrum_edge::_test_support::set_response_presentation_policy_digest_for_test(
        &mut context,
        Some([0x5c; 32]),
    );
    context
}

/// Finalized backend-visible request headers, including the framed length the
/// proxy publishes for a buffered body.
fn request_headers(body: &str) -> HashMap<String, String> {
    HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("content-length".to_string(), body.len().to_string()),
    ])
}

fn response_headers() -> HashMap<String, String> {
    HashMap::from([("content-type".to_string(), "application/json".to_string())])
}

fn new_plugin(entry_count: usize) -> AiSemanticCache {
    AiSemanticCache::new(
        &json!({
            "ttl_seconds": 3600,
            "max_entries": entry_count,
            "max_entry_size_bytes": 1024,
            "max_total_size_bytes": 1_073_741_824_u64,
        }),
        PluginHttpClient::default(),
    )
    .expect("benchmark config must be valid")
}

fn run_request_hook(
    plugin: &AiSemanticCache,
    hook: RequestHook,
    body: &str,
) -> (RequestContext, PluginResult) {
    let mut context = request_context();
    let mut headers = request_headers(body);
    let result = match hook {
        RequestHook::FinalRequestBody => poll_ready(plugin.on_final_request_body_with_context(
            &mut context,
            &headers,
            body.as_bytes(),
        )),
        RequestHook::InheritedBeforeProxy => {
            poll_ready(plugin.before_proxy(&mut context, &mut headers))
        }
    };
    (context, result)
}

/// The cache status this instance publishes for the request, read the way a
/// client sees it: through the `x-ai-cache-status` response header.
fn published_cache_status(
    plugin: &AiSemanticCache,
    context: &mut RequestContext,
) -> Option<String> {
    let mut headers = HashMap::new();
    let _ = poll_ready(plugin.after_proxy(context, 200, &mut headers));
    headers.remove("x-ai-cache-status")
}

/// A lookup counts as an exact local miss only if it continued, staged this
/// instance's miss key for the response hook, and published `MISS`.
fn check_staged_miss(
    plugin: &AiSemanticCache,
    context: &mut RequestContext,
    result: &PluginResult,
) -> Result<(), String> {
    if !matches!(result, PluginResult::Continue) {
        return Err("lookup did not continue as a cache miss".to_string());
    }
    if !plugin.should_buffer_response_body(context) {
        return Err("lookup staged no miss key, so no cache keying or lookup ran".to_string());
    }
    match published_cache_status(plugin, context).as_deref() {
        Some("MISS") => Ok(()),
        other => Err(format!(
            "lookup published cache status {other:?}, expected MISS"
        )),
    }
}

fn seed_entry(plugin: &AiSemanticCache, index: usize, hook: RequestHook) -> Result<(), String> {
    let body = seed_body(index);
    let (mut context, result) = run_request_hook(plugin, hook, &body);
    check_staged_miss(plugin, &mut context, &result)
        .map_err(|error| format!("seed {index}: {error}"))?;
    let stored = poll_ready(plugin.on_final_response_body(
        &mut context,
        200,
        &response_headers(),
        RESPONSE_BODY,
    ));
    if !matches!(stored, PluginResult::Continue) {
        return Err(format!("seed {index}: response hook did not continue"));
    }
    if plugin.should_buffer_response_body(&context) {
        return Err(format!(
            "seed {index}: response hook left the miss key staged, so it refused retention"
        ));
    }
    Ok(())
}

/// Replay every seed through the production lookup and require a retained HIT
/// carrying the seeded response. `entry_count` distinct keys all hitting proves
/// the cache retains at least that many entries before timing starts.
fn verify_retained(plugin: &AiSemanticCache, entry_count: usize) -> Result<usize, String> {
    let mut hits = 0usize;
    for index in 0..entry_count {
        let body = seed_body(index);
        let (_, result) = run_request_hook(plugin, RequestHook::FinalRequestBody, &body);
        match result {
            PluginResult::RejectBinary {
                status_code: 200,
                body,
                headers,
            } if &body[..] == RESPONSE_BODY
                && headers.get("x-ai-cache-status").map(String::as_str) == Some("HIT") =>
            {
                hits += 1;
            }
            _ => {
                return Err(format!(
                    "seed {index} was not retained: replay did not return the seeded HIT \
                     ({hits} of {entry_count} seeds verified)"
                ));
            }
        }
    }
    Ok(hits)
}

/// The measured operation: one exact local miss through the production hook.
fn measured_lookup(plugin: &AiSemanticCache, hook: RequestHook) -> (RequestContext, PluginResult) {
    run_request_hook(plugin, hook, MEASURED_MISS_BODY)
}

fn check_measured_path(plugin: &AiSemanticCache, hook: RequestHook) -> Result<(), String> {
    let (mut context, result) = measured_lookup(plugin, hook);
    check_staged_miss(plugin, &mut context, &result)
        .map_err(|error| format!("measured request: {error}"))
}

/// Build a fixture and verify it. `seed_hook: None` skips seeding entirely.
fn build_fixture(
    entry_count: usize,
    seed_hook: Option<RequestHook>,
) -> Result<(AiSemanticCache, usize), String> {
    let plugin = new_plugin(entry_count);
    if let Some(hook) = seed_hook {
        for index in 0..entry_count {
            seed_entry(&plugin, index, hook)?;
        }
    }
    let retained = verify_retained(&plugin, entry_count)?;
    check_measured_path(&plugin, RequestHook::FinalRequestBody)?;
    Ok((plugin, retained))
}

/// Prove the fixture checks reject the defects they guard against, so a
/// skipped seed or a default-hook substitution cannot produce accepted timing.
fn run_negative_fixtures() -> BTreeMap<&'static str, bool> {
    let skipped_seed = build_fixture(NEGATIVE_FIXTURE_ENTRIES, None).is_err();
    assert!(
        skipped_seed,
        "negative fixture: an unseeded cache passed fixture verification"
    );

    let default_hook_seed = build_fixture(
        NEGATIVE_FIXTURE_ENTRIES,
        Some(RequestHook::InheritedBeforeProxy),
    )
    .is_err();
    assert!(
        default_hook_seed,
        "negative fixture: seeding through the inherited before_proxy passed fixture verification"
    );

    let (plugin, _) = build_fixture(
        NEGATIVE_FIXTURE_ENTRIES,
        Some(RequestHook::FinalRequestBody),
    )
    .unwrap_or_else(|error| panic!("control fixture failed verification: {error}"));
    let default_hook_measurement =
        check_measured_path(&plugin, RequestHook::InheritedBeforeProxy).is_err();
    assert!(
        default_hook_measurement,
        "negative fixture: measuring through the inherited before_proxy passed the miss check"
    );

    BTreeMap::from([
        ("skipped_seed_rejected", skipped_seed),
        ("default_hook_seed_rejected", default_hook_seed),
        (
            "default_hook_measurement_rejected",
            default_hook_measurement,
        ),
    ])
}

fn evidence_path() -> Option<std::path::PathBuf> {
    std::env::var_os(EVIDENCE_PATH_ENV)
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
}

fn bench_ai_semantic_cache_cleanup_hot_path(c: &mut Criterion) {
    // A failed run must never leave a previous run's evidence behind.
    let evidence_path = evidence_path();
    if let Some(path) = &evidence_path {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("cannot clear stale fixture evidence: {error}"),
        }
    }

    let negative_fixtures = run_negative_fixtures();
    let mut fixtures = BTreeMap::new();

    let mut group = c.benchmark_group(BENCHMARK_GROUP);
    for entry_count in CACHE_CARDINALITIES {
        let (plugin, retained) = build_fixture(entry_count, Some(RequestHook::FinalRequestBody))
            .unwrap_or_else(|error| {
                panic!("{entry_count}-entry fixture failed verification before timing: {error}")
            });

        group.bench_function(format!("{entry_count}_entries"), |b| {
            b.iter(|| {
                let (context, result) = measured_lookup(&plugin, RequestHook::FinalRequestBody);
                black_box(&context);
                assert!(matches!(black_box(result), PluginResult::Continue));
            });
        });

        // Timing must not have changed what was measured.
        check_measured_path(&plugin, RequestHook::FinalRequestBody).unwrap_or_else(|error| {
            panic!("{entry_count}-entry fixture changed during timing: {error}")
        });

        fixtures.insert(
            entry_count.to_string(),
            json!({
                "seeded": entry_count,
                "retained_hits": retained,
                "measured_path": MEASURED_PATH,
            }),
        );
    }
    group.finish();

    if let Some(path) = evidence_path {
        let evidence = json!({
            "schema": 1,
            "group": BENCHMARK_GROUP,
            "request_hook": REQUEST_HOOK,
            "store_hook": STORE_HOOK,
            "maintenance_workers_started": false,
            "fixtures": fixtures,
            "negative_fixtures": negative_fixtures,
        });
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent).unwrap_or_else(|error| {
                panic!("cannot create fixture evidence directory: {error}")
            });
        }
        let mut contents = serde_json::to_string_pretty(&evidence)
            .unwrap_or_else(|error| panic!("cannot serialize fixture evidence: {error}"));
        contents.push('\n');
        std::fs::write(&path, contents)
            .unwrap_or_else(|error| panic!("cannot write fixture evidence: {error}"));
    }
}

criterion_group!(benches, bench_ai_semantic_cache_cleanup_hot_path);
criterion_main!(benches);

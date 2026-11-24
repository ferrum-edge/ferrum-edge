//! Plugin-cache request-view microbenchmark (issue #7207).
//!
//! Every HTTP-family request resolves one `PluginCacheRequestView` through
//! `PluginCache::request_view` before any plugin runs: the published-generation
//! load, the namespaced runtime-key composition, the per-(proxy, protocol)
//! entry lookup and the per-proxy flag lookups. The measured operation is that
//! call plus dropping the view, which is exactly what a request pays to obtain
//! its plugin chain.
//!
//! The reference-count writes the view performs land on cache lines shared by
//! every worker serving the same route, so the fixture runs the same workload on
//! one thread and on eight barrier-synchronized threads that all resolve the
//! same proxy (the RR/WRR contention-bench harness shape). Two fixtures are
//! measured: a proxy with its own five-plugin chain, and a proxy with no scoped
//! plugins, which resolves the global chain.
//!
//! Only public API is used, so hosted CI can compile this one file against an
//! older revision and compare the two binaries on one runner. See
//! `.github/scripts/run_plugin_request_view_comparison.sh`.

use std::hint::black_box;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use ferrum_edge::PluginCache;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::plugins::{Plugin, ProxyProtocol};
use serde_json::json;

const THREAD_COUNTS: [usize; 2] = [1, 8];
const ITERATIONS_PER_THREAD: usize = 50_000;
const NAMESPACE: &str = "ferrum";
const SCOPED_PROXY: &str = "scoped";
const GLOBAL_PROXY: &str = "global-only";
/// The configured plugins each fixture's HTTP chain must contain. The cache
/// may add its own internal instances (a CORS finalizer, for example), so the
/// check is containment, not an exact count.
const SCOPED_CHAIN: [&str; 5] = [
    "cors",
    "key_auth",
    "access_control",
    "rate_limiting",
    "request_transformer",
];
const GLOBAL_CHAIN: [&str; 1] = ["cors"];

/// A representative routed API: key authentication, an ACL, a local rate
/// limit and a header transform on the route, plus a global CORS policy.
fn gateway_config() -> GatewayConfig {
    let proxy = |id: &str, listen_path: &str, plugins: &[&str]| {
        json!({
            "id": id,
            "name": id,
            "listen_path": listen_path,
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": 3001,
            "strip_listen_path": false,
            "preserve_host_header": false,
            "auth_mode": "single",
            "plugins": plugins
                .iter()
                .map(|plugin| json!({ "plugin_config_id": plugin }))
                .collect::<Vec<_>>(),
        })
    };
    let scoped = |id: &str, name: &str, config: serde_json::Value| {
        json!({
            "id": id,
            "plugin_name": name,
            "config": config,
            "scope": "proxy",
            "proxy_id": SCOPED_PROXY,
            "enabled": true,
        })
    };
    serde_json::from_value(json!({
        "version": "1",
        "proxies": [
            proxy(SCOPED_PROXY, "/scoped", &["auth", "acl", "limit", "transform"]),
            proxy(GLOBAL_PROXY, "/global", &[]),
        ],
        "consumers": [],
        "plugin_configs": [
            {
                "id": "cors",
                "plugin_name": "cors",
                "config": { "allowed_origins": ["*"] },
                "scope": "global",
                "enabled": true,
            },
            scoped("auth", "key_auth", json!({})),
            scoped("acl", "access_control", json!({ "allowed_consumers": ["alice"] })),
            scoped(
                "limit",
                "rate_limiting",
                json!({ "limits": [{ "scope": "default", "window_seconds": 60, "max_requests": 100 }] }),
            ),
            scoped(
                "transform",
                "request_transformer",
                json!({ "rules": [{ "operation": "add", "target": "header", "key": "x-bench", "value": "1" }] }),
            ),
        ],
    }))
    .expect("benchmark gateway config must deserialize")
}

/// Refuse to time anything unless each fixture resolves the chain it claims to.
fn verify_fixture(cache: &PluginCache) {
    let chain_contains = |proxy_id: &str, expected: &[&str], auth_len: usize| {
        let view = cache.request_view(NAMESPACE, proxy_id, ProxyProtocol::Http);
        let plugins = view.plugins();
        for name in expected {
            assert!(
                plugins.iter().any(|plugin| plugin.name() == *name),
                "{proxy_id} chain must contain {name}"
            );
        }
        assert_eq!(view.auth_plugins().len(), auth_len, "{proxy_id} auth phase");
    };
    chain_contains(SCOPED_PROXY, &SCOPED_CHAIN, 1);
    chain_contains(GLOBAL_PROXY, &GLOBAL_CHAIN, 0);
    let scoped = cache.request_view(NAMESPACE, SCOPED_PROXY, ProxyProtocol::Http);
    let global = cache.request_view(NAMESPACE, GLOBAL_PROXY, ProxyProtocol::Http);
    assert!(
        !Arc::ptr_eq(&scoped.plugins(), &global.plugins()),
        "the two fixtures must resolve different entries"
    );
}

fn resolve_views(cache: &PluginCache, proxy_id: &str, iterations: usize) {
    for _ in 0..iterations {
        let view = cache.request_view(NAMESPACE, black_box(proxy_id), ProxyProtocol::Http);
        black_box(&view);
        drop(view);
    }
}

/// One measured batch: `ITERATIONS_PER_THREAD` view resolutions on the calling
/// thread.
type Workload = Arc<dyn Fn() + Send + Sync>;

fn measure_serial_batches(work: &Workload, batches: u64) -> Duration {
    let mut total = Duration::ZERO;
    for _ in 0..batches {
        let started = Instant::now();
        work();
        total += started.elapsed();
    }
    total
}

fn measure_parallel_batches(work: &Workload, threads: usize, batches: u64) -> Duration {
    let start_line = Arc::new(Barrier::new(threads + 1));
    let end_line = Arc::new(Barrier::new(threads + 1));
    let stop = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::with_capacity(threads);
    for _ in 0..threads {
        let work = Arc::clone(work);
        let start_line = Arc::clone(&start_line);
        let end_line = Arc::clone(&end_line);
        let stop = Arc::clone(&stop);
        handles.push(thread::spawn(move || {
            loop {
                start_line.wait();
                if stop.load(Ordering::Acquire) {
                    end_line.wait();
                    break;
                }
                work();
                end_line.wait();
            }
        }));
    }

    // Untimed prime so the first measured sample is not cold-scheduled.
    start_line.wait();
    end_line.wait();

    let mut total = Duration::ZERO;
    for _ in 0..batches {
        // Start before release so no worker can execute outside the timer.
        let started = Instant::now();
        start_line.wait();
        end_line.wait();
        total += started.elapsed();
    }

    stop.store(true, Ordering::Release);
    start_line.wait();
    end_line.wait();
    for handle in handles {
        handle.join().expect("bench worker");
    }
    total
}

fn bench_workload(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    prefix: &str,
    work: Workload,
) {
    for threads in THREAD_COUNTS {
        group.throughput(Throughput::Elements(
            (ITERATIONS_PER_THREAD * threads) as u64,
        ));
        let work = Arc::clone(&work);
        group.bench_function(format!("{prefix}_{threads}_threads"), |b| {
            b.iter_custom(|iters| {
                if threads == 1 {
                    measure_serial_batches(&work, iters)
                } else {
                    measure_parallel_batches(&work, threads, iters)
                }
            });
        });
    }
}

fn bench_plugin_request_view(c: &mut Criterion) {
    // Plugin construction may stage background work; keep a runtime entered
    // for the cache's whole lifetime. The measured loop itself never awaits.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("benchmark runtime");
    let _runtime = runtime.enter();
    let cache =
        Arc::new(PluginCache::new(&gateway_config()).expect("benchmark plugin cache must build"));
    verify_fixture(&cache);

    let mut group = c.benchmark_group("plugin_request_view");
    for proxy_id in [SCOPED_PROXY, GLOBAL_PROXY] {
        resolve_views(&cache, proxy_id, 2_048);
        let work: Workload = {
            let cache = Arc::clone(&cache);
            Arc::new(move || resolve_views(&cache, proxy_id, ITERATIONS_PER_THREAD))
        };
        bench_workload(&mut group, &proxy_id.replace('-', "_"), work);
    }
    group.finish();
}

fn criterion_config() -> Criterion {
    let criterion = Criterion::default();
    match std::env::var_os("FERRUM_REQUEST_VIEW_CRITERION_ROOT") {
        Some(path) => criterion.output_directory(Path::new(&path)),
        None => criterion,
    }
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets = bench_plugin_request_view
}
criterion_main!(benches);

//! Concurrent RoundRobin selection microbenchmark for hosted CI (#2947).
//!
//! Guards the sharded / CachePadded RR selection counters against a regression
//! back to a single shared `AtomicU64` (or a mutex) on the selection path.
//! Fixture contract matches the WRR contention bench pattern (long-lived
//! barrier-synchronized workers; Criterion custom-iteration wall time covers
//! `threads * ITERATIONS_PER_THREAD` operations).
//!
//! # Same-workload reference (issue #4708)
//!
//! Hosted CI compiles the same harness against the candidate and an immutable
//! baseline revision, then interleaves three measurements of each binary on
//! one runner. The full selection path is compared at each thread count. The
//! bare shared-counter fixture remains available for exploration, but no
//! proportional relationship between its cost and selection cost is assumed.
//! See `.github/scripts/run_rr_selection_comparison.py`.

use std::collections::HashMap;
use std::hint::black_box;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use ferrum_edge::config::types::{LoadBalancerAlgorithm, UpstreamTarget};
use ferrum_edge::load_balancer::LoadBalancer;

/// Issue #2947 regression fixture: small healthy set where an unsharded counter
/// is the throughput ceiling.
const TARGET_COUNT: usize = 2;
const THREAD_COUNTS: [usize; 2] = [1, 8];
const ITERATIONS_PER_THREAD: usize = 50_000;

/// Issue #4484 reference workload: every worker advances this one counter, so
/// the whole batch serializes on a single cache line.
static SHARED_CONTROL_COUNTER: AtomicU64 = AtomicU64::new(0);

fn make_targets(n: usize) -> Vec<UpstreamTarget> {
    (0..n)
        .map(|i| UpstreamTarget {
            host: format!("host{i}"),
            port: 8080,
            service_port_policy_key: None,
            weight: 1,
            tags: HashMap::new(),
            locality: None,
            path: None,
        })
        .collect()
}

fn run_selections(lb: &LoadBalancer, iterations: usize) {
    for _ in 0..iterations {
        black_box(lb.select("", None));
    }
}

fn run_shared_counter(iterations: usize) {
    for _ in 0..iterations {
        black_box(SHARED_CONTROL_COUNTER.fetch_add(1, Ordering::Relaxed));
    }
}

/// One measured batch: `ITERATIONS_PER_THREAD` operations on the calling thread.
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

fn bench_rr_selection(c: &mut Criterion) {
    let mut group = c.benchmark_group("rr_selection");

    let fixture = make_targets(TARGET_COUNT);
    let lb = Arc::new(LoadBalancer::new(
        "bench-rr",
        LoadBalancerAlgorithm::RoundRobin,
        &fixture,
        None,
    ));
    run_selections(&lb, 2_048);

    let selection: Workload = {
        let lb = Arc::clone(&lb);
        Arc::new(move || run_selections(&lb, ITERATIONS_PER_THREAD))
    };
    bench_workload(&mut group, &format!("{TARGET_COUNT}_targets"), selection);

    run_shared_counter(2_048);
    let control: Workload = Arc::new(|| run_shared_counter(ITERATIONS_PER_THREAD));
    bench_workload(&mut group, "shared_counter_control", control);

    group.finish();
}

fn criterion_config() -> Criterion {
    let criterion = Criterion::default();
    match std::env::var_os("FERRUM_RR_CRITERION_ROOT") {
        Some(path) => criterion.output_directory(Path::new(&path)),
        None => criterion,
    }
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets = bench_rr_selection
}
criterion_main!(benches);

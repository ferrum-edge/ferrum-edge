//! Concurrent RoundRobin selection microbenchmark for hosted CI (#2947).
//!
//! Guards the sharded / CachePadded RR selection counters: a 2-target upstream
//! must keep multi-thread throughput clearly above a single shared `AtomicU64`
//! contention floor. Fixture contract matches the WRR contention bench pattern
//! (long-lived barrier-synchronized workers; Criterion custom-iteration wall
//! time covers `threads * ITERATIONS_PER_THREAD` selections).

use std::collections::HashMap;
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, Ordering};
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

fn measure_parallel_batches(lb: &Arc<LoadBalancer>, threads: usize, batches: u64) -> Duration {
    let start_line = Arc::new(Barrier::new(threads + 1));
    let end_line = Arc::new(Barrier::new(threads + 1));
    let stop = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::with_capacity(threads);
    for _ in 0..threads {
        let lb = Arc::clone(lb);
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
                run_selections(&lb, ITERATIONS_PER_THREAD);
                end_line.wait();
            }
        }));
    }

    // Untimed prime so the first measured sample is not cold-scheduled.
    start_line.wait();
    end_line.wait();

    let mut total = Duration::ZERO;
    for _ in 0..batches {
        start_line.wait();
        let started = Instant::now();
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

    for threads in THREAD_COUNTS {
        group.throughput(Throughput::Elements(
            (ITERATIONS_PER_THREAD * threads) as u64,
        ));
        group.bench_function(
            format!("{TARGET_COUNT}_targets_{threads}_threads"),
            |b| {
                b.iter_custom(|iters| {
                    if threads == 1 {
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            let started = Instant::now();
                            run_selections(&lb, ITERATIONS_PER_THREAD);
                            total += started.elapsed();
                        }
                        total
                    } else {
                        measure_parallel_batches(&lb, threads, iters)
                    }
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_rr_selection);
criterion_main!(benches);

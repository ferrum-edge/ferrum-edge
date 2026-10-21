use std::time::{Duration, Instant};

use mesh_runtime_perf::{BenchMetrics, MeasurementWindow};

#[test]
fn common_window_excludes_deadline_and_drain_from_throughput_and_latency() {
    let epoch = Instant::now();
    let window = MeasurementWindow::new(epoch, Duration::from_secs(1));
    let deadline = epoch + Duration::from_secs(1);
    assert!(!window.contains(epoch - Duration::from_nanos(1)));
    assert!(window.contains(epoch));
    assert!(window.contains(deadline - Duration::from_nanos(1)));
    assert!(!window.contains(deadline));

    let mut metrics = BenchMetrics::new();
    metrics.record_completion(window, epoch, 100, 16);
    metrics.record_completion(window, deadline - Duration::from_nanos(1), 200, 32);
    metrics.record_completion(window, deadline, 1_000_000, 64);
    metrics.record_completion(window, deadline + Duration::from_secs(1), 2_000_000, 128);

    let report = metrics.json("test", "http://example/echo", 2, 1, 16);
    assert_eq!(report.total_requests, 2);
    assert_eq!(report.total_bytes, 48);
    assert_eq!(report.rps, 2.0);
    assert_eq!(report.latency_avg_us, 150);
    assert_eq!(report.latency_max_us, 200);
    assert_eq!(report.drained_requests, 2);
    assert_eq!(report.drained_bytes, 192);
    assert_eq!(report.total_errors, 0);
}

#[test]
fn merged_workers_preserve_drain_warmup_and_cell_errors_separately() {
    let epoch = Instant::now();
    let window = MeasurementWindow::new(epoch, Duration::from_secs(1));
    let mut combined = BenchMetrics::new();
    for _ in 0..2 {
        let mut worker = BenchMetrics::new();
        worker.record_warmup_success();
        worker.record_warmup_error();
        worker.record_error();
        worker.record_completion(window, epoch, 100, 16);
        worker.record_completion(window, epoch + Duration::from_secs(1), 2_000_000, 32);
        combined.merge(&worker);
    }

    let report = combined.json("test", "http://example/echo", 2, 1, 16);
    assert_eq!(report.total_requests, 2);
    assert_eq!(report.total_bytes, 32);
    assert_eq!(report.rps, 2.0);
    assert_eq!(report.latency_max_us, 100);
    assert_eq!(report.drained_requests, 2);
    assert_eq!(report.drained_bytes, 64);
    assert_eq!(report.warmup_requests, 2);
    assert_eq!(report.warmup_errors, 2);
    assert_eq!(
        report.total_errors, 4,
        "warmup failures invalidate the cell"
    );
}

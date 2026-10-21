use std::sync::Arc;
use std::time::{Duration, Instant};

use mesh_runtime_perf::{BenchMetrics, FixedRateSchedule, MeasurementWindow};

#[test]
fn absolute_slots_preserve_aggregate_rate_without_rounding_drift() {
    let schedule = FixedRateSchedule::new(3, 2).unwrap();
    let slots: Vec<_> = std::iter::from_fn(|| schedule.claim()).collect();
    assert_eq!(schedule.rate(), 3);
    assert_eq!(schedule.offered_requests(), 6);
    assert_eq!(
        slots,
        [
            Duration::ZERO,
            Duration::from_nanos(333_333_333),
            Duration::from_nanos(666_666_666),
            Duration::from_secs(1),
            Duration::from_nanos(1_333_333_333),
            Duration::from_nanos(1_666_666_666),
        ]
    );
    assert_eq!(schedule.claim(), None);
}

#[test]
fn workers_claim_one_shared_sequence_even_with_more_workers_than_slots() {
    let schedule = Arc::new(FixedRateSchedule::new(2, 1).unwrap());
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let schedule = schedule.clone();
            std::thread::spawn(move || schedule.claim())
        })
        .collect();
    let mut slots: Vec<_> = handles
        .into_iter()
        .filter_map(|handle| handle.join().unwrap())
        .collect();
    slots.sort();
    assert_eq!(slots, [Duration::ZERO, Duration::from_millis(500)]);
    assert_eq!(schedule.offered_requests(), 2);
}

#[test]
fn invalid_rate_and_counter_overflow_are_rejected() {
    assert!(FixedRateSchedule::new(0, 1).is_err());
    assert!(FixedRateSchedule::new(1_000_000_001, 1).is_err());
    assert!(FixedRateSchedule::new(1_000_000_000, u64::MAX).is_err());
    let schedule = FixedRateSchedule::new(1_000_000_000, 1).unwrap();
    assert_eq!(schedule.claim(), Some(Duration::ZERO));
    assert_eq!(schedule.claim(), Some(Duration::from_nanos(1)));
}

#[test]
fn late_admission_and_drain_preserve_scheduled_and_service_populations() {
    let epoch = Instant::now();
    let window = MeasurementWindow::new(epoch, Duration::from_secs(1));
    let schedule = FixedRateSchedule::new(4, 1).unwrap();
    let mut combined = BenchMetrics::new();

    let mut first = BenchMetrics::new();
    let due = epoch + schedule.claim().unwrap();
    let admission = epoch + Duration::from_millis(100);
    first.record_scheduled_admission(due, admission);
    first.record_scheduled_completion(
        window,
        due,
        admission,
        epoch + Duration::from_millis(150),
        16,
    );
    combined.merge(&first);

    let mut second = BenchMetrics::new();
    let due = epoch + schedule.claim().unwrap();
    let admission = epoch + Duration::from_millis(750);
    second.record_scheduled_admission(due, admission);
    second.record_scheduled_completion(
        window,
        due,
        admission,
        epoch + Duration::from_millis(1_250),
        32,
    );
    // Reserving a slot without admitting it must not erase it from missed
    // accounting; the final fourth slot is never even claimed.
    assert_eq!(schedule.claim(), Some(Duration::from_millis(500)));
    second.record_warmup_success();
    combined.merge(&second);
    combined.configure_fixed_rate(&schedule);

    let report = combined.json("test", "http://example/echo", 2, 1, 16);
    assert_eq!(report.rate, 4);
    assert_eq!(report.offered_requests, 4);
    assert_eq!(report.admitted_requests, 2);
    assert_eq!(report.missed_requests, 2);
    assert_eq!(report.total_requests, 1);
    assert_eq!(report.drained_requests, 1);
    assert_eq!(report.cohort_requests, 2);
    assert_eq!(report.scheduled_requests, 1);
    assert_eq!(report.cohort_scheduled_requests, 2);
    assert!(report.p99_us >= 50_000 && report.p99_us < 51_000);
    assert!(report.scheduled_p99_us >= 150_000 && report.scheduled_p99_us < 151_000);
    assert!(report.cohort_p99_us >= 500_000 && report.cohort_p99_us < 501_000);
    assert!(report.cohort_scheduled_p99_us >= 1_000_000);
    assert!(report.cohort_scheduled_p99_us < 1_001_000);
    assert!(report.admission_delay_p99_us >= 500_000);
    assert_eq!(report.admission_delay_max_us, report.admission_delay_p99_us);
    assert_eq!(report.warmup_requests, 1);
    assert_eq!(report.total_errors, 0);
}

#[test]
fn failed_admissions_and_setup_errors_are_not_synthetic_latency_samples() {
    let epoch = Instant::now();
    let schedule = FixedRateSchedule::new(2, 1).unwrap();
    let mut metrics = BenchMetrics::new();
    metrics.configure_fixed_rate(&schedule);
    metrics.record_warmup_error();
    metrics.record_scheduled_admission(epoch, epoch + Duration::from_millis(250));
    metrics.record_admitted_error();
    let report = metrics.json("test", "http://example/echo", 1, 1, 16);
    assert_eq!(report.offered_requests, 2);
    assert_eq!(report.admitted_requests, 1);
    assert_eq!(report.admitted_errors, 1);
    assert_eq!(report.missed_requests, 1);
    assert_eq!(report.warmup_errors, 1);
    assert_eq!(report.total_errors, 2);
    assert_eq!(report.scheduled_requests, 0);
    assert_eq!(report.cohort_scheduled_requests, 0);
    assert_eq!(report.cohort_requests, 0);
    assert!(report.admission_delay_p99_us >= 250_000);
}

#[test]
fn saturated_accounting_keeps_existing_service_latency_semantics() {
    let epoch = Instant::now();
    let window = MeasurementWindow::new(epoch, Duration::from_secs(1));
    let mut metrics = BenchMetrics::new();
    metrics.record_admission();
    metrics.record_completion(window, epoch, 100, 16);
    metrics.record_admission();
    metrics.record_completion(window, window.deadline(), 500_000, 32);
    let report = metrics.json("test", "http://example/echo", 1, 1, 16);
    assert_eq!(report.rate, 0);
    assert_eq!(report.offered_requests, 0);
    assert_eq!(report.missed_requests, 0);
    assert_eq!(report.admitted_requests, 2);
    assert_eq!(report.total_requests, 1);
    assert_eq!(report.rps, 1.0);
    assert_eq!(report.latency_avg_us, 100);
    assert_eq!(report.cohort_requests, 2);
    assert!(report.cohort_p99_us >= 500_000);
    assert_eq!(report.scheduled_requests, 0);
    assert_eq!(report.cohort_scheduled_requests, 0);
    assert_eq!(report.admission_delay_max_us, 0);
}

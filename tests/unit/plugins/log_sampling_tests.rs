use ferrum_edge::plugins::utils::log_sampling::{
    WARNING_INTERVAL_MS, WarningSampler, warn_sampled,
};
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn first_event_emits_even_at_tick_zero() {
    assert_eq!(WarningSampler::new().on_event(0), Some(0));
    assert_eq!(WarningSampler::default().on_event(42), Some(0));
}

#[test]
fn burst_is_suppressed_and_reported_on_the_next_emission() {
    let sampler = WarningSampler::new();
    assert_eq!(sampler.on_event(0), Some(0));
    for tick in 0..100 {
        assert_eq!(sampler.on_event(tick), None);
    }
    assert_eq!(sampler.on_event(WARNING_INTERVAL_MS - 1), None);
    assert_eq!(sampler.on_event(WARNING_INTERVAL_MS), Some(101));
    assert_eq!(sampler.on_event(2 * WARNING_INTERVAL_MS), Some(0));
}

#[test]
fn stale_and_saturated_ticks_do_not_reopen_the_gate() {
    let sampler = WarningSampler::new();
    assert_eq!(sampler.on_event(100), Some(0));
    assert_eq!(sampler.on_event(99), None);
    assert_eq!(sampler.on_event(WARNING_INTERVAL_MS + 99), None);
    assert_eq!(sampler.on_event(WARNING_INTERVAL_MS + 100), Some(2));
    assert_eq!(sampler.on_event(u64::MAX), Some(0));
    assert_eq!(sampler.on_event(u64::MAX), None);
}

#[test]
fn concurrent_events_share_one_slot_and_preserve_the_count() {
    let sampler = WarningSampler::new();
    let emitted = AtomicUsize::new(0);
    let reported = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                for _ in 0..100 {
                    if let Some(suppressed) = sampler.on_event(0) {
                        emitted.fetch_add(1, Ordering::Relaxed);
                        reported.fetch_add(suppressed as usize, Ordering::Relaxed);
                    }
                }
            });
        }
    });
    assert_eq!(emitted.load(Ordering::Relaxed), 1);
    let next = sampler.on_event(WARNING_INTERVAL_MS).unwrap();
    assert_eq!(next as usize + reported.load(Ordering::Relaxed), 799);
}

#[test]
fn macro_shares_its_site_across_generic_instances_without_formatting_suppressed_events() {
    fn emit<T>(_value: &T, evaluated: &AtomicUsize) {
        warn_sampled!(
            evaluated = evaluated.fetch_add(1, Ordering::Relaxed),
            "sampled warning fixture"
        );
    }

    let (logs, _guard) = super::plugin_utils::capture_logs();
    let evaluated = AtomicUsize::new(0);
    emit(&0_u8, &evaluated);
    emit(&0_u64, &evaluated);
    for _ in 0..100 {
        emit(&"another instance", &evaluated);
    }
    let output = logs.contents();
    assert_eq!(output.matches("sampled warning fixture").count(), 1);
    assert!(output.contains("suppressed_events=0"));
    assert!(output.contains("sample_interval_seconds=10"));
    assert_eq!(evaluated.load(Ordering::Relaxed), 1);
}

#[test]
fn macro_preserves_debug_details_and_independent_sites() {
    super::plugin_utils::install_interest_floor();
    let logs = super::plugin_utils::CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(logs.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    for detail in 0..3 {
        warn_sampled!(target: "sampling_fixture", detail, "first site");
        warn_sampled!(detail, "second site");
    }
    let output = logs.contents();
    assert_eq!(
        output.lines().filter(|line| line.contains("WARN")).count(),
        2
    );
    assert_eq!(
        output.lines().filter(|line| line.contains("DEBUG")).count(),
        6
    );
    assert!(output.contains("sampling_fixture"));
    assert!(output.contains("detail=2"));
}

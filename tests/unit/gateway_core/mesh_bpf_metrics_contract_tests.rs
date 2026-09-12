//! Honest `__mesh_bpf_metrics` contract coverage
//! (#2218/#2220/#2224/#2229/#3308/#3309).
//!
//! Validates the public Prometheus surface, ABI decode rules, pin-rotation
//! dropped-baseline seeding, and the fixed TCP latency histogram contract
//! without requiring a live BPF load.

use ferrum_ebpf_common::{
    ACCEPT_FIRST_BYTE_MAP_MAX_ENTRIES, ACCEPT_FIRST_BYTE_MAX_DELTA_NS,
    ACCEPT_FIRST_BYTE_PHASE_CONFIRMED, ACCEPT_FIRST_BYTE_PHASE_ENROLLING,
    ACCEPT_FIRST_BYTE_PHASE_ENROLLING_CONFIRMED, ACCEPT_FIRST_BYTE_PHASE_PENDING,
    AcceptFirstByteState, SOCK_OPS_DIRECTION_RECEIVED, SOCK_OPS_DIRECTION_SENT,
    SOCK_OPS_DROP_BYPASS_UID_HIT, SOCK_OPS_DROP_EXCLUDE_CIDR_HIT, SOCK_OPS_DROP_EXCLUDE_PORT_HIT,
    SOCK_OPS_DROP_NOT_IN_INCLUDE_CIDR, SOCK_OPS_EVENT_ACCEPT_TO_FIRST_BYTE_LATENCY,
    SOCK_OPS_EVENT_DROP_REASON, SOCK_OPS_EVENT_RST, SockOpsRecord, accept_to_first_byte_us,
};
use ferrum_edge::ebpf::bpf_metrics::{
    BPF_LATENCY_BUCKET_BOUNDS_US, BPF_LATENCY_BUCKET_LE_LABELS, BPF_LATENCY_EXCLUSIVE_BUCKET_COUNT,
    BPF_LATENCY_FINITE_BUCKET_COUNT, BpfDropReason, BpfMetricsState, TcpDirection,
    bpf_latency_exclusive_bucket_index,
};
use ferrum_edge::ebpf::event_consumer::{
    PollOutcome, SockOpsConsumer, SockOpsEvent, seed_dropped_baseline,
};
use ferrum_edge::plugins::mesh::bpf_metrics::MeshBpfMetrics;
use serde_json::json;

fn render_with(state: std::sync::Arc<BpfMetricsState>) -> String {
    MeshBpfMetrics::with_state(&json!({}), state)
        .expect("plugin config")
        .exporter()
        .render_prometheus()
}

fn metric_value(text: &str, needle: &str) -> u64 {
    let line = text
        .lines()
        .find(|line| line.starts_with(needle))
        .unwrap_or_else(|| panic!("missing metric line starting with {needle}:\n{text}"));
    line.rsplit_once(' ')
        .map(|(_, v)| v)
        .unwrap_or_else(|| panic!("no value on line {line}"))
        .parse()
        .unwrap_or_else(|_| panic!("non-u64 value on line {line}"))
}

#[test]
fn prometheus_surface_uses_nondirectional_rst_and_exports_accept_to_first_byte() {
    let state = BpfMetricsState::new();
    state.record_connect();
    state.record_rst();
    state.record_drop(BpfDropReason::ExcludePortHit);
    state.record_syn_to_ack(40);
    state.record_accept_to_first_byte(2_500);
    let text = render_with(state);

    assert!(text.contains("ferrum_mesh_bpf_tcp_events_total{event=\"rst\"} 1"));
    assert!(
        !text.contains("rst_sent") && !text.contains("rst_received"),
        "directional RST labels must not appear: {text}"
    );
    assert!(text.contains("ferrum_mesh_bpf_accept_to_first_byte_microseconds_count 1"));
    assert!(text.contains("ferrum_mesh_bpf_accept_to_first_byte_microseconds_sum 2500"));
    assert!(text.contains("ferrum_mesh_bpf_drops_total{reason=\"exclude_port_hit\"} 1"));
    assert!(text.contains("ferrum_mesh_bpf_syn_to_ack_microseconds_count 1"));
    assert!(
        text.contains("without sent/received") || text.contains("cannot distinguish direction"),
        "HELP must disclose non-directional RST: {text}"
    );
}

#[test]
fn all_four_drop_reasons_render_at_zero_when_unset() {
    let text = render_with(BpfMetricsState::new());
    for reason in [
        "bypass_uid_hit",
        "exclude_cidr_hit",
        "not_in_include_cidr",
        "exclude_port_hit",
    ] {
        assert!(
            text.contains(&format!(
                "ferrum_mesh_bpf_drops_total{{reason=\"{reason}\"}} 0"
            )),
            "missing zero series for {reason}: {text}"
        );
    }
}

#[test]
fn abi_drop_reason_and_rst_decode_contract() {
    fn rec(event: u32, direction: u32, drop_reason: u32) -> SockOpsRecord {
        SockOpsRecord {
            event_type: event,
            direction,
            drop_reason,
            _pad: 0,
            value: 0,
        }
    }

    assert_eq!(
        SockOpsEvent::from_record(rec(SOCK_OPS_EVENT_RST, 0, 0)),
        Some(SockOpsEvent::Rst)
    );
    assert_eq!(
        SockOpsEvent::from_record(rec(SOCK_OPS_EVENT_RST, SOCK_OPS_DIRECTION_SENT, 0)),
        Some(SockOpsEvent::Rst)
    );
    assert_eq!(
        SockOpsEvent::from_record(rec(SOCK_OPS_EVENT_RST, SOCK_OPS_DIRECTION_RECEIVED, 0)),
        Some(SockOpsEvent::Rst)
    );
    let mut first_byte = rec(SOCK_OPS_EVENT_ACCEPT_TO_FIRST_BYTE_LATENCY, 0, 0);
    first_byte.value = 42;
    assert_eq!(
        SockOpsEvent::from_record(first_byte),
        Some(SockOpsEvent::AcceptToFirstByteLatency {
            us: 42,
            socket_cookie: 0,
        })
    );

    for (raw, expected) in [
        (SOCK_OPS_DROP_BYPASS_UID_HIT, BpfDropReason::BypassUidHit),
        (
            SOCK_OPS_DROP_EXCLUDE_CIDR_HIT,
            BpfDropReason::ExcludeCidrHit,
        ),
        (
            SOCK_OPS_DROP_NOT_IN_INCLUDE_CIDR,
            BpfDropReason::NotInIncludeCidr,
        ),
        (
            SOCK_OPS_DROP_EXCLUDE_PORT_HIT,
            BpfDropReason::ExcludePortHit,
        ),
    ] {
        assert_eq!(
            SockOpsEvent::from_record(rec(SOCK_OPS_EVENT_DROP_REASON, 0, raw)),
            Some(SockOpsEvent::DropReason(expected))
        );
    }
}

#[test]
fn accept_first_byte_timestamp_and_phase_contract_rejects_false_evidence() {
    assert_eq!(
        AcceptFirstByteState::pending(10).phase,
        ACCEPT_FIRST_BYTE_PHASE_PENDING
    );
    assert_eq!(
        AcceptFirstByteState::confirmed(10).phase,
        ACCEPT_FIRST_BYTE_PHASE_CONFIRMED
    );

    // Round up sub-microsecond positive intervals instead of losing fast flows.
    assert_eq!(accept_to_first_byte_us(1_000, 1_001), Some(1));
    assert_eq!(accept_to_first_byte_us(1_000, 2_000), Some(1));
    assert_eq!(accept_to_first_byte_us(1_000, 2_001), Some(2));

    // Equal/reversed values include clock/ktime wrap and never fabricate zero
    // or saturated latency. Over-age evidence is stale.
    assert_eq!(accept_to_first_byte_us(5, 5), None);
    assert_eq!(accept_to_first_byte_us(u64::MAX - 5, 4), None);
    assert_eq!(
        accept_to_first_byte_us(1, 1 + ACCEPT_FIRST_BYTE_MAX_DELTA_NS),
        Some(3_600_000_000)
    );
    assert_eq!(
        accept_to_first_byte_us(1, 2 + ACCEPT_FIRST_BYTE_MAX_DELTA_NS),
        None
    );
}

#[test]
fn accept_first_byte_lifecycle_is_bounded_and_terminal() {
    assert_eq!(ACCEPT_FIRST_BYTE_MAP_MAX_ENTRIES, 65_536);

    let enrolling = AcceptFirstByteState::enrolling(123);
    assert_eq!(enrolling.phase, ACCEPT_FIRST_BYTE_PHASE_ENROLLING);
    assert!(!enrolling.is_confirmed());
    let enrolling_confirmed = enrolling
        .confirm()
        .expect("capture proof is retained during enrollment");
    assert_eq!(
        enrolling_confirmed.phase,
        ACCEPT_FIRST_BYTE_PHASE_ENROLLING_CONFIRMED
    );
    assert!(!enrolling_confirmed.is_confirmed());
    assert_eq!(
        enrolling_confirmed.arm_after_enrollment(false),
        Some(AcceptFirstByteState::confirmed(123))
    );
    assert_eq!(
        enrolling.arm_after_enrollment(false),
        Some(AcceptFirstByteState::pending(123))
    );
    assert_eq!(
        enrolling.arm_after_enrollment(true),
        Some(AcceptFirstByteState::confirmed(123))
    );

    let pending = AcceptFirstByteState::pending(123);
    let confirmed = pending.confirm().expect("pending state confirms");
    assert!(confirmed.is_confirmed());
    assert_eq!(confirmed.accepted_ns, pending.accepted_ns);
    assert!(confirmed.confirm().is_none());

    // A fresh cookie generation starts pending even when the network tuple is
    // reused. Kernel BPF_EXIST confirmation cannot recreate state after the
    // first-data/close delete wins the race.
    let reused_tuple_generation = AcceptFirstByteState::pending(456);
    assert!(!reused_tuple_generation.is_confirmed());
    assert_eq!(
        reused_tuple_generation.confirm(),
        Some(AcceptFirstByteState::confirmed(456))
    );
}

#[test]
fn accept_first_byte_histogram_distinguishes_fast_and_delayed_data() {
    let state = BpfMetricsState::new();
    state.record_accept_to_first_byte(250);
    state.record_accept_to_first_byte(2_500_000);
    let text = render_with(state);

    assert_eq!(
        metric_value(
            &text,
            "ferrum_mesh_bpf_accept_to_first_byte_microseconds_bucket{le=\"250\"}"
        ),
        1
    );
    assert_eq!(
        metric_value(
            &text,
            "ferrum_mesh_bpf_accept_to_first_byte_microseconds_bucket{le=\"2500000\"}"
        ),
        2
    );
    assert_eq!(
        metric_value(
            &text,
            "ferrum_mesh_bpf_accept_to_first_byte_microseconds_count"
        ),
        2
    );
    assert_eq!(
        metric_value(
            &text,
            "ferrum_mesh_bpf_accept_to_first_byte_microseconds_sum"
        ),
        2_500_250
    );
}

#[test]
fn accept_first_byte_sum_saturates_by_dropping_overflowing_sample() {
    let state = BpfMetricsState::new();
    state.record_accept_to_first_byte(u64::MAX);
    state.record_accept_to_first_byte(1);
    let snap = state.snapshot();
    assert_eq!(snap.accept_to_first_byte_us_sum, u64::MAX);
    assert_eq!(snap.accept_to_first_byte_count, 1);
    assert_eq!(
        snap.accept_to_first_byte_bucket_exclusive[BPF_LATENCY_FINITE_BUCKET_COUNT],
        1
    );
}

#[test]
fn accept_first_byte_count_and_bucket_saturate_without_wrap() {
    use std::sync::atomic::Ordering;

    let state = BpfMetricsState::new();
    state
        .accept_to_first_byte_count
        .store(u64::MAX, Ordering::Relaxed);
    state.accept_to_first_byte_bucket_exclusive[0].store(u64::MAX, Ordering::Relaxed);
    state.record_accept_to_first_byte(100);

    let snap = state.snapshot();
    assert_eq!(snap.accept_to_first_byte_count, u64::MAX);
    assert_eq!(snap.accept_to_first_byte_bucket_exclusive[0], u64::MAX);
    assert_eq!(snap.accept_to_first_byte_us_sum, 0);

    let bucket_saturated = BpfMetricsState::new();
    bucket_saturated.accept_to_first_byte_bucket_exclusive[0].store(u64::MAX, Ordering::Relaxed);
    bucket_saturated.record_accept_to_first_byte(100);
    let snap = bucket_saturated.snapshot();
    assert_eq!(snap.accept_to_first_byte_count, 0);
    assert_eq!(snap.accept_to_first_byte_bucket_exclusive[0], u64::MAX);
    assert_eq!(snap.accept_to_first_byte_us_sum, 0);
}

#[test]
fn pin_rotation_seed_preserves_cumulative_state() {
    let consumer = SockOpsConsumer::new(BpfMetricsState::new());
    consumer.handle_event(SockOpsEvent::Connect);
    consumer.handle_event(SockOpsEvent::Fin {
        direction: TcpDirection::Sent,
    });
    consumer.handle_event(SockOpsEvent::DropReason(BpfDropReason::BypassUidHit));

    // First map generation with no pre-existing drops.
    assert_eq!(seed_dropped_baseline(&consumer, 0), 0);
    let mid = consumer.metrics().snapshot();
    assert_eq!(mid.connect, 1);
    assert_eq!(mid.fin_sent, 1);
    assert_eq!(mid.drop_bypass_uid_hit, 1);
    assert_eq!(mid.ringbuf_overruns, 0);
    assert!(!mid.in_overrun_regime);

    // Replacement map generation already lost events before reattach.
    assert_eq!(seed_dropped_baseline(&consumer, 7), 7);
    let after = consumer.metrics().snapshot();
    assert_eq!(after.connect, 1, "userspace cumulative state must survive");
    assert_eq!(after.fin_sent, 1);
    assert_eq!(after.drop_bypass_uid_hit, 1);
    assert_eq!(after.ringbuf_overruns, 1);
    assert!(after.in_overrun_regime);

    // Subsequent poll-style overruns still advance the counter.
    let mut consecutive = 0u32;
    consumer.observe_poll(PollOutcome::Overrun, &mut consecutive, 3);
    assert_eq!(consumer.metrics().snapshot().ringbuf_overruns, 2);
}

#[test]
fn sock_ops_pin_publication_unpublishes_marker_before_dependents() {
    let loader = include_str!("../../../src/ebpf/loader.rs");
    let publication = loader
        .split_once("fn pin_sock_ops_maps")
        .expect("pin_sock_ops_maps definition")
        .1
        .split_once("fn pin_map_at")
        .expect("pin_map_at follows publication")
        .0;

    let marker_unpublish = publication
        .find("remove_pin_if_present(BPF_SOCK_OPS_EVENTS_PIN_PATH)?;")
        .expect("old events commit marker must be unpublished");
    let stats_publish = publication
        .find("pin_map_at(bpf, BPF_MAP_SOCK_OPS_STATS")
        .expect("stats publication");
    let sockhash_publish = publication
        .find("BPF_MAP_ACCEPT_FIRST_BYTE_SOCKETS,")
        .expect("first-byte SockHash publication");
    let marker_publish = publication
        .rfind("pin_map_at(bpf, BPF_MAP_SOCK_OPS_EVENTS")
        .expect("events commit-marker publication");

    assert!(
        marker_unpublish < stats_publish
            && stats_publish < sockhash_publish
            && sockhash_publish < marker_publish,
        "events must be absent while dependent pins are replaced, then published last"
    );
    assert!(
        loader.contains("Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(())"),
        "a missing stale pin must not fail publication"
    );
}

#[test]
fn ringbuf_overrun_help_documents_reattach_seeding() {
    let text = render_with(BpfMetricsState::new());
    assert!(
        text.contains("re-attaching") || text.contains("pin rotation"),
        "overrun HELP must document pin-rotation seeding: {text}"
    );
}

#[test]
fn latency_histogram_bucket_boundaries_and_labels_are_stable() {
    assert_eq!(
        BPF_LATENCY_BUCKET_BOUNDS_US.len(),
        BPF_LATENCY_FINITE_BUCKET_COUNT
    );
    assert_eq!(
        BPF_LATENCY_BUCKET_LE_LABELS.len(),
        BPF_LATENCY_FINITE_BUCKET_COUNT
    );
    assert_eq!(
        BPF_LATENCY_EXCLUSIVE_BUCKET_COUNT,
        BPF_LATENCY_FINITE_BUCKET_COUNT + 1
    );
    assert_eq!(
        BPF_LATENCY_BUCKET_BOUNDS_US,
        [
            100, 250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000,
            1_000_000, 2_500_000, 5_000_000,
        ]
    );
    for (bound, label) in BPF_LATENCY_BUCKET_BOUNDS_US
        .iter()
        .zip(BPF_LATENCY_BUCKET_LE_LABELS.iter())
    {
        assert_eq!(*label, bound.to_string());
    }

    // Inclusive upper bounds: exact boundary lands in that finite bucket.
    assert_eq!(bpf_latency_exclusive_bucket_index(100), 0);
    assert_eq!(bpf_latency_exclusive_bucket_index(101), 1);
    assert_eq!(
        bpf_latency_exclusive_bucket_index(5_000_000),
        BPF_LATENCY_FINITE_BUCKET_COUNT - 1
    );
    assert_eq!(
        bpf_latency_exclusive_bucket_index(5_000_001),
        BPF_LATENCY_FINITE_BUCKET_COUNT
    );
    assert_eq!(
        bpf_latency_exclusive_bucket_index(u64::MAX),
        BPF_LATENCY_FINITE_BUCKET_COUNT
    );
}

#[test]
fn latency_histogram_renders_cumulative_buckets_sum_and_count() {
    let state = BpfMetricsState::new();
    // 100µs → first bucket; 250µs → second; 5_000_001 → +Inf only.
    state.record_srtt_sample(100);
    state.record_srtt_sample(250);
    state.record_srtt_sample(5_000_001);
    state.record_syn_to_ack(500);
    state.record_syn_to_ack(500);

    let text = render_with(state.clone());
    let snap = state.snapshot();

    assert!(text.contains("# TYPE ferrum_mesh_bpf_srtt_microseconds histogram"));
    assert!(text.contains("# TYPE ferrum_mesh_bpf_syn_to_ack_microseconds histogram"));
    assert!(
        !text.contains("# TYPE ferrum_mesh_bpf_srtt_microseconds summary"),
        "latency families must be histograms, not summaries"
    );

    // Zero-state finite buckets must still be present for series stability.
    let empty = render_with(BpfMetricsState::new());
    for le in BPF_LATENCY_BUCKET_LE_LABELS {
        assert!(
            empty.contains(&format!(
                "ferrum_mesh_bpf_srtt_microseconds_bucket{{le=\"{le}\"}} 0"
            )),
            "missing zero SRTT bucket le={le}"
        );
        assert!(
            empty.contains(&format!(
                "ferrum_mesh_bpf_syn_to_ack_microseconds_bucket{{le=\"{le}\"}} 0"
            )),
            "missing zero SYN→ACK bucket le={le}"
        );
    }
    assert!(empty.contains("ferrum_mesh_bpf_srtt_microseconds_bucket{le=\"+Inf\"} 0"));

    // Cumulative rendering: sample@100 and sample@250 both contribute to le="250".
    assert_eq!(
        metric_value(
            &text,
            "ferrum_mesh_bpf_srtt_microseconds_bucket{le=\"100\"}"
        ),
        1
    );
    assert_eq!(
        metric_value(
            &text,
            "ferrum_mesh_bpf_srtt_microseconds_bucket{le=\"250\"}"
        ),
        2
    );
    assert_eq!(
        metric_value(
            &text,
            "ferrum_mesh_bpf_srtt_microseconds_bucket{le=\"5000000\"}"
        ),
        2,
        "overflow sample must not inflate finite buckets"
    );
    assert_eq!(
        metric_value(
            &text,
            "ferrum_mesh_bpf_srtt_microseconds_bucket{le=\"+Inf\"}"
        ),
        3
    );
    assert_eq!(
        metric_value(&text, "ferrum_mesh_bpf_srtt_microseconds_sum"),
        100 + 250 + 5_000_001
    );
    assert_eq!(
        metric_value(&text, "ferrum_mesh_bpf_srtt_microseconds_count"),
        3
    );

    // Snapshot cumulative helpers match exposition.
    let cum = snap.srtt_cumulative_buckets();
    assert_eq!(cum[0], 1);
    assert_eq!(cum[1], 2);
    assert_eq!(cum[BPF_LATENCY_FINITE_BUCKET_COUNT - 1], 2);
    assert_eq!(
        snap.srtt_bucket_exclusive[BPF_LATENCY_FINITE_BUCKET_COUNT],
        1
    );

    assert_eq!(
        metric_value(
            &text,
            "ferrum_mesh_bpf_syn_to_ack_microseconds_bucket{le=\"500\"}"
        ),
        2
    );
    assert_eq!(
        metric_value(&text, "ferrum_mesh_bpf_syn_to_ack_microseconds_sum"),
        1_000
    );
    assert_eq!(
        metric_value(&text, "ferrum_mesh_bpf_syn_to_ack_microseconds_count"),
        2
    );
}

#[test]
fn latency_histogram_distribution_shape_separates_bimodal_tail() {
    let state = BpfMetricsState::new();
    // Fast mode cluster around 200µs.
    for _ in 0..10 {
        state.record_srtt_sample(200);
    }
    // Slow tail cluster around 2ms.
    for _ in 0..2 {
        state.record_srtt_sample(2_000);
    }

    let text = render_with(state);
    let le_250 = metric_value(
        &text,
        "ferrum_mesh_bpf_srtt_microseconds_bucket{le=\"250\"}",
    );
    let le_1000 = metric_value(
        &text,
        "ferrum_mesh_bpf_srtt_microseconds_bucket{le=\"1000\"}",
    );
    let le_2500 = metric_value(
        &text,
        "ferrum_mesh_bpf_srtt_microseconds_bucket{le=\"2500\"}",
    );
    let inf = metric_value(
        &text,
        "ferrum_mesh_bpf_srtt_microseconds_bucket{le=\"+Inf\"}",
    );

    assert_eq!(le_250, 10, "fast mode must land at/under 250µs");
    assert_eq!(le_1000, 10, "slow samples must not inflate the 1ms bucket");
    assert_eq!(le_2500, 12, "slow tail must appear by the 2.5ms bucket");
    assert_eq!(inf, 12);
    assert_eq!(
        metric_value(&text, "ferrum_mesh_bpf_srtt_microseconds_count"),
        12
    );
    assert_eq!(
        metric_value(&text, "ferrum_mesh_bpf_srtt_microseconds_sum"),
        10 * 200 + 2 * 2_000
    );
}

#[test]
fn latency_histogram_clamps_raced_count_to_finite_buckets() {
    use std::sync::atomic::Ordering;

    let state = BpfMetricsState::new();
    // Model a scrape that loaded count before a concurrent observation but
    // loaded the observation's exclusive bucket afterward.
    state.srtt_count.store(1, Ordering::Relaxed);
    state.srtt_bucket_exclusive[0].store(2, Ordering::Relaxed);

    let text = render_with(state);
    assert_eq!(
        metric_value(
            &text,
            "ferrum_mesh_bpf_srtt_microseconds_bucket{le=\"100\"}"
        ),
        2
    );
    assert_eq!(
        metric_value(
            &text,
            "ferrum_mesh_bpf_srtt_microseconds_bucket{le=\"+Inf\"}"
        ),
        2
    );
    assert_eq!(
        metric_value(&text, "ferrum_mesh_bpf_srtt_microseconds_count"),
        2
    );
}

#[test]
fn latency_histogram_extreme_values_are_deterministic() {
    let state = BpfMetricsState::new();

    // Invalid zero samples are ignored for both signals.
    state.record_srtt_sample(0);
    state.record_syn_to_ack(0);
    let after_zero = state.snapshot();
    assert_eq!(after_zero.srtt_count, 0);
    assert_eq!(after_zero.srtt_sample_us_sum, 0);
    assert_eq!(after_zero.syn_to_ack_count, 0);
    assert_eq!(after_zero.syn_to_ack_us_sum, 0);
    assert!(after_zero.srtt_bucket_exclusive.iter().all(|&c| c == 0));
    assert!(
        after_zero
            .syn_to_ack_bucket_exclusive
            .iter()
            .all(|&c| c == 0)
    );

    // Extreme finite overflow lands only in +Inf.
    state.record_srtt_sample(u64::MAX);
    let after_max = state.snapshot();
    assert_eq!(after_max.srtt_count, 1);
    assert_eq!(after_max.srtt_sample_us_sum, u64::MAX);
    assert_eq!(
        after_max.srtt_bucket_exclusive[BPF_LATENCY_FINITE_BUCKET_COUNT],
        1
    );
    assert!(
        after_max.srtt_bucket_exclusive[..BPF_LATENCY_FINITE_BUCKET_COUNT]
            .iter()
            .all(|&c| c == 0)
    );

    // A further sample that would overflow u64 sum is dropped entirely.
    state.record_srtt_sample(1);
    let after_overflow = state.snapshot();
    assert_eq!(after_overflow.srtt_count, 1);
    assert_eq!(after_overflow.srtt_sample_us_sum, u64::MAX);
    assert_eq!(
        after_overflow.srtt_bucket_exclusive[BPF_LATENCY_FINITE_BUCKET_COUNT],
        1
    );

    let text = render_with(state);
    assert_eq!(
        metric_value(
            &text,
            "ferrum_mesh_bpf_srtt_microseconds_bucket{le=\"+Inf\"}"
        ),
        1
    );
    assert_eq!(
        metric_value(&text, "ferrum_mesh_bpf_srtt_microseconds_sum"),
        u64::MAX
    );
    assert_eq!(
        metric_value(&text, "ferrum_mesh_bpf_srtt_microseconds_count"),
        1
    );
}

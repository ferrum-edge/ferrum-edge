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
    SOCK_OPS_EVENT_DROP_REASON, SOCK_OPS_EVENT_RST, SOCK_OPS_STATS_EVENTS_DROPPED,
    SOCK_OPS_STATS_LEN, SockOpsRecord, accept_to_first_byte_us,
    sock_ops_stats_index_for_drop_reason,
};
use ferrum_edge::ebpf::bpf_metrics::{
    BPF_LATENCY_BUCKET_BOUNDS_US, BPF_LATENCY_BUCKET_LE_LABELS, BPF_LATENCY_EXCLUSIVE_BUCKET_COUNT,
    BPF_LATENCY_FINITE_BUCKET_COUNT, BpfDropReason, BpfMetricsState, TcpDirection,
    bpf_latency_exclusive_bucket_index,
};
use ferrum_edge::ebpf::event_consumer::{
    BPF_DROP_REASON_COUNT, BPF_DROP_REASON_STATS_SLOTS, DrainOutcome, PollOutcome,
    RINGBUF_DRAIN_RECORD_BUDGET, RingBufAttach, RingBufCursor, SockOpsConsumer, SockOpsEvent,
    drain_outstanding_records, drop_reason_baseline_after_reopen, drop_reason_delta,
    ringbuf_attach, ringbuf_outstanding_bytes, seed_dropped_baseline,
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
    consumer.record_drops(BpfDropReason::BypassUidHit, 1);

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

/// Issue #5502 regression guard.
///
/// `ferrum_mesh_bpf_drops_total` used to be incremented from the
/// `SOCK_OPS_EVENT_DROP_REASON` ringbuf record. A full ring discards that
/// record — only the generic dropped-events counter moves — so a bypass
/// decision could be classified in-kernel and still never reach the metric.
/// The kernel per-CPU counters are now the accounting authority, and the
/// record must not ALSO increment or every decision that survived the ring
/// would be counted twice.
#[test]
fn drop_reason_records_do_not_count_the_bypass_decision() {
    let consumer = SockOpsConsumer::new(BpfMetricsState::new());
    consumer.handle_event(SockOpsEvent::DropReason(BpfDropReason::ExcludePortHit));
    consumer.handle_event(SockOpsEvent::DropReason(BpfDropReason::ExcludePortHit));

    let after_records = consumer.metrics().snapshot();
    assert_eq!(
        after_records.drop_exclude_port_hit, 0,
        "the ringbuf record is the event stream, not the accounting authority"
    );
    assert_eq!(
        after_records.ringbuf_events_consumed, 2,
        "the record is still a consumed ringbuf event"
    );

    // Only the kernel-counter path moves the exported counter, and it moves
    // by the kernel delta rather than by one per record.
    consumer.record_drops(BpfDropReason::ExcludePortHit, 3);
    assert_eq!(consumer.metrics().snapshot().drop_exclude_port_hit, 3);
}

/// The kernel emitter and the userspace poller must agree on which
/// `FERRUM_SOCK_OPS_STATS` slot carries each reason, and none of them may
/// alias slot 0 — that slot drives the ringbuf overrun regime, so a bypass
/// decision landing there would manufacture a phantom overrun.
#[test]
fn kernel_drop_reason_slots_are_distinct_disjoint_and_in_bounds() {
    let expected_wire = [
        (BpfDropReason::BypassUidHit, SOCK_OPS_DROP_BYPASS_UID_HIT),
        (
            BpfDropReason::ExcludeCidrHit,
            SOCK_OPS_DROP_EXCLUDE_CIDR_HIT,
        ),
        (
            BpfDropReason::NotInIncludeCidr,
            SOCK_OPS_DROP_NOT_IN_INCLUDE_CIDR,
        ),
        (
            BpfDropReason::ExcludePortHit,
            SOCK_OPS_DROP_EXCLUDE_PORT_HIT,
        ),
    ];
    assert_eq!(BPF_DROP_REASON_STATS_SLOTS.len(), BPF_DROP_REASON_COUNT);
    assert_eq!(expected_wire.len(), BPF_DROP_REASON_COUNT);

    let mut seen = Vec::new();
    for (index, (reason, slot)) in BPF_DROP_REASON_STATS_SLOTS.iter().enumerate() {
        let (expected_reason, wire) = expected_wire[index];
        assert_eq!(*reason, expected_reason, "exposition order must be stable");
        assert_eq!(
            sock_ops_stats_index_for_drop_reason(wire),
            Some(*slot),
            "kernel emitter and userspace poller disagree for {reason:?}"
        );
        assert_ne!(
            *slot, SOCK_OPS_STATS_EVENTS_DROPPED,
            "a drop reason must never alias the ringbuf dropped-events slot"
        );
        assert!(*slot < SOCK_OPS_STATS_LEN, "slot must fit the stats map");
        assert!(!seen.contains(slot), "each reason needs its own slot");
        seen.push(*slot);
    }

    // An unrecognised wire discriminant must not fall back onto slot 0.
    assert_eq!(sock_ops_stats_index_for_drop_reason(0), None);
    assert_eq!(sock_ops_stats_index_for_drop_reason(999), None);
}

/// The kernel counters are cumulative per map generation. A node-agent
/// restart re-creates the map and the counters start over; the metric must
/// resume immediately instead of stalling until the new generation climbs
/// past the old total.
#[test]
fn drop_reason_delta_adopts_a_reset_generation_without_stalling() {
    assert_eq!(drop_reason_delta(0, 0), 0);
    assert_eq!(drop_reason_delta(0, 7), 7);
    assert_eq!(drop_reason_delta(7, 7), 0, "a quiet poll publishes nothing");
    assert_eq!(drop_reason_delta(7, 9), 2);
    // Generation reset: everything the new map reports is new.
    assert_eq!(drop_reason_delta(9_000, 3), 3);
    assert_eq!(drop_reason_delta(u64::MAX, 1), 1);
}

/// After a pin rotation the new generation's decisions were all made before
/// the consumer noticed, so none may be adopted as baseline (issue #7264):
/// with a zero baseline the next poll publishes every one of them. A re-open
/// of the same generation keeps the running baseline.
#[test]
fn reopen_baseline_publishes_a_rotated_generations_decisions() {
    let published_old_generation = [900, 50, 0, 3];
    let new_generation_totals = [4, 0, 2, 0];

    let rotated = drop_reason_baseline_after_reopen(true, published_old_generation);
    let deltas: Vec<u64> = rotated
        .iter()
        .zip(new_generation_totals)
        .map(|(last, current)| drop_reason_delta(*last, current))
        .collect();
    assert_eq!(deltas, new_generation_totals.to_vec());

    assert_eq!(
        drop_reason_baseline_after_reopen(false, published_old_generation),
        published_old_generation,
        "a resynchronization re-reads the same generation"
    );
}

/// Ringbuf record stride used by the fake cursor: the kernel's 8-byte record
/// header plus a `SockOpsRecord`, rounded up to the 8-byte boundary the
/// kernel reserves on.
const FAKE_RECORD_STRIDE: u64 = 32;

/// Default ringbuf size (`FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES`).
const FAKE_RING_BYTES: u64 = 4 * 1024 * 1024;

/// Fake ringbuf cursor that reproduces the defect behind issue #5563.
///
/// `with_next_record` never checks the producer position — exactly like aya
/// 0.13's `RingBuf`, whose cached producer position starts at `0` and is only
/// refreshed once its own consumer position catches that cache up, a
/// condition a pinned ring opened with a non-zero consumer position can never
/// reach. Left unbounded it wraps around the resident records forever, which
/// is what made every `ferrum_mesh_bpf_*` counter on an ambient pod a pure
/// rescale of one replayed record multiset. Only the producer-position bound
/// stops it.
struct ReplayingRingBuf {
    /// Resident records, in ring order.
    records: Vec<Vec<u8>>,
    /// Consumer position of `records[0]`.
    base: u64,
    consumer_pos: u64,
    producer_pos: u64,
    /// Consumer position of a record the producer has not committed yet.
    busy_at: Option<u64>,
    /// Publish `count` more records right after the `nth` record is taken,
    /// modelling a producer that commits while a drain pass is running.
    publish_after_take: Option<(usize, u64)>,
    /// Every record ever handed out, in delivery order.
    delivered: Vec<Vec<u8>>,
}

impl ReplayingRingBuf {
    fn with_resident(base: u64, records: Vec<Vec<u8>>) -> Self {
        let producer_pos = base + FAKE_RECORD_STRIDE * records.len() as u64;
        Self {
            records,
            base,
            consumer_pos: base,
            producer_pos,
            busy_at: None,
            publish_after_take: None,
            delivered: Vec::new(),
        }
    }

    /// Publish `count` more records without changing the resident set, so a
    /// replay and a genuinely new record differ only by position.
    fn publish(&mut self, count: u64) {
        self.producer_pos += FAKE_RECORD_STRIDE * count;
    }
}

impl RingBufCursor for ReplayingRingBuf {
    fn producer_position(&self) -> u64 {
        self.producer_pos
    }

    fn consumer_position(&self) -> u64 {
        self.consumer_pos
    }

    fn with_next_record<R, F: FnOnce(&[u8]) -> R>(&mut self, f: F) -> Option<R> {
        if self.busy_at == Some(self.consumer_pos) {
            return None;
        }
        let slot = ((self.consumer_pos - self.base) / FAKE_RECORD_STRIDE) as usize;
        let record = self.records[slot % self.records.len()].clone();
        self.consumer_pos += FAKE_RECORD_STRIDE;
        let result = f(record.as_slice());
        self.delivered.push(record);
        if let Some((nth, count)) = self.publish_after_take
            && self.delivered.len() == nth
        {
            self.publish(count);
        }
        Some(result)
    }
}

fn rtt_record_bytes(srtt_us: u64) -> Vec<u8> {
    use ferrum_ebpf_common::SOCK_OPS_EVENT_RTT_SAMPLE;

    let record = SockOpsRecord {
        event_type: SOCK_OPS_EVENT_RTT_SAMPLE,
        direction: 0,
        drop_reason: 0,
        _pad: 0,
        value: srtt_us,
    };
    // SAFETY: `SockOpsRecord` is `#[repr(C)]` with an explicit `_pad`, so its
    // byte layout is the ringbuf wire format.
    let bytes: [u8; std::mem::size_of::<SockOpsRecord>()] = unsafe { std::mem::transmute(record) };
    bytes.to_vec()
}

fn resume(outstanding_bytes: u64) -> RingBufAttach {
    RingBufAttach::Resume { outstanding_bytes }
}

/// Drain with an explicit per-wakeup record budget.
fn drain_with_budget(
    ring: &mut ReplayingRingBuf,
    budget: u32,
    on_record: impl FnMut(&[u8]),
) -> DrainOutcome {
    drain_outstanding_records(ring, FAKE_RING_BYTES, budget, on_record)
}

/// Drain with the production per-wakeup record budget.
fn drain_all(ring: &mut ReplayingRingBuf, on_record: impl FnMut(&[u8])) -> DrainOutcome {
    drain_with_budget(ring, RINGBUF_DRAIN_RECORD_BUDGET, on_record)
}

fn drain_into(ring: &mut ReplayingRingBuf, consumer: &SockOpsConsumer) -> u32 {
    let outcome = drain_all(ring, |bytes: &[u8]| {
        if let Some(event) = SockOpsEvent::from_record_bytes(bytes) {
            consumer.handle_event(event);
        }
    });
    outcome.records
}

#[test]
fn outstanding_bytes_accepts_only_positions_a_live_ring_can_hold() {
    // A ring nobody has written yet.
    assert_eq!(ringbuf_outstanding_bytes(0, 0, FAKE_RING_BYTES), Some(0));
    // Caught up part-way through the ring's life.
    assert_eq!(
        ringbuf_outstanding_bytes(9_000, 9_000, FAKE_RING_BYTES),
        Some(0)
    );
    // An ordinary backlog.
    assert_eq!(
        ringbuf_outstanding_bytes(9_000, 8_968, FAKE_RING_BYTES),
        Some(32)
    );
    // Exactly full: the kernel drops rather than overwrite unconsumed data,
    // so this is the largest backlog a live ring can present.
    assert_eq!(
        ringbuf_outstanding_bytes(FAKE_RING_BYTES, 0, FAKE_RING_BYTES),
        Some(FAKE_RING_BYTES)
    );
    // Behind by more than a whole ring — impossible for a live producer.
    assert_eq!(
        ringbuf_outstanding_bytes(FAKE_RING_BYTES + 32, 0, FAKE_RING_BYTES),
        None
    );
    // Ahead of the producer: the state a replaying consumer leaves behind,
    // and the state that makes every kernel reserve underflow and drop.
    assert_eq!(
        ringbuf_outstanding_bytes(9_000, 9_032, FAKE_RING_BYTES),
        None
    );
}

#[test]
fn attach_resynchronizes_only_an_unusable_consumer_position() {
    assert_eq!(
        ringbuf_attach(0, 0, FAKE_RING_BYTES),
        resume(0),
        "a freshly pinned ring is resumable"
    );
    assert_eq!(
        ringbuf_attach(123_456, 123_424, FAKE_RING_BYTES),
        resume(32),
        "a predecessor's position with a real backlog is resumable"
    );
    assert_eq!(
        ringbuf_attach(123_456, 123_488, FAKE_RING_BYTES),
        RingBufAttach::Resynchronize,
        "a consumer position past the producer must be repaired"
    );
    assert_eq!(
        ringbuf_attach(FAKE_RING_BYTES * 2, 0, FAKE_RING_BYTES),
        RingBufAttach::Resynchronize,
        "a position stale by more than a whole ring must be repaired"
    );
}

/// The headline regression for issue #5563: a consumer attaching to a
/// pre-filled ring drains it exactly once, a wakeup that finds nothing new
/// adds nothing, and records published afterwards are still observed.
#[test]
fn a_prefilled_ring_drains_exactly_once_and_then_stays_quiet() {
    let consumer = SockOpsConsumer::new(BpfMetricsState::new());
    let resident: Vec<Vec<u8>> = (1..=4).map(|i| rtt_record_bytes(i * 100)).collect();
    // A predecessor pod left the consumer position well past zero, and the
    // ring filled up behind it before this consumer attached.
    let mut ring = ReplayingRingBuf::with_resident(1_000_000, resident.clone());

    let drained = drain_into(&mut ring, &consumer);

    assert_eq!(drained, 4, "every resident record is delivered");
    assert_eq!(ring.delivered, resident, "and delivered exactly once");
    assert_eq!(ring.consumer_position(), ring.producer_position());
    let after_first_drain = consumer.metrics().snapshot();
    assert_eq!(after_first_drain.ringbuf_events_consumed, 4);
    assert_eq!(after_first_drain.srtt_count, 4);
    assert_eq!(after_first_drain.srtt_sample_us_sum, 100 + 200 + 300 + 400);

    // A wakeup with nothing new behind the producer must add nothing, even
    // though the cursor would happily keep handing back resident records.
    for _ in 0..3 {
        let drained = drain_into(&mut ring, &consumer);
        assert_eq!(drained, 0, "a spurious wakeup must not replay the ring");
    }
    assert_eq!(ring.delivered.len(), 4);
    let after_spurious = consumer.metrics().snapshot();
    assert_eq!(after_spurious.ringbuf_events_consumed, 4);
    assert_eq!(
        after_spurious.srtt_sample_us_sum, after_first_drain.srtt_sample_us_sum,
        "a replay would rescale every counter at once"
    );

    // Forward progress survives the overflow: new records are still drained.
    ring.publish(2);
    let drained = drain_into(&mut ring, &consumer);
    assert_eq!(drained, 2, "the consumer keeps making forward progress");
    assert_eq!(consumer.metrics().snapshot().ringbuf_events_consumed, 6);
}

/// The producer may commit more while a pass is running, and a ringbuf wakeup
/// only fires on commit. A pass that made progress therefore has to re-read
/// the producer position before concluding the ring is empty.
#[test]
fn a_pass_re_reads_the_producer_position_after_making_progress() {
    let resident: Vec<Vec<u8>> = (1..=2).map(rtt_record_bytes).collect();
    let mut ring = ReplayingRingBuf::with_resident(4_096, resident);
    ring.publish_after_take = Some((1, 2));
    let mut seen = 0u32;

    let drained = drain_all(&mut ring, |_bytes: &[u8]| {
        seen += 1;
    });

    assert_eq!(drained.records, 4, "late records drain in the same wakeup");
    assert_eq!(seen, 4);
    assert_eq!(ring.consumer_position(), ring.producer_position());
}

/// A record the producer has not committed yet halts the pass without losing
/// the consumer position; the next drain resumes from exactly there.
#[test]
fn an_uncommitted_record_halts_the_pass_and_the_next_drain_resumes() {
    let resident: Vec<Vec<u8>> = (1..=4).map(rtt_record_bytes).collect();
    let mut ring = ReplayingRingBuf::with_resident(64, resident);
    ring.busy_at = Some(64 + FAKE_RECORD_STRIDE * 2);

    let drained = drain_all(&mut ring, |_bytes: &[u8]| {});
    assert_eq!(
        drained.records, 2,
        "the pass stops at the uncommitted record"
    );
    assert!(!drained.budget_exhausted);
    assert_eq!(ring.consumer_position(), 64 + FAKE_RECORD_STRIDE * 2);

    ring.busy_at = None;
    let drained = drain_all(&mut ring, |_bytes: &[u8]| {});
    assert_eq!(
        drained.records, 2,
        "the rest drains once the producer commits"
    );
    assert_eq!(ring.delivered.len(), 4, "and nothing was delivered twice");
}

/// A consumer position that already ran past the producer — the state the
/// replay defect leaves on a pinned map, and the state in which the kernel
/// drops every record it tries to reserve — must deliver nothing, and attach
/// must classify it as needing repair.
#[test]
fn a_consumer_position_past_the_producer_drains_nothing() {
    let consumer = SockOpsConsumer::new(BpfMetricsState::new());
    let resident: Vec<Vec<u8>> = (1..=4).map(rtt_record_bytes).collect();
    let mut ring = ReplayingRingBuf::with_resident(0, resident);
    ring.consumer_pos = ring.producer_pos + FAKE_RECORD_STRIDE;

    let drained = drain_into(&mut ring, &consumer);

    assert_eq!(drained, 0);
    assert!(ring.delivered.is_empty());
    assert_eq!(consumer.metrics().snapshot().ringbuf_events_consumed, 0);

    let producer_pos = ring.producer_position();
    let consumer_pos = ring.consumer_position();
    assert_eq!(
        ringbuf_attach(producer_pos, consumer_pos, FAKE_RING_BYTES),
        RingBufAttach::Resynchronize,
        "attach must republish the producer position to un-wedge the ring"
    );
}

/// The drain shares a `tokio::select!` with the drop-reason poll, the
/// first-byte cleanup sweep and the pin-inode check. A node producing events
/// at or above the drain rate would otherwise keep the readable arm resident
/// forever, which is exactly how the kernel per-CPU bypass counters went
/// unread for a whole live-datapath window. The budget caps one wakeup and
/// the next one resumes from the committed consumer position.
#[test]
fn a_drain_pass_stops_at_its_budget_and_the_next_one_resumes() {
    let resident: Vec<Vec<u8>> = (1..=4).map(rtt_record_bytes).collect();
    let mut ring = ReplayingRingBuf::with_resident(4_096, resident.clone());

    let first = drain_with_budget(&mut ring, 2, |_bytes: &[u8]| {});
    assert_eq!(first.records, 2, "the budget stops the pass");
    assert!(
        first.budget_exhausted,
        "the caller must retain ringbuf readiness"
    );
    assert!(!first.needs_resynchronize);
    assert_eq!(ring.consumer_position(), 4_096 + FAKE_RECORD_STRIDE * 2);

    let second = drain_with_budget(&mut ring, 2, |_bytes: &[u8]| {});
    assert_eq!(second.records, 2, "the next drain resumes where it stopped");
    assert!(
        !second.budget_exhausted,
        "the ring is caught up, so readiness may be cleared"
    );
    assert_eq!(ring.delivered, resident, "delivered once, in ring order");
    assert_eq!(ring.consumer_position(), ring.producer_position());

    // A budget that exactly covers the backlog must not claim exhaustion:
    // nothing is left behind the producer to come back for.
    ring.publish(2);
    let exact = drain_with_budget(&mut ring, 2, |_bytes: &[u8]| {});
    assert_eq!(exact.records, 2);
    assert!(!exact.budget_exhausted);
}

/// A budget of zero would let the caller spin on a drain that can never take
/// a record, so it is raised to one.
#[test]
fn a_zero_record_budget_still_makes_forward_progress() {
    let resident: Vec<Vec<u8>> = (1..=2).map(rtt_record_bytes).collect();
    let mut ring = ReplayingRingBuf::with_resident(0, resident);

    let outcome = drain_with_budget(&mut ring, 0, |_bytes: &[u8]| {});

    assert_eq!(outcome.records, 1);
    assert!(outcome.budget_exhausted);
    assert_eq!(ring.consumer_position(), FAKE_RECORD_STRIDE);
}

/// `attach_events_ring` repairs an unusable consumer position at attach and
/// at pin rotation, but a ring that reaches that state mid-run used to stall
/// silently: the drain stopped, `Drained { events: 0 }` was recorded, and the
/// 30s inode check never fired because the pin did not rotate. The drain now
/// reports the condition so the consumer can re-attach through that same
/// repair.
#[test]
fn a_live_ring_that_runs_past_the_producer_asks_to_be_resynchronized() {
    let resident: Vec<Vec<u8>> = (1..=4).map(rtt_record_bytes).collect();
    let mut ring = ReplayingRingBuf::with_resident(0, resident);
    ring.consumer_pos = ring.producer_pos + FAKE_RECORD_STRIDE;

    let outcome = drain_all(&mut ring, |_bytes: &[u8]| {});

    assert_eq!(outcome.records, 0);
    assert!(!outcome.budget_exhausted);
    assert!(
        outcome.needs_resynchronize,
        "a position the ring cannot describe must not read as a quiet wakeup"
    );
    assert!(ring.delivered.is_empty());
    assert_eq!(
        ringbuf_attach(
            ring.producer_position(),
            ring.consumer_position(),
            FAKE_RING_BYTES
        ),
        RingBufAttach::Resynchronize,
        "the re-attach path classifies the same pair the drain reported"
    );
}

/// A ring that is merely caught up, or that stops on an uncommitted record,
/// is an ordinary quiet wakeup and must never trigger a re-attach.
#[test]
fn an_ordinary_drain_never_asks_to_be_resynchronized() {
    let resident: Vec<Vec<u8>> = (1..=3).map(rtt_record_bytes).collect();
    let mut ring = ReplayingRingBuf::with_resident(512, resident);
    ring.busy_at = Some(512 + FAKE_RECORD_STRIDE);

    let halted = drain_all(&mut ring, |_bytes: &[u8]| {});
    assert_eq!(halted.records, 1);
    assert!(!halted.needs_resynchronize);

    ring.busy_at = None;
    let rest = drain_all(&mut ring, |_bytes: &[u8]| {});
    assert_eq!(rest.records, 2);
    assert!(!rest.needs_resynchronize);

    let quiet = drain_all(&mut ring, |_bytes: &[u8]| {});
    assert_eq!(quiet.records, 0);
    assert!(!quiet.needs_resynchronize);
}

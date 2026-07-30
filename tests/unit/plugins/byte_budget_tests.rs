//! Shared observability byte-budget primitive tests.

use ferrum_edge::_test_support::{
    loki_logging_probe_batch_materialization_for_test, loki_logging_probe_payload_json_for_test,
    otel_tracing_probe_batch_materialization_for_test,
};
use ferrum_edge::plugins::utils::byte_budget::{
    ByteBudget, DEFAULT_BUFFER_MAX_BYTES, DEFAULT_MAX_ENTRY_BYTES, HARD_MAX_BUFFER_MAX_BYTES,
    HARD_MAX_ENTRY_BYTES, MIN_MAX_ENTRY_BYTES, PROCESS_MAX_RETAINED_BYTES_DEFAULT,
    PROCESS_MAX_RETAINED_BYTES_MAX, PROCESS_MAX_RETAINED_BYTES_MIN, PayloadMaterializationError,
    RetainedByteCeiling, admit_byte_limits, batch_materialization_fallbacks,
    batch_materialization_loss_events, batch_materialization_lost_records,
    materialize_reserved_payload, record_batch_materialization_fallback,
    record_batch_materialization_loss,
};
use ferrum_edge::plugins::utils::summary_log_budget::serialize_under_byte_budget;
use serde_json::json;
use std::io::Write;

#[test]
fn admit_byte_limits_defaults_and_bounds() {
    let defaults = admit_byte_limits(&json!({}), "probe").expect("defaults");
    assert_eq!(defaults.max_entry_bytes, DEFAULT_MAX_ENTRY_BYTES);
    assert_eq!(defaults.buffer_max_bytes, DEFAULT_BUFFER_MAX_BYTES);

    let err = admit_byte_limits(
        &json!({"max_entry_bytes": MIN_MAX_ENTRY_BYTES - 1}),
        "probe",
    )
    .expect_err("below minimum");
    assert!(err.contains("max_entry_bytes"), "{err}");

    let err = admit_byte_limits(
        &json!({"max_entry_bytes": HARD_MAX_ENTRY_BYTES + 1}),
        "probe",
    )
    .expect_err("above hard max");
    assert!(err.contains("max_entry_bytes"), "{err}");

    let err = admit_byte_limits(
        &json!({
            "max_entry_bytes": 2048,
            "buffer_max_bytes": 1024
        }),
        "probe",
    )
    .expect_err("buffer smaller than entry");
    assert!(err.contains("buffer_max_bytes"), "{err}");

    let err = admit_byte_limits(
        &json!({
            "max_entry_bytes": 2048,
            "buffer_max_bytes": HARD_MAX_BUFFER_MAX_BYTES + 1
        }),
        "probe",
    )
    .expect_err("buffer above hard max");
    assert!(err.contains("buffer_max_bytes"), "{err}");
}

#[test]
fn byte_budget_reserves_before_serialize_and_rejects_oversize() {
    let budget = ByteBudget::new("probe", 256);
    let held = budget.try_acquire(256).expect("fill budget");
    let rejected = serialize_under_byte_budget(&budget, 64, &json!({"k": "v"}));
    assert!(
        rejected.is_none(),
        "saturated budget must reject before retain"
    );
    assert!(budget.drops_total() > 0);
    drop(held);
    assert_eq!(budget.used(), 0);

    let admitted = serialize_under_byte_budget(&budget, 64, &json!({"k": "v"}))
        .expect("admission after release");
    assert!(admitted.as_bytes().len() <= 64);
    assert_eq!(budget.used(), (admitted.as_bytes().len() + 1) * 2);
    drop(admitted);
    assert_eq!(budget.used(), 0);
}

#[test]
fn byte_budget_rejects_hostile_serialized_length() {
    let budget = ByteBudget::new("probe", 1_024);
    let huge = "x".repeat(2_048);
    let rejected = serialize_under_byte_budget(&budget, 128, &json!({ "ua": huge }));
    assert!(rejected.is_none());
    assert_eq!(budget.used(), 0);
    assert!(budget.drops_total() > 0);
}

// ---------------------------------------------------------------------------
// Process-wide retained-byte ceiling (GHSA-83h5-52mw-f33p).
//
// Saturation coverage runs against a test-owned leaked `RetainedByteCeiling`
// so it can use a tiny ceiling without perturbing the process-global counter
// that other tests in this same binary reserve against. Coverage of the
// process-global path asserts *deltas*, which stay exact under concurrency.
// ---------------------------------------------------------------------------

fn test_ceiling(max_bytes: usize) -> &'static RetainedByteCeiling {
    let ceiling: &'static RetainedByteCeiling =
        Box::leak(Box::new(RetainedByteCeiling::new(max_bytes)));
    ceiling.set_max_unclamped_for_test(max_bytes);
    ceiling
}

#[test]
fn process_ceiling_rejects_past_the_total_and_releases_on_drop() {
    let ceiling = test_ceiling(1_024);

    let first = ceiling.try_acquire(768).expect("first reservation fits");
    assert_eq!(ceiling.used(), 768);

    // A second instance's admission is refused by the *aggregate* ceiling even
    // though it has taken nothing itself. This is the multi-instance clause:
    // N sinks cannot multiply past the process total.
    assert!(
        ceiling.try_acquire(512).is_none(),
        "aggregate ceiling must refuse the second instance"
    );
    assert_eq!(ceiling.rejections(), 1);
    assert_eq!(
        ceiling.used(),
        768,
        "a refused reservation must not charge the ceiling"
    );

    // Exactly-at-the-ceiling still fits; one byte more does not.
    let second = ceiling.try_acquire(256).expect("exact fit admitted");
    assert_eq!(ceiling.used(), 1_024);
    assert!(ceiling.try_acquire(1).is_none());
    assert_eq!(ceiling.rejections(), 2);

    assert_eq!(ceiling.high_water(), 1_024);

    drop(second);
    assert_eq!(ceiling.used(), 768, "drop releases exactly its own bytes");
    drop(first);
    assert_eq!(ceiling.used(), 0, "all permits released");

    // Capacity recovers without waiting for shutdown.
    let after = ceiling.try_acquire(1_024).expect("capacity recovered");
    assert_eq!(ceiling.used(), 1_024);
    drop(after);
    assert_eq!(ceiling.used(), 0);
    assert_eq!(
        ceiling.high_water(),
        1_024,
        "high water is a peak, not a live gauge"
    );
}

#[test]
fn process_ceiling_shrink_releases_only_the_unused_delta() {
    let ceiling = test_ceiling(4_096);

    // Sinks reserve a provisional `max_entry_bytes` lease *before* serializing,
    // then shrink to the measured size. Only the unused delta comes back.
    let lease = ceiling.try_acquire(4_096).expect("provisional reservation");
    assert_eq!(ceiling.used(), 4_096);
    lease.shrink_to(100);
    assert_eq!(ceiling.used(), 100);
    assert_eq!(lease.reserved(), 100);

    // Shrinking upward is a no-op: a lease can never silently grow its charge.
    lease.shrink_to(4_000);
    assert_eq!(ceiling.used(), 100);

    // Release is idempotent, so a double release cannot underflow the counter.
    lease.release();
    assert_eq!(ceiling.used(), 0);
    lease.release();
    assert_eq!(ceiling.used(), 0);
    drop(lease);
    assert_eq!(ceiling.used(), 0);

    // Freed capacity is reusable in full.
    let reused = ceiling.try_acquire(4_096).expect("full capacity reusable");
    assert_eq!(ceiling.used(), 4_096);
    drop(reused);
}

#[test]
fn zero_byte_reservations_are_free_and_never_rejected() {
    let ceiling = test_ceiling(16);
    let filled = ceiling.try_acquire(16).expect("fill");
    let free = ceiling
        .try_acquire(0)
        .expect("zero-byte reservations always succeed");
    assert_eq!(ceiling.used(), 16);
    assert_eq!(free.reserved(), 0);
    assert_eq!(ceiling.rejections(), 0);
    drop(free);
    assert_eq!(ceiling.used(), 16);
    drop(filled);
}

#[test]
fn per_instance_byte_budget_also_charges_the_shared_ceiling() {
    // A `ByteBudget` reservation must show up in aggregate accounting;
    // otherwise per-instance budgets would be the only bound and N instances
    // would multiply.
    let ceiling = test_ceiling(1 << 20);
    let budget = ByteBudget::with_ceiling("probe", 4_096, ceiling);

    let lease = budget.try_acquire(1_024).expect("admitted");
    assert_eq!(budget.used(), 1_024);
    assert_eq!(
        ceiling.used(),
        1_024,
        "per-instance reservation must also charge the shared ceiling"
    );

    // Shrink propagates to both counters in lockstep.
    lease.shrink_to(256);
    assert_eq!(budget.used(), 256);
    assert_eq!(ceiling.used(), 256);

    drop(lease);
    assert_eq!(budget.used(), 0);
    assert_eq!(
        ceiling.used(),
        0,
        "dropping the lease must release the ceiling reservation too"
    );
}

#[test]
fn generic_byte_budget_does_not_charge_the_observability_ceiling() {
    let ceiling = test_ceiling(16);
    let observability = ByteBudget::with_ceiling("http_logging", 16, ceiling);
    let cache = ByteBudget::new("ai_semantic_cache", 16);

    let cache_lease = cache.try_acquire(16).expect("cache admission");
    assert_eq!(
        ceiling.used(),
        0,
        "cache bytes must not consume log capacity"
    );

    let log_lease = observability
        .try_acquire(16)
        .expect("observability admission remains available");
    assert_eq!(ceiling.used(), 16);

    drop(log_lease);
    drop(cache_lease);
    assert_eq!(ceiling.used(), 0);
    assert_eq!(cache.used(), 0);
}

#[test]
fn two_instances_cannot_exceed_the_shared_ceiling_between_them() {
    // The multi-instance clause: each sink is individually within its own
    // budget, yet the process total still holds.
    let ceiling = test_ceiling(4_096);
    let first = ByteBudget::with_ceiling("probe_a", 4_096, ceiling);
    let second = ByteBudget::with_ceiling("probe_b", 4_096, ceiling);

    let held = first.try_acquire(4_096).expect("first instance fills");
    assert_eq!(ceiling.used(), 4_096);

    // The second instance's own budget is entirely free, but the aggregate is
    // not, so admission is refused and nothing is retained.
    assert!(
        second.try_acquire(1).is_none(),
        "the shared ceiling must refuse a second instance"
    );
    assert_eq!(second.used(), 0, "a refused admission charges nothing");
    assert!(second.drops_total() > 0, "the refusal is accounted");
    assert_eq!(ceiling.rejections(), 1);

    drop(held);
    assert_eq!(ceiling.used(), 0);
    let recovered = second.try_acquire(4_096).expect("capacity recovered");
    assert_eq!(ceiling.used(), 4_096);
    drop(recovered);
}

#[test]
fn serialize_under_byte_budget_releases_the_ceiling_reservation_on_rejection() {
    // A record refused for exceeding `max_entry_bytes` must leave *neither*
    // counter charged: rejection happens before the payload is retained, and
    // the provisional ceiling reservation is handed back.
    let ceiling = test_ceiling(1 << 20);
    let budget = ByteBudget::with_ceiling("probe", 1_048_576, ceiling);
    let hostile = "x".repeat(8_192);

    let rejected = serialize_under_byte_budget(&budget, 1_024, &json!({ "ua": hostile }));
    assert!(rejected.is_none(), "oversize record must be refused");
    assert_eq!(budget.used(), 0);
    assert_eq!(
        ceiling.used(),
        0,
        "a refused record must not leak a ceiling reservation"
    );

    // The admitted path charges both counters and releases both on drop.
    let admitted =
        serialize_under_byte_budget(&budget, 1_024, &json!({"k": "v"})).expect("small record fits");
    assert!(ceiling.used() > 0);
    assert_eq!(
        ceiling.used(),
        budget.used(),
        "both counters must agree after the lease shrinks to the measured size"
    );
    drop(admitted);
    assert_eq!(ceiling.used(), 0);
    assert_eq!(budget.used(), 0);
}

#[test]
fn a_saturated_ceiling_refuses_before_the_record_is_serialized() {
    // Admission-before-materialization: with the ceiling already full, the
    // hostile payload is never serialized, so nothing is retained anywhere.
    // 262_144 comfortably admits one 65_536-byte entry's accounted charge
    // ((65_536 + 1) * 2 = 131_074) once the ceiling drains again.
    let ceiling = test_ceiling(262_144);
    let budget = ByteBudget::with_ceiling("probe", 1_048_576, ceiling);
    let filled = ceiling.try_acquire(262_144).expect("saturate the ceiling");

    let hostile = "x".repeat(16_384);
    let rejected = serialize_under_byte_budget(&budget, 65_536, &json!({ "ua": hostile }));
    assert!(rejected.is_none(), "saturated ceiling must refuse");
    assert_eq!(budget.used(), 0);
    assert_eq!(
        ceiling.used(),
        262_144,
        "only the pre-existing hold remains"
    );
    assert!(budget.drops_total() > 0);

    drop(filled);
    assert_eq!(ceiling.used(), 0);
    assert!(
        serialize_under_byte_budget(&budget, 65_536, &json!({"k": "v"})).is_some(),
        "admission resumes once the ceiling drains"
    );
}

#[test]
fn process_ceiling_config_bounds_are_clamped_not_silently_accepted() {
    let ceiling = test_ceiling(PROCESS_MAX_RETAINED_BYTES_DEFAULT);

    ceiling.set_max(0);
    assert_eq!(
        ceiling.max(),
        PROCESS_MAX_RETAINED_BYTES_MIN,
        "an unsafely small ceiling is raised to the documented minimum"
    );

    ceiling.set_max(usize::MAX);
    assert_eq!(
        ceiling.max(),
        PROCESS_MAX_RETAINED_BYTES_MAX,
        "an unbounded ceiling is capped at the documented maximum"
    );

    ceiling.set_max(PROCESS_MAX_RETAINED_BYTES_DEFAULT);
    assert_eq!(ceiling.max(), PROCESS_MAX_RETAINED_BYTES_DEFAULT);

    // The documented bounds must stay mutually consistent, and the default
    // process total must admit at least one maximally configured sink
    // instance, or a single legal instance could never fill its budget. These
    // are asserted against the ceiling's *installed* maximum rather than the
    // constant, so the check exercises real state instead of folding away.
    let installed_default = ceiling.max();
    assert!(PROCESS_MAX_RETAINED_BYTES_MIN < installed_default);
    assert!(installed_default <= PROCESS_MAX_RETAINED_BYTES_MAX);
    assert!(HARD_MAX_BUFFER_MAX_BYTES <= installed_default);
}

// ---------------------------------------------------------------------------
// Bounded batch materialization (GHSA-83h5-52mw-f33p root review).
//
// A queued entry's lease covers the entry. The contiguous wire payload, any
// intermediate `serde_json::Value`, and any compressed buffer are *additional*
// attacker-shaped copies that coexist with the still-charged queue, so they must
// be reserved before they are materialized and released on every terminal path.
// ---------------------------------------------------------------------------

#[test]
fn batch_materialization_is_charged_for_the_payload_lifetime_and_released_on_drop() {
    let ceiling = test_ceiling(64 * 1024);

    let payload = materialize_reserved_payload(ceiling, 64 * 1024, |writer| {
        writer
            .write_all(&b"x".repeat(1_000))
            .map_err(|error| error.to_string())
    })
    .expect("payload fits the ceiling");

    assert_eq!(payload.len(), 1_000);
    // Provisional `bound` is reserved before the write; afterwards the charge
    // shrinks to the buffer's exact retained capacity (framing/escaping
    // included). A 1_000-byte body must not keep a 64 KiB provisional bound
    // pinned for the delivery lifetime.
    let held = ceiling.used();
    assert!(held >= 1_000, "exact charge must cover the written body: held={held}");
    assert!(
        held < 16 * 1024,
        "exact charge must release unused provisional headroom: held={held}"
    );

    // Retries reuse the same immutable bytes rather than re-serializing.
    let first = payload.bytes();
    let second = payload.bytes();
    assert_eq!(first, second);
    assert_eq!(
        ceiling.used(),
        held,
        "a retry handle must not add a second charge"
    );
    drop(first);
    drop(second);
    assert_eq!(ceiling.used(), held);

    drop(payload);
    assert_eq!(
        ceiling.used(),
        0,
        "the materialization reservation releases exactly once, with no underflow"
    );
}

#[test]
fn batch_materialization_refuses_before_writing_when_the_ceiling_is_exhausted() {
    let ceiling = test_ceiling(4_096);
    let queued = ceiling.try_acquire(4_000).expect("queued entries fit");
    let rejections_before = ceiling.rejections();

    let refused = materialize_reserved_payload(ceiling, 2_048, |_writer| {
        panic!("the writer must never run once the ceiling refuses the bound");
    });
    assert_eq!(
        refused.unwrap_err(),
        PayloadMaterializationError::CeilingExhausted
    );
    assert_eq!(
        ceiling.used(),
        4_000,
        "a refused materialization must not charge the ceiling"
    );
    assert_eq!(ceiling.rejections(), rejections_before + 1);

    drop(queued);
    assert_eq!(ceiling.used(), 0);
}

#[test]
fn batch_materialization_fails_closed_when_a_write_exceeds_its_bound() {
    let ceiling = test_ceiling(64 * 1024);

    let overrun = materialize_reserved_payload(ceiling, 512, |writer| {
        // Hostile payload: three times the reserved bound.
        writer
            .write_all(&b"y".repeat(1_536))
            .map_err(|error| error.to_string())
    });
    assert_eq!(
        overrun.unwrap_err(),
        PayloadMaterializationError::BoundExceeded
    );
    assert_eq!(
        ceiling.used(),
        0,
        "a bound overrun releases the reservation instead of leaking it"
    );

    let failed = materialize_reserved_payload(ceiling, 512, |_writer| {
        Err("synthetic serializer failure".to_string())
    });
    assert_eq!(
        failed.unwrap_err(),
        PayloadMaterializationError::WriteFailed
    );
    assert_eq!(ceiling.used(), 0);
}

#[test]
fn batch_materialization_reasons_are_fixed_labels() {
    for error in [
        PayloadMaterializationError::BoundOverflowed,
        PayloadMaterializationError::CeilingExhausted,
        PayloadMaterializationError::BoundExceeded,
        PayloadMaterializationError::WriteFailed,
    ] {
        let reason = error.reason();
        assert!(!reason.is_empty());
        assert_eq!(reason, error.to_string(), "Display must be the fixed label");
        assert!(
            reason.is_ascii() && !reason.contains('\n'),
            "diagnostics must stay a single fixed ASCII label: {reason}"
        );
    }
}

#[test]
fn concurrent_instances_cannot_multiply_batch_materialization_past_the_ceiling() {
    let ceiling = test_ceiling(32 * 1024);

    let first = materialize_reserved_payload(ceiling, 24 * 1024, |writer| {
        // Fill the provisional bound so the exact retained charge still saturates
        // enough of the ceiling to refuse a second concurrent instance.
        writer
            .write_all(&vec![b'x'; 24 * 1024])
            .map_err(|error| error.to_string())
    })
    .expect("first instance's batch fits");
    assert_eq!(
        ceiling.used(),
        24 * 1024,
        "a full-bound body keeps its exact retained charge"
    );

    // A second sink instance's batch is refused by the aggregate ceiling even
    // though its own per-instance budget is untouched.
    let second = materialize_reserved_payload(ceiling, 24 * 1024, |_writer| {
        panic!("the second instance must be refused before it materializes anything");
    });
    assert_eq!(
        second.unwrap_err(),
        PayloadMaterializationError::CeilingExhausted
    );

    drop(first);
    assert_eq!(ceiling.used(), 0);
    assert!(
        materialize_reserved_payload(ceiling, 24 * 1024, |writer| {
            writer
                .write_all(b"second")
                .map_err(|error| error.to_string())
        })
        .is_ok(),
        "the second instance is admitted once the first releases"
    );
}

// ---------------------------------------------------------------------------
// Loki batch materialization.
// ---------------------------------------------------------------------------

#[test]
fn loki_batch_body_is_charged_alongside_the_queued_entries() {
    for gzip in [false, true] {
        let ceiling = test_ceiling(8 * 1024 * 1024);
        let (queued, peak, after_body, after_release, refused, _rejections, encoding, _grouping) =
            loki_logging_probe_batch_materialization_for_test(ceiling, 16, 4_096, gzip, 1)
                .expect("probe ran");

        assert!(!refused, "an 8 MiB ceiling must admit a 64 KiB batch");
        assert!(queued > 0, "queued entries must charge the ceiling");
        assert!(
            peak > queued,
            "the wire body must add its own charge (queued={queued}, peak={peak}, gzip={gzip})"
        );
        assert_eq!(
            after_body, queued,
            "dropping the body releases exactly the materialization charge"
        );
        assert_eq!(
            after_release, 0,
            "releasing the queued entries drains the ceiling with no underflow"
        );
        assert_eq!(encoding, if gzip { Some("gzip") } else { None });
    }
}

#[test]
fn loki_batch_body_is_refused_rather_than_materialized_under_a_saturated_ceiling() {
    // Enough headroom for the queued entries, far too little for the batch's
    // own doubled-by-escaping JSON representation.
    let ceiling = test_ceiling(200_000);
    let (queued, peak, _after_body, after_release, refused, rejections, encoding, _grouping) =
        loki_logging_probe_batch_materialization_for_test(ceiling, 16, 8_192, false, 1)
            .expect("probe ran");

    assert!(refused, "the batch body must be refused, not materialized");
    assert_eq!(encoding, None);
    assert_eq!(
        peak, queued,
        "a refused body must not charge the ceiling at all"
    );
    assert!(rejections > 0, "the refusal must be counted");
    assert_eq!(after_release, 0);
}

// ---------------------------------------------------------------------------
// Loki label grouping — GHSA-83h5-52mw-f33p.
//
// A hostile client can manufacture a new dynamic label set per entry. The
// grouping representation must therefore be charged to the ceiling like every
// other batch-scale allocation, and must not scale with the number of *distinct*
// label sets.
// ---------------------------------------------------------------------------

/// Entry count used by the grouping regressions. Every entry carries its own
/// label set, which is the worst case for grouping.
const LOKI_GROUPING_ENTRIES: usize = 256;

#[test]
fn loki_label_grouping_is_charged_to_the_ceiling() {
    let ceiling = test_ceiling(8 * 1024 * 1024);
    let (queued, peak, _after_body, after_release, refused, _rejections, _encoding, grouping) =
        loki_logging_probe_batch_materialization_for_test(
            ceiling,
            LOKI_GROUPING_ENTRIES,
            256,
            false,
            LOKI_GROUPING_ENTRIES,
        )
        .expect("probe ran");

    assert!(!refused, "an 8 MiB ceiling must admit this batch");
    assert!(peak > queued);
    assert_eq!(after_release, 0);
    // One `usize` per entry — independent of how many distinct label sets the
    // batch contains.
    assert_eq!(
        grouping,
        LOKI_GROUPING_ENTRIES * std::mem::size_of::<usize>(),
        "grouping must scale with the entry count, not the label-set count"
    );

    // `peak` is observed after the write returns, so the grouping index is
    // already released: a ceiling of exactly `peak` leaves room for the queued
    // entries and the reserved body but *not* for the grouping index. The old
    // uncharged grouping path would have sailed through this ceiling.
    let tight = test_ceiling(peak);
    let (_, _, _, tight_after_release, tight_refused, tight_rejections, _, _) =
        loki_logging_probe_batch_materialization_for_test(
            tight,
            LOKI_GROUPING_ENTRIES,
            256,
            false,
            LOKI_GROUPING_ENTRIES,
        )
        .expect("probe ran");
    assert!(
        tight_refused,
        "the grouping representation must be reserved, not built for free"
    );
    assert!(tight_rejections > 0);
    assert_eq!(tight_after_release, 0, "a refused grouping leaks nothing");

    // One grouping index of extra headroom is all it takes to admit the batch.
    let exact = test_ceiling(peak + grouping);
    let (_, _, _, exact_after_release, exact_refused, _, _, _) =
        loki_logging_probe_batch_materialization_for_test(
            exact,
            LOKI_GROUPING_ENTRIES,
            256,
            false,
            LOKI_GROUPING_ENTRIES,
        )
        .expect("probe ran");
    assert!(
        !exact_refused,
        "the reserved grouping bound must be exact, not merely conservative"
    );
    assert_eq!(exact_after_release, 0);
}

#[test]
fn loki_grouping_semantics_survive_many_distinct_label_sets() {
    // Four label sets over twelve entries: three entries per stream, and the
    // per-stream order must be the original queue order.
    let payload = loki_logging_probe_payload_json_for_test(12, 4).expect("payload");
    let payload: serde_json::Value = serde_json::from_str(&payload).expect("valid JSON");
    let streams = payload["streams"].as_array().expect("streams array");
    assert_eq!(streams.len(), 4, "one stream per distinct label set");

    let mut seen_labels = std::collections::BTreeSet::new();
    let mut timestamps: Vec<u128> = Vec::new();
    for stream in streams {
        let labels = stream["stream"].as_object().expect("label object");
        assert!(
            seen_labels.insert(serde_json::to_string(labels).expect("labels")),
            "each label set must be emitted exactly once"
        );
        let values = stream["values"].as_array().expect("values array");
        assert_eq!(values.len(), 3, "entries must not be dropped or duplicated");
        for value in values {
            let timestamp: u128 = value[0]
                .as_str()
                .expect("timestamp string")
                .parse()
                .expect("nanosecond timestamp");
            timestamps.push(timestamp);
        }
    }

    // Timestamps are assigned in write order and must be strictly increasing.
    assert_eq!(timestamps.len(), 12);
    assert!(
        timestamps.windows(2).all(|pair| pair[0] < pair[1]),
        "Loki requires strictly monotonic per-push timestamps: {timestamps:?}"
    );

    // A single label set still collapses into one stream.
    let single = loki_logging_probe_payload_json_for_test(12, 1).expect("payload");
    let single: serde_json::Value = serde_json::from_str(&single).expect("valid JSON");
    assert_eq!(single["streams"].as_array().expect("streams").len(), 1);

    // Determinism: the same batch shape produces byte-identical grouping.
    let repeat = loki_logging_probe_payload_json_for_test(12, 4).expect("payload");
    let repeat: serde_json::Value = serde_json::from_str(&repeat).expect("valid JSON");
    let labels_of = |value: &serde_json::Value| -> Vec<String> {
        value["streams"]
            .as_array()
            .expect("streams")
            .iter()
            .map(|stream| serde_json::to_string(&stream["stream"]).expect("labels"))
            .collect()
    };
    assert_eq!(
        labels_of(&payload),
        labels_of(&repeat),
        "stream emission order must be deterministic"
    );
}

// ---------------------------------------------------------------------------
// Batch-materialization loss accounting — GHSA-83h5-52mw-f33p.
//
// The counters below are process-global statics that other tests in this binary
// touch concurrently, so every assertion is a lower-bound delta.
// ---------------------------------------------------------------------------

#[test]
fn batch_materialization_loss_accounting_counts_records_separately_from_events() {
    let records_before = batch_materialization_lost_records();
    let events_before = batch_materialization_loss_events();
    let fallbacks_before = batch_materialization_fallbacks();

    // One event that lost seven records: a reservation-rejection count could
    // never express this, which is why the two must not be conflated.
    record_batch_materialization_loss("probe_sink", 7, "probe reason");

    assert!(
        batch_materialization_lost_records() >= records_before + 7,
        "the record-scale counter must advance by the records lost"
    );
    assert!(
        batch_materialization_loss_events() > events_before,
        "the event counter must advance by one, not by seven"
    );

    // A degraded-but-complete delivery is a fallback, never a loss.
    let records_after_loss = batch_materialization_lost_records();
    record_batch_materialization_fallback("probe_sink", "probe reason");
    assert!(batch_materialization_fallbacks() > fallbacks_before);
    assert!(
        batch_materialization_lost_records() >= records_after_loss,
        "a fallback must never decrement the loss counter"
    );
}

// ---------------------------------------------------------------------------
// OTel / Zipkin / Datadog trace batch materialization.
// ---------------------------------------------------------------------------

#[test]
fn trace_batch_body_is_charged_alongside_the_queued_spans() {
    let ceiling = test_ceiling(64 * 1024 * 1024);
    let (queued, peak, after_body, after_release, refused, _rejections) =
        otel_tracing_probe_batch_materialization_for_test(ceiling, 8, 2_048).expect("probe ran");

    assert!(!refused);
    assert!(queued > 0, "queued spans must charge the ceiling");
    assert!(
        peak > queued,
        "the `Value` tree and serialized body must add their own charge \
         (queued={queued}, peak={peak})"
    );
    assert_eq!(
        after_body, queued,
        "dropping the body releases exactly the materialization charge"
    );
    assert_eq!(after_release, 0, "no reservation leaks and none underflows");
}

#[test]
fn trace_batch_body_is_refused_rather_than_materialized_under_a_saturated_ceiling() {
    // Enough for the queued span, nowhere near enough for the batch's `Value`
    // tree, and a single-span slice cannot be halved into admission either.
    let ceiling = test_ceiling(12_000);
    let (queued, peak, _after_body, after_release, refused, rejections) =
        otel_tracing_probe_batch_materialization_for_test(ceiling, 1, 4_096).expect("probe ran");

    assert!(refused, "the batch body must be refused, not materialized");
    assert_eq!(
        peak, queued,
        "a refused body must not charge the ceiling at all"
    );
    assert!(rejections > 0);
    assert_eq!(after_release, 0);
}

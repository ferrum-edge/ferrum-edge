//! Shared observability byte-budget primitive tests.

use ferrum_edge::plugins::utils::byte_budget::{
    ByteBudget, DEFAULT_BUFFER_MAX_BYTES, DEFAULT_MAX_ENTRY_BYTES, HARD_MAX_BUFFER_MAX_BYTES,
    HARD_MAX_ENTRY_BYTES, MIN_MAX_ENTRY_BYTES, admit_byte_limits,
};
use ferrum_edge::plugins::utils::summary_log_budget::serialize_under_byte_budget;
use serde_json::json;

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

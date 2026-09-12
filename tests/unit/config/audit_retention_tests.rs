//! Unit coverage for admin audit-event retention (#2996).
//!
//! Behavioral SQLite coverage lives in
//! `tests/integration/audit_retention_tests.rs`. This module locks config
//! validation and SQL/Mongo source parity for the shared retention contract.

use ferrum_edge::admin::audit::{
    AUDIT_MAX_ROWS_PRUNE_GATES_CAP, AUDIT_RETENTION_DAYS_MAX, AUDIT_RETENTION_MAX_ROWS_CAP,
    AUDIT_RETENTION_MAX_ROWS_CHECK_INTERVAL, AUDIT_RETENTION_MAX_ROWS_DEFAULT,
    AUDIT_RETENTION_PRUNE_BATCH_SIZE, AUDIT_RETENTION_PRUNE_MAX_BATCHES, AuditMaxRowsPruneGate,
    AuditRetentionPolicy, audit_max_rows_prune_gate_should_run,
    audit_retention_hit_prune_batch_budget, audit_retention_max_rows_check_interval,
};
use ferrum_edge::config::EnvConfig;
use std::sync::Arc;

use crate::unit::env_lock::with_env_vars;

const DB_LOADER_SOURCE: &str = include_str!("../../../src/config/db_loader.rs");
const MONGO_INDEX_PLAN_SOURCE: &str = include_str!("../../../src/config/mongo_index_plan.rs");
const MONGO_STORE_SOURCE: &str = include_str!("../../../src/config/mongo_store.rs");
const AUDIT_SOURCE: &str = include_str!("../../../src/admin/audit.rs");

#[test]
fn audit_retention_policy_defaults_to_a_namespace_cap() {
    let policy = AuditRetentionPolicy::default();
    assert!(policy.is_enabled());
    assert_eq!(policy.retention_days, None);
    assert_eq!(
        policy.max_rows_per_namespace,
        Some(AUDIT_RETENTION_MAX_ROWS_DEFAULT)
    );
}

#[test]
fn audit_retention_policy_accepts_safe_bounds() {
    let policy = AuditRetentionPolicy::from_parts(Some(90), Some(100_000)).unwrap();
    assert!(policy.is_enabled());
    assert_eq!(policy.retention_days, Some(90));
    assert_eq!(policy.max_rows_per_namespace, Some(100_000));

    let days_only = AuditRetentionPolicy::from_parts(Some(AUDIT_RETENTION_DAYS_MAX), None).unwrap();
    assert_eq!(days_only.retention_days, Some(AUDIT_RETENTION_DAYS_MAX));

    let rows_only =
        AuditRetentionPolicy::from_parts(None, Some(AUDIT_RETENTION_MAX_ROWS_CAP)).unwrap();
    assert_eq!(
        rows_only.max_rows_per_namespace,
        Some(AUDIT_RETENTION_MAX_ROWS_CAP)
    );
}

#[test]
fn audit_retention_policy_rejects_zero_days_and_oversize() {
    let zero_days = AuditRetentionPolicy::from_parts(Some(0), None).unwrap_err();
    assert!(
        zero_days.contains("FERRUM_AUDIT_RETENTION_DAYS"),
        "got: {zero_days}"
    );

    let over_days =
        AuditRetentionPolicy::from_parts(Some(AUDIT_RETENTION_DAYS_MAX + 1), None).unwrap_err();
    assert!(
        over_days.contains("FERRUM_AUDIT_RETENTION_DAYS"),
        "got: {over_days}"
    );

    let over_rows =
        AuditRetentionPolicy::from_parts(None, Some(AUDIT_RETENTION_MAX_ROWS_CAP + 1)).unwrap_err();
    assert!(
        over_rows.contains("FERRUM_AUDIT_RETENTION_MAX_ROWS"),
        "got: {over_rows}"
    );
}

#[test]
fn audit_retention_policy_zero_max_rows_disables_row_cap() {
    let policy = AuditRetentionPolicy::from_parts(None, Some(0)).unwrap();
    assert_eq!(policy.max_rows_per_namespace, None);
    assert!(!policy.is_enabled());

    let rows_only_days = AuditRetentionPolicy::from_parts(Some(30), Some(0)).unwrap();
    assert_eq!(rows_only_days.retention_days, Some(30));
    assert_eq!(rows_only_days.max_rows_per_namespace, None);
    assert!(rows_only_days.is_enabled());
}

#[test]
fn env_config_parses_audit_retention_knobs() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_AUDIT_RETENTION_DAYS", "30"),
            ("FERRUM_AUDIT_RETENTION_MAX_ROWS", "5000"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.audit_retention_days, Some(30));
            assert_eq!(config.audit_retention_max_rows, Some(5000));
        },
    );
}

#[test]
fn env_config_defaults_to_bounded_audit_retention() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.audit_retention_days, None);
            assert_eq!(
                config.audit_retention_max_rows,
                Some(AUDIT_RETENTION_MAX_ROWS_DEFAULT)
            );
        },
    );
}

#[test]
fn env_config_zero_max_rows_disables_row_cap() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_AUDIT_RETENTION_MAX_ROWS", "0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.audit_retention_max_rows, None);
        },
    );
}

#[test]
fn env_config_rejects_invalid_audit_retention() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_AUDIT_RETENTION_DAYS", "0"),
        ],
        || {
            let err = EnvConfig::from_env().unwrap_err();
            assert!(err.contains("FERRUM_AUDIT_RETENTION_DAYS"), "got: {err}");
        },
    );

    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_AUDIT_RETENTION_MAX_ROWS", "not-a-number"),
        ],
        || {
            let err = EnvConfig::from_env().unwrap_err();
            assert!(
                err.contains("FERRUM_AUDIT_RETENTION_MAX_ROWS"),
                "got: {err}"
            );
        },
    );
}

#[test]
fn max_rows_soft_cap_gate_skips_steady_state_scans_until_interval() {
    let max_rows = AUDIT_RETENTION_MAX_ROWS_DEFAULT;
    let interval = audit_retention_max_rows_check_interval(max_rows);
    assert_eq!(interval, AUDIT_RETENTION_MAX_ROWS_CHECK_INTERVAL);
    assert_eq!(
        audit_retention_max_rows_check_interval(2),
        2,
        "small caps must tighten the soft-overshoot interval"
    );

    let mut gate = AuditMaxRowsPruneGate::default();
    assert!(
        gate.should_run_max_rows_prune(max_rows, false),
        "the first insert must scan for a backlog that predates this process"
    );
    gate.note_max_rows_prune_result(false);
    for _ in 1..interval {
        assert!(
            !gate.should_run_max_rows_prune(max_rows, false),
            "steady-state inserts must not scan until the soft-cap interval"
        );
    }
    assert!(gate.should_run_max_rows_prune(max_rows, false));
    gate.note_max_rows_prune_result(false);
    assert!(
        !gate.should_run_max_rows_prune(max_rows, false),
        "after an under-cap check, soft cadence must reset"
    );
    assert!(
        gate.should_run_max_rows_prune(max_rows, true),
        "explicit prune must always force a max-rows scan"
    );
}

#[test]
fn max_rows_soft_cap_gate_keeps_draining_after_batch_budget() {
    let mut gate = AuditMaxRowsPruneGate::default();
    assert!(gate.should_run_max_rows_prune(100_000, true));
    let full_budget =
        AUDIT_RETENTION_PRUNE_BATCH_SIZE * u64::from(AUDIT_RETENTION_PRUNE_MAX_BATCHES);
    assert!(audit_retention_hit_prune_batch_budget(full_budget));
    assert!(!audit_retention_hit_prune_batch_budget(full_budget - 1));
    gate.note_max_rows_prune_result(true);
    assert!(
        gate.should_run_max_rows_prune(100_000, false),
        "a budget-exhausted scan must prune on every subsequent insert"
    );
    gate.note_max_rows_prune_result(false);
    assert!(
        !gate.should_run_max_rows_prune(100_000, false),
        "a completed scan must restore the soft-cap cadence"
    );
}

#[test]
fn max_rows_prune_gate_map_at_capacity_runs_scan_without_insert() {
    use dashmap::DashMap;

    let gates: Arc<DashMap<String, AuditMaxRowsPruneGate>> = Arc::new(DashMap::new());
    for i in 0..AUDIT_MAX_ROWS_PRUNE_GATES_CAP {
        gates.insert(format!("ns-{i}"), AuditMaxRowsPruneGate::default());
    }
    assert_eq!(gates.len(), AUDIT_MAX_ROWS_PRUNE_GATES_CAP);

    let unknown = "fresh-namespace";
    assert!(
        audit_max_rows_prune_gate_should_run(&gates, unknown, 100_000, false),
        "at-capacity unknown namespace must scan every insert"
    );
    assert!(
        !gates.contains_key(unknown),
        "at-capacity path must not grow the gate map"
    );

    let mut existing = gates.get_mut("ns-0").unwrap();
    existing.note_max_rows_prune_result(false);
    drop(existing);
    assert!(
        !audit_max_rows_prune_gate_should_run(&gates, "ns-0", 100_000, false),
        "existing namespace must keep soft-cap cadence"
    );
}

#[test]
fn sql_and_mongo_audit_retention_share_bounded_namespace_contract() {
    for source in [DB_LOADER_SOURCE, MONGO_STORE_SOURCE] {
        assert!(
            source.contains("prune_audit_events"),
            "both backends must expose prune_audit_events"
        );
        assert!(
            source.contains("AUDIT_RETENTION_PRUNE_BATCH_SIZE"),
            "both backends must bound delete batch size"
        );
        assert!(
            source.contains("AUDIT_RETENTION_PRUNE_MAX_BATCHES"),
            "both backends must bound batches per prune call"
        );
        assert!(
            source.contains("AuditMaxRowsPruneGate")
                || source.contains("audit_max_rows_prune_gates"),
            "both backends must cadence-gate insert-path max-row scans"
        );
        assert!(
            source.contains("AUDIT_MAX_ROWS_PRUNE_GATES_CAP")
                || source.contains("audit_max_rows_prune_gate_should_run"),
            "both backends must bound the per-namespace prune gate map"
        );
        assert!(
            source.contains("force_max_rows"),
            "both backends must distinguish insert piggyback from forced prune"
        );
        assert!(
            source.contains("namespace"),
            "retention must stay namespace-scoped"
        );
        assert!(
            source.contains("Failed to prune audit_events after insert"),
            "insert must keep best-effort prune semantics distinct from #2421 delivery loss"
        );
    }

    assert!(
        AUDIT_SOURCE.contains("AUDIT_RETENTION_MAX_ROWS_CHECK_INTERVAL"),
        "soft-cap cadence constant must live with the retention policy"
    );
    assert!(
        AUDIT_SOURCE.contains("AUDIT_MAX_ROWS_PRUNE_GATES_CAP"),
        "prune gate map cap must live with the retention policy"
    );
    assert!(
        DB_LOADER_SOURCE.contains("ORDER BY ts ASC, id ASC"),
        "SQL age/cap deletes must use deterministic (ts, id) order"
    );
    assert!(
        DB_LOADER_SOURCE.contains("ORDER BY ts DESC, id DESC LIMIT 1 OFFSET"),
        "SQL max-row boundary must use newest-first (ts, id) keyset"
    );
    assert!(
        MONGO_STORE_SOURCE.contains("\"ts\": -1, \"id\": -1")
            || MONGO_STORE_SOURCE.contains("ts\": -1, \"id\": -1"),
        "Mongo list/cap boundary must use deterministic (ts, id) order"
    );
    assert!(
        MONGO_INDEX_PLAN_SOURCE.contains("\"namespace\": 1, \"ts\": -1, \"id\": -1"),
        "Mongo canonical plan baseline index must include id for (ts, id) parity"
    );
    assert_eq!(AUDIT_RETENTION_PRUNE_BATCH_SIZE, 1_000);
    assert_eq!(AUDIT_RETENTION_PRUNE_MAX_BATCHES, 8);
    assert_eq!(
        AUDIT_RETENTION_MAX_ROWS_CHECK_INTERVAL,
        AUDIT_RETENTION_PRUNE_BATCH_SIZE
    );
}

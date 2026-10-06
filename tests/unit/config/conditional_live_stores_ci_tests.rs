//! The mandatory conditional-restore live-store lane must stay in CI. Workflow
//! review owns the lane's shell programs; this only catches the lane, its
//! fixtures, its transactional tests or the ignored-test wiring being dropped.

const CI: &str = include_str!("../../../.github/workflows/ci.yml");
const LIVE_TESTS: &[&str] = &[
    "integration::admin_conditional_write_tests::postgres_conditional_restore_checks_state_and_lease_in_transaction",
    "integration::admin_conditional_write_tests::mysql_conditional_restore_checks_state_and_lease_in_transaction",
    "integration::admin_conditional_write_tests::mongo_replica_set_conditional_restore_checks_state_and_lease_in_transaction",
];

#[test]
fn conditional_live_store_lane_runs_the_transactional_tests() {
    let workflow: serde_yaml::Value = serde_yaml::from_str(CI).expect("CI workflow must parse");
    let job = &workflow["jobs"]["test-integration"];
    let lanes: Vec<_> = job["strategy"]["matrix"]["include"]
        .as_sequence()
        .expect("integration matrix include is a sequence")
        .iter()
        .filter(|entry| entry["conditional_live_stores"].as_bool() == Some(true))
        .collect();
    assert_eq!(lanes.len(), 1, "exactly one conditional live-store lane");
    let filters = lanes[0]["filters"]
        .as_str()
        .expect("live lane filters are a string");
    for test in LIVE_TESTS {
        assert!(
            filters.lines().any(|line| line.trim() == *test),
            "live lane must run {test}"
        );
    }
    let steps = job["steps"]
        .as_sequence()
        .expect("integration steps are a sequence");
    for name in [
        "Start conditional restore live stores",
        "Stop conditional restore live stores",
    ] {
        assert!(
            steps.iter().any(|step| step["name"].as_str() == Some(name)),
            "missing CI step: {name}"
        );
    }
    // The live tests are `#[ignore]`; only this flag runs them, and only this
    // env mapping selects it for the live lane.
    let run_step = steps
        .iter()
        .find(|step| step["name"].as_str() == Some("Run integration test shard"))
        .expect("missing CI step: Run integration test shard");
    let run = run_step["run"]
        .as_str()
        .expect("integration shard run is a string");
    assert!(
        run.contains("--run-ignored=all"),
        "live lane must run ignored tests"
    );
    let live_env = run_step["env"]["CONDITIONAL_LIVE_STORES"]
        .as_str()
        .expect("CONDITIONAL_LIVE_STORES is set on the shard step");
    assert!(
        live_env.contains("matrix.conditional_live_stores"),
        "CONDITIONAL_LIVE_STORES must be wired from the matrix"
    );
}

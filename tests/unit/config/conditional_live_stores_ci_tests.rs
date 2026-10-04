//! Keep the mandatory conditional-restore lane and its fixture boundaries explicit.
//! These guards inspect workflow text; only hosted CI executes the live stores.

const CI: &str = include_str!("../../../.github/workflows/ci.yml");
const LIVE_TESTS: &[&str] = &[
    "integration::admin_conditional_write_tests::postgres_conditional_restore_checks_state_and_lease_in_transaction",
    "integration::admin_conditional_write_tests::mysql_conditional_restore_checks_state_and_lease_in_transaction",
    "integration::admin_conditional_write_tests::mongo_replica_set_conditional_restore_checks_state_and_lease_in_transaction",
];

fn between<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
    text.split_once(start)
        .expect("workflow section must exist")
        .1
        .split_once(end)
        .expect("workflow section must have a boundary")
        .0
}

fn integration_job() -> &'static str {
    between(CI, "  test-integration:\n", "  test-conformance:\n")
}

#[test]
fn conditional_live_lane_requires_all_three_tests_and_urls() {
    let job = integration_job();
    let lane = between(
        job,
        "          - shard: conditional-live-stores\n",
        "          - shard: admin-platform\n",
    );
    assert!(lane.contains("conditional_live_stores: true"));
    let selected: Vec<_> = lane
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("integration::"))
        .collect();
    assert_eq!(
        selected.as_slice(),
        LIVE_TESTS,
        "live tests must be selected exactly"
    );
    let runner = between(
        job,
        "      - name: Run integration test shard\n",
        "      - name: Stop conditional restore live stores\n",
    );
    let live_args = between(
        runner,
        "          if [ \"$CONDITIONAL_LIVE_STORES\" = \"true\" ]; then\n",
        "          fi\n",
    );
    assert!(live_args.contains("nextest_args+=(--run-ignored=all -j 1)"));
    for name in ["POSTGRES_URL", "MYSQL_URL", "MONGO_URL"] {
        assert!(
            live_args.contains(&format!("${{{name}:?")),
            "the live lane must reject an absent or empty {name}"
        );
        assert!(runner.contains(&format!("          {name}:")));
    }
    assert!(runner.contains("\"${nextest_args[@]}\""));
    assert!(runner.contains("\"${filters[@]}\""));
    assert!(!runner.contains("continue-on-error"));
    assert!(!lane.contains("continue-on-error"));
}

#[test]
fn conditional_fixture_pins_and_network_boundaries_are_explicit() {
    let start = between(
        integration_job(),
        "      - name: Start conditional restore live stores\n",
        "      - name: Run integration test shard\n",
    );
    for (variable, tag) in [
        ("postgres_image", "postgres:16-alpine"),
        ("mysql_image", "mysql:8"),
        ("mongo_image", "mongo:7"),
    ] {
        let prefix = format!("{variable}='");
        let value = start
            .lines()
            .find_map(|line| line.trim().strip_prefix(&prefix))
            .expect("fixture image must have a literal pin")
            .strip_suffix('\'')
            .expect("fixture image pin must be closed");
        let (actual_tag, digest) = value
            .split_once("@sha256:")
            .expect("fixture image must be pinned by OCI index digest");
        assert_eq!(actual_tag, tag, "fixture major/profile must be preserved");
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(start.matches(&prefix).count(), 1);
    }
    for port in [5432, 3306] {
        assert!(start.contains(&format!("-p 127.0.0.1:{port}:{port}")));
        assert!(!start.contains(&format!("-p {port}:{port}")));
    }
    assert!(start.contains("--bind_ip 127.0.0.1"));
    assert!(!start.contains("--bind_ip_all"));
    assert!(start.contains("--replSet rs0"));
    assert!(start.contains("transactionLifetimeLimitSeconds=180"));
    assert!(start.contains("--name conditional-postgres-client --network host"));
    assert!(start.contains("--name conditional-mysql-client --network host"));
    assert!(start.contains(
        "--host=127.0.0.1 --port=5432 --username=ferrum --dbname=ferrum"
    ));
    assert!(start.contains("mysql --protocol=TCP"));
    assert!(start.contains(
        "--host=127.0.0.1 --port=3306 --user=ferrum --database=ferrum"
    ));
    assert!(!start.contains("pg_isready"));
    assert!(start.contains("--command='SELECT 1'"));
    assert!(start.contains("--execute='SELECT 1'"));
    assert!(start.contains("replicaSet=rs0&serverSelectionTimeoutMS=3000"));
    assert!(start.contains("db.hello().isWritablePrimary === true"));
    assert!(start.contains("rs.initiate("));
    assert!(start.contains("}).ok === 1 ? 0 : 1)"));
}

#[test]
fn conditional_fixture_credentials_and_cleanup_remain_bounded() {
    let job = integration_job();
    let start = between(
        job,
        "      - name: Start conditional restore live stores\n",
        "      - name: Run integration test shard\n",
    );
    for forbidden in ["-pferrum", "-e POSTGRES_PASSWORD=", "-e MYSQL_PASSWORD="] {
        assert!(!start.contains(forbidden), "password must not enter argv");
    }
    assert!(start.contains("-e PGPASSWORD"));
    assert!(start.contains("-e MYSQL_PWD"));
    assert!(start.contains("::add-mask::"));
    assert!(start.contains("openssl rand -hex 24"));
    assert!(start.contains("set +x"));
    assert!(start.contains("deadline=$((SECONDS + 480))"));
    assert!(start.contains("timeout --kill-after=5s \"${limit}s\" \"$@\""));
    assert!(start.contains("trap cleanup_on_failure EXIT"));
    assert!(start.contains("timeout-minutes: 10"));
    let stop = between(
        job,
        "      - name: Stop conditional restore live stores\n",
        "      - name: Check the test run left the checkout clean\n",
    );
    assert!(stop.contains("if: always() && matrix.conditional_live_stores == true"));
    assert!(stop.contains("timeout-minutes: 2"));
    assert!(stop.contains("timeout --kill-after=5s 20s docker rm -f -v"));
    assert!(stop.contains("conditional-(postgres|mysql|mongo)(-client)?"));
    assert!(stop.contains("::error::conditional live store cleanup failed"));
    for section in [start, stop] {
        assert!(!section.contains("docker logs"));
        assert!(!section.contains("docker inspect"));
        assert!(!section.contains("continue-on-error"));
    }
}

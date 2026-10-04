//! Keep the mandatory conditional-restore lane and its fixture boundaries explicit.
//! Hosted unit CI runs these guards and negative mutations; no shell is executed here.

use serde_yaml::{Mapping, Value};

const CI: &str = include_str!("../../../.github/workflows/ci.yml");
const LIVE_TESTS: &[&str] = &[
    "integration::admin_conditional_write_tests::postgres_conditional_restore_checks_state_and_lease_in_transaction",
    "integration::admin_conditional_write_tests::mysql_conditional_restore_checks_state_and_lease_in_transaction",
    "integration::admin_conditional_write_tests::mongo_replica_set_conditional_restore_checks_state_and_lease_in_transaction",
];
const START_STEP: &str = "Start conditional restore live stores";
const RUN_STEP: &str = "Run integration test shard";
const STOP_STEP: &str = "Stop conditional restore live stores";
const JOB_CONDITION: &str = "needs.ci-plan.outputs.mode == 'full' && needs.ci-plan.outputs.run_rust == 'true' && (github.event_name == 'pull_request' || github.event_name == 'merge_group' || (github.event_name == 'push' && github.ref == 'refs/heads/main') || github.event_name == 'workflow_dispatch')";
const RUN_ENV: &[(&str, &str)] = &[
    ("INTEGRATION_FILTERS", "${{ matrix.filters }}"),
    (
        "CONDITIONAL_LIVE_STORES",
        "${{ matrix.conditional_live_stores == true && 'true' || 'false' }}",
    ),
    (
        "POSTGRES_URL",
        "${{ matrix.conditional_live_stores == true && env.CONDITIONAL_POSTGRES_URL || '' }}",
    ),
    (
        "MYSQL_URL",
        "${{ matrix.conditional_live_stores == true && env.CONDITIONAL_MYSQL_URL || '' }}",
    ),
    (
        "MONGO_URL",
        "${{ matrix.conditional_live_stores == true && 'mongodb://127.0.0.1:27020/?replicaSet=rs0' || '' }}",
    ),
];

// These are reviewed, complete shell programs, not a set of required substrings.
// Keep exact bytes, including comments/newlines: removing a comment or blank line
// after a continuation can change shell execution. Legitimate program changes
// require reviewing this contract and its mutations together with the workflow.
// Pinning the whole program rejects early exits, dead branches, argv additions,
// ignored failures, and later array resets even if all old guard text survives.

const START_PROGRAM: &str = r#"set -euo pipefail
set +x
# Docker Hub OCI index digests verified against registry-1.docker.io
# on 2026-10-04. Preserve the existing tags/majors and client versions.
postgres_image='postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea'
mysql_image='mysql:8@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242'
mongo_image='mongo:7@sha256:1f995ad6fdb93244a1addab1b58f934a0bc2f5643c38e02f5e9d7f0c7d227a7b'
deadline=$((SECONDS + 480))
fixture_phase='initializing credentials'
cleanup_on_failure() {
  status=$?
  trap - EXIT
  if [ "$status" -ne 0 ]; then
    echo "::error::conditional live stores failed while $fixture_phase"
    timeout --kill-after=5s 20s docker rm -f -v \
      conditional-postgres conditional-mysql conditional-mongo \
      conditional-postgres-client conditional-mysql-client >/dev/null 2>&1 \
      || echo '::warning::fixture cleanup incomplete; the always-run cleanup will retry'
  fi
  exit "$status"
}
trap cleanup_on_failure EXIT
bounded() {
  local limit="$1"
  shift
  local remaining=$((deadline - SECONDS))
  [ "$remaining" -gt 0 ] || return 124
  if [ "$remaining" -lt "$limit" ]; then
    limit="$remaining"
  fi
  timeout --kill-after=5s "${limit}s" "$@"
}
wait_for_store() {
  fixture_phase="$1"
  shift
  until bounded 15 "$@" >/dev/null 2>&1; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "::error::conditional live stores readiness deadline exceeded while $fixture_phase"
      return 1
    fi
    bounded 3 sleep 2 || return 1
  done
}
# Per-run credentials travel in environment variables, never client
# argv. Mask both passwords and test URLs before any later step logs.
POSTGRES_PASSWORD="$(openssl rand -hex 24)"
MYSQL_PASSWORD="$(openssl rand -hex 24)"
MYSQL_ROOT_PASSWORD="$(openssl rand -hex 24)"
for password in "$POSTGRES_PASSWORD" "$MYSQL_PASSWORD" "$MYSQL_ROOT_PASSWORD"; do
  printf '::add-mask::%s\n' "$password"
done
export POSTGRES_PASSWORD MYSQL_PASSWORD MYSQL_ROOT_PASSWORD
export PGPASSWORD="$POSTGRES_PASSWORD" MYSQL_PWD="$MYSQL_PASSWORD"
postgres_url="postgres://ferrum:${POSTGRES_PASSWORD}@127.0.0.1:5432/ferrum"
mysql_url="mysql://ferrum:${MYSQL_PASSWORD}@127.0.0.1:3306/ferrum"
printf '::add-mask::%s\n' "$postgres_url" "$mysql_url"
printf 'CONDITIONAL_POSTGRES_URL=%s\nCONDITIONAL_MYSQL_URL=%s\n' \
  "$postgres_url" "$mysql_url" >> "$GITHUB_ENV"
fixture_phase='pulling pinned database images'
bounded 120 docker pull "$postgres_image"
bounded 120 docker pull "$mysql_image"
bounded 120 docker pull "$mongo_image"
fixture_phase='starting loopback database fixtures and TCP clients'
bounded 30 docker run -d --name conditional-postgres -p 127.0.0.1:5432:5432 \
  -e POSTGRES_DB=ferrum -e POSTGRES_USER=ferrum -e POSTGRES_PASSWORD \
  "$postgres_image"
bounded 30 docker run -d --name conditional-mysql -p 127.0.0.1:3306:3306 \
  -e MYSQL_DATABASE=ferrum -e MYSQL_USER=ferrum -e MYSQL_PASSWORD \
  -e MYSQL_ROOT_PASSWORD "$mysql_image"
bounded 30 docker run -d --name conditional-mongo --network host \
  "$mongo_image" --replSet rs0 --port 27020 --bind_ip 127.0.0.1 \
  --setParameter transactionLifetimeLimitSeconds=180
# These sleeping client containers share the RUNNER network namespace.
# Explicit TCP queries authenticate against the published test ports,
# never the temporary init server's container-local SQL socket.
bounded 30 docker run -d --name conditional-postgres-client --network host \
  -e PGPASSWORD -e PGCONNECT_TIMEOUT=3 --entrypoint sleep "$postgres_image" infinity
bounded 30 docker run -d --name conditional-mysql-client --network host \
  -e MYSQL_PWD --entrypoint sleep "$mysql_image" infinity
wait_for_store 'authenticating PostgreSQL at 127.0.0.1:5432/ferrum' \
  docker exec conditional-postgres-client psql --no-psqlrc --no-password \
    --host=127.0.0.1 --port=5432 --username=ferrum --dbname=ferrum \
    --set=ON_ERROR_STOP=1 --command='SELECT 1'
wait_for_store 'authenticating MySQL at 127.0.0.1:3306/ferrum' \
  docker exec conditional-mysql-client mysql --protocol=TCP \
    --host=127.0.0.1 --port=3306 --user=ferrum --database=ferrum \
    --connect-timeout=3 --execute='SELECT 1'
wait_for_store 'probing MongoDB at 127.0.0.1:27020' \
  docker exec conditional-mongo mongosh --quiet \
    'mongodb://127.0.0.1:27020/?directConnection=true&serverSelectionTimeoutMS=3000' \
    --eval 'quit(db.adminCommand({ping: 1}).ok === 1 ? 0 : 1)'
fixture_phase='initiating the MongoDB replica set'
bounded 15 docker exec conditional-mongo mongosh --quiet \
  'mongodb://127.0.0.1:27020/?directConnection=true&serverSelectionTimeoutMS=3000' \
  --eval 'quit(rs.initiate({_id: "rs0", members: [{_id: 0, host: "127.0.0.1:27020"}]}).ok === 1 ? 0 : 1)' \
  >/dev/null 2>&1
wait_for_store 'waiting for MongoDB rs0 writable primary at 127.0.0.1:27020' \
  docker exec conditional-mongo mongosh --quiet \
    'mongodb://127.0.0.1:27020/?replicaSet=rs0&serverSelectionTimeoutMS=3000' \
    --eval 'quit(db.hello().isWritablePrimary === true ? 0 : 1)'
echo 'Conditional live stores authenticated on runner loopback; MongoDB rs0 is writable.'
"#;

const RUN_PROGRAM: &str = r#"set -e
archive_file="integration-tests-${RUNNER_OS}-${RUNNER_ARCH}.tar.zst"
filters=()
while IFS= read -r filter; do
  [ -z "$filter" ] && continue
  filters+=("$filter")
done <<< "$INTEGRATION_FILTERS"
nextest_args=()
if [ "$CONDITIONAL_LIVE_STORES" = "true" ]; then
  : "${POSTGRES_URL:?conditional live stores require POSTGRES_URL}"
  : "${MYSQL_URL:?conditional live stores require MYSQL_URL}"
  : "${MONGO_URL:?conditional live stores require MONGO_URL}"
  nextest_args+=(--run-ignored=all -j 1)
fi
cargo nextest run \
  --archive-file "$archive_file" \
  --workspace-remap . \
  --no-fail-fast \
  "${nextest_args[@]}" \
  "${filters[@]}"
"#;

const STOP_PROGRAM: &str = r#"set -euo pipefail
# Never dump credential-bearing database logs or inspect environment.
# Discovery makes cleanup idempotent after a partial startup failure.
container_ids="$(timeout --kill-after=5s 20s docker ps -aq \
  --filter 'name=^/conditional-(postgres|mysql|mongo)(-client)?$')" \
  || { echo '::error::conditional live store cleanup could not list containers'; exit 1; }
if [ -n "$container_ids" ]; then
  mapfile -t containers <<< "$container_ids"
  timeout --kill-after=5s 20s docker rm -f -v "${containers[@]}" >/dev/null \
    || { echo '::error::conditional live store cleanup failed'; exit 1; }
fi
"#;

type GuardResult<T> = Result<T, &'static str>;

fn member<'a>(map: &'a Mapping, key: &str) -> GuardResult<&'a Value> {
    map.get(key).ok_or("required workflow member is missing")
}

fn mapping(value: &Value) -> GuardResult<&Mapping> {
    value.as_mapping().ok_or("workflow mapping required")
}

fn exact_keys(map: &Mapping, keys: &[&str]) -> GuardResult<()> {
    if map.len() != keys.len()
        || !map
            .keys()
            .all(|key| key.as_str().is_some_and(|key| keys.contains(&key)))
    {
        return Err("workflow keys differ from the reviewed contract");
    }
    Ok(())
}

fn string_is(map: &Mapping, key: &str, expected: &str) -> GuardResult<()> {
    if member(map, key)?.as_str() != Some(expected) {
        return Err("workflow string differs from the reviewed contract");
    }
    Ok(())
}

fn validate_step(
    value: &Value,
    condition: Option<&str>,
    minutes: u64,
    program: &str,
    env: Option<&[(&str, &str)]>,
) -> GuardResult<()> {
    let step = mapping(value)?;
    let mut keys = vec!["name", "run", "timeout-minutes"];
    if let Some(condition) = condition {
        keys.push("if");
        string_is(step, "if", condition)?;
    }
    if let Some(env) = env {
        keys.push("env");
        let actual = mapping(member(step, "env")?)?;
        let mut env_keys: Vec<_> = env.iter().map(|(key, _)| *key).collect();
        env_keys.push("RUST_BACKTRACE");
        exact_keys(actual, &env_keys)?;
        for (key, expected) in env {
            string_is(actual, key, expected)?;
        }
        if member(actual, "RUST_BACKTRACE")?.as_u64() != Some(1) {
            return Err("runner backtrace environment changed");
        }
    }
    // No unreviewed if, shell, uses, env, working-directory, or
    // continue-on-error can override the active run block.
    exact_keys(step, &keys)?;
    if member(step, "timeout-minutes")?.as_u64() != Some(minutes) {
        return Err("live step timeout changed");
    }
    string_is(step, "run", program)
}

fn validate_workflow(workflow: &Value) -> GuardResult<()> {
    let root = mapping(workflow)?;
    if root.contains_key("defaults") {
        return Err("workflow defaults can override live shell execution");
    }
    // Reject inherited shell/credential/client options. Step-local env alone
    // cannot stop BASH_ENV or a global database-client option from taking effect.
    let root_env = mapping(member(root, "env")?)?;
    exact_keys(
        root_env,
        &[
            "CARGO_TERM_COLOR",
            "CARGO_NET_RETRY",
            "CARGO_HTTP_MULTIPLEXING",
            "BORINGCACHE_ENABLED",
        ],
    )?;
    for (key, expected) in [
        ("CARGO_TERM_COLOR", "always"),
        ("CARGO_NET_RETRY", "10"),
        ("CARGO_HTTP_MULTIPLEXING", "false"),
        ("BORINGCACHE_ENABLED", "${{ vars.BORINGCACHE_ENABLED }}"),
    ] {
        string_is(root_env, key, expected)?;
    }
    let jobs = mapping(member(root, "jobs")?)?;
    let job = mapping(member(jobs, "test-integration")?)?;
    exact_keys(
        job,
        &["name", "if", "needs", "runs-on", "strategy", "steps"],
    )?;
    string_is(job, "if", JOB_CONDITION)?;
    string_is(job, "runs-on", "ubuntu-latest")?;
    let needs = member(job, "needs")?
        .as_sequence()
        .ok_or("integration prerequisites must be explicit")?;
    let needs: Vec<_> = needs.iter().map(Value::as_str).collect();
    if needs != [Some("ci-plan"), Some("build-test-artifacts")] {
        return Err("integration prerequisites changed");
    }
    let strategy = mapping(member(job, "strategy")?)?;
    exact_keys(strategy, &["fail-fast", "matrix"])?;
    if member(strategy, "fail-fast")?.as_bool() != Some(false) {
        return Err("live lane must not be cancelled by another shard failure");
    }
    let matrix = mapping(member(strategy, "matrix")?)?;
    exact_keys(matrix, &["include"])?;
    let include = member(matrix, "include")?
        .as_sequence()
        .ok_or("integration matrix include must be explicit")?;
    let mut live_lanes = Vec::new();
    for entry in include {
        let entry = mapping(entry)?;
        if member(entry, "shard")?.as_str() == Some("conditional-live-stores") {
            live_lanes.push(entry);
        }
    }
    if live_lanes.len() != 1 {
        return Err("exactly one mandatory conditional live lane is required");
    }
    let lane = live_lanes[0];
    exact_keys(lane, &["shard", "conditional_live_stores", "filters"])?;
    if member(lane, "conditional_live_stores")?.as_bool() != Some(true) {
        return Err("live lane must enable fixtures and ignored tests");
    }
    let filters = member(lane, "filters")?
        .as_str()
        .ok_or("live filters must be an explicit string")?;
    if filters.lines().collect::<Vec<_>>() != LIVE_TESTS {
        return Err("live lane must select exactly the three transactional tests");
    }
    let steps = member(job, "steps")?
        .as_sequence()
        .ok_or("integration steps must be explicit")?;
    let mut selected = Vec::new();
    for name in [START_STEP, RUN_STEP, STOP_STEP] {
        let mut matches = Vec::new();
        for (index, step) in steps.iter().enumerate() {
            let step_map = mapping(step)?;
            if step_map.get("name").and_then(Value::as_str) == Some(name) {
                matches.push(index);
            }
        }
        if matches.len() != 1 {
            return Err("live steps must exist exactly once as active YAML steps");
        }
        selected.push(matches[0]);
    }
    if selected[0] + 1 != selected[1] || selected[1] + 1 != selected[2] {
        return Err("live start, runner and cleanup must be consecutive and ordered");
    }
    validate_step(
        &steps[selected[0]],
        Some("matrix.conditional_live_stores == true"),
        10,
        START_PROGRAM,
        None,
    )
    .map_err(|_| "fixture credential/readiness/deadline contract changed")?;
    validate_step(
        &steps[selected[1]],
        None,
        30,
        RUN_PROGRAM,
        Some(RUN_ENV),
    )
    .map_err(|_| "active runner/filter/serial/URL contract changed")?;
    validate_step(
        &steps[selected[2]],
        Some("always() && matrix.conditional_live_stores == true"),
        2,
        STOP_PROGRAM,
        None,
    )
    .map_err(|_| "always-run bounded fatal cleanup contract changed")
}

fn workflow() -> Value {
    serde_yaml::from_str(CI).expect("CI workflow must parse")
}

fn step_mut<'a>(workflow: &'a mut Value, name: &str) -> &'a mut Value {
    workflow["jobs"]["test-integration"]["steps"]
        .as_sequence_mut()
        .expect("steps are a sequence")
        .iter_mut()
        .find(|step| step["name"].as_str() == Some(name))
        .expect("named step exists")
}

fn live_lane_mut(workflow: &mut Value) -> &mut Value {
    &mut workflow["jobs"]["test-integration"]["strategy"]["matrix"]["include"][0]
}

fn assert_rejected(workflow: &Value, context: &str) {
    assert!(
        validate_workflow(workflow).is_err(),
        "guard accepted negative mutation: {context}"
    );
}

fn reject_program_mutations(name: &str, mutations: &[(&str, &str)]) {
    let original = workflow();
    validate_workflow(&original).expect("reviewed workflow must pass before negative mutations");
    for &(before, after) in mutations {
        let mut mutated = original.clone();
        let step = step_mut(&mut mutated, name);
        let program = step["run"].as_str().expect("step has a shell program");
        assert_eq!(
            program.matches(before).count(),
            1,
            "mutation must be unique"
        );
        step["run"] = Value::String(program.replacen(before, after, 1));
        assert_rejected(&mutated, before);
    }
}

#[test]
fn conditional_live_workflow_requires_reviewed_active_programs() {
    validate_workflow(&workflow()).expect("mandatory live lane contract must hold");
}

#[test]
fn conditional_live_guards_reject_skips_and_execution_overrides() {
    let original = workflow();
    validate_workflow(&original).expect("reviewed workflow must pass before negative mutations");
    for name in [START_STEP, RUN_STEP, STOP_STEP] {
        for (key, value) in [
            ("if", Value::Bool(false)),
            ("if", Value::String("false".to_owned())),
            ("continue-on-error", Value::Bool(true)),
            ("shell", Value::String("bash {0} || true".to_owned())),
            ("timeout-minutes", Value::Number(1.into())),
        ] {
            let mut mutated = original.clone();
            step_mut(&mut mutated, name)[key] = value;
            assert_rejected(&mutated, key);
        }
    }
    for key in ["if", "continue-on-error", "defaults", "env", "container"] {
        let mut mutated = original.clone();
        mutated["jobs"]["test-integration"][key] = Value::Bool(false);
        assert_rejected(&mutated, key);
    }
    let mut mutated = original.clone();
    mutated["jobs"]["test-integration"]["if"] = Value::String(format!("{JOB_CONDITION} || true"));
    assert_rejected(
        &mutated,
        "job condition bypass preserves the original condition text",
    );
    let mut mutated = original.clone();
    mutated["defaults"] = serde_yaml::from_str("run:\n  shell: bash {0} || true").unwrap();
    assert_rejected(&mutated, "inherited shell override");
    let mut mutated = original.clone();
    mutated["env"]["BASH_ENV"] = Value::String("/tmp/skip-tests.sh".to_owned());
    assert_rejected(&mutated, "inherited shell startup override");
    let mut mutated = original.clone();
    let steps = mutated["jobs"]["test-integration"]["steps"]
        .as_sequence_mut()
        .unwrap();
    let runner = steps
        .iter()
        .find(|step| step["name"] == RUN_STEP)
        .unwrap()
        .clone();
    steps.push(runner);
    assert_rejected(&mutated, "duplicate runner");
    let mut mutated = original.clone();
    let steps = mutated["jobs"]["test-integration"]["steps"]
        .as_sequence_mut()
        .unwrap();
    let runner_index = steps
        .iter()
        .position(|step| step["name"] == RUN_STEP)
        .unwrap();
    steps.swap(runner_index, runner_index + 1);
    assert_rejected(&mutated, "cleanup before tests");
}

#[test]
fn conditional_live_guards_reject_filter_and_url_wiring_regressions() {
    let original = workflow();
    validate_workflow(&original).expect("reviewed workflow must pass before negative mutations");
    for filters in [
        LIVE_TESTS[..2].join("\n"),
        "integration::admin_conditional_write_tests".to_owned(),
        format!("{}\n{}\n", LIVE_TESTS.join("\n"), LIVE_TESTS[0]),
    ] {
        let mut mutated = original.clone();
        live_lane_mut(&mut mutated)["filters"] = Value::String(filters);
        assert_rejected(&mutated, "omitted, broadened or duplicate test filter");
    }
    let mut mutated = original.clone();
    live_lane_mut(&mut mutated)["conditional_live_stores"] = Value::Bool(false);
    assert_rejected(&mutated, "live fixtures disabled in matrix");
    let mut mutated = original.clone();
    mutated["jobs"]["test-integration"]["strategy"]["matrix"]["exclude"] =
        serde_yaml::from_str("- shard: conditional-live-stores").unwrap();
    assert_rejected(&mutated, "matrix excludes mandatory lane");
    for key in [
        "INTEGRATION_FILTERS",
        "CONDITIONAL_LIVE_STORES",
        "POSTGRES_URL",
        "MYSQL_URL",
        "MONGO_URL",
    ] {
        let mut mutated = original.clone();
        step_mut(&mut mutated, RUN_STEP)["env"][key] = Value::String(String::new());
        assert_rejected(&mutated, key);
    }
    reject_program_mutations(
        RUN_STEP,
        &[
            ("set -e\n", "set -e\nexit 0\n"),
            ("--run-ignored=all -j 1", "--run-ignored=ignored-only -j 1"),
            ("--run-ignored=all -j 1", "--run-ignored=all -j 2"),
            ("$CONDITIONAL_LIVE_STORES", "false"),
            ("${POSTGRES_URL:?", "${POSTGRES_URL:-"),
            ("${MYSQL_URL:?", "${MYSQL_URL:-"),
            ("${MONGO_URL:?", "${MONGO_URL:-"),
            ("cargo nextest run", "nextest_args=()\n  cargo nextest run"),
            ("\"${filters[@]}\"", "\"${filters[@]}\" || true"),
        ],
    );
}

#[test]
fn conditional_live_guards_reject_password_argv_and_unmasked_credentials() {
    reject_program_mutations(
        START_STEP,
        &[
            (
                "mysql --protocol=TCP",
                "mysql --password=\"$MYSQL_PASSWORD\" --protocol=TCP",
            ),
            (
                "mysql --protocol=TCP",
                "mysql -p\"$MYSQL_PASSWORD\" --protocol=TCP",
            ),
            ("-e MYSQL_PWD", "-e MYSQL_PWD=\"$MYSQL_PASSWORD\""),
            ("-e PGPASSWORD ", "-e PGPASSWORD=\"$POSTGRES_PASSWORD\" "),
            ("-e MYSQL_PASSWORD ", "-e MYSQL_PASSWORD=\"$MYSQL_PASSWORD\" "),
            (
                "-e POSTGRES_PASSWORD ",
                "-e POSTGRES_PASSWORD=\"$POSTGRES_PASSWORD\" ",
            ),
            (
                "MYSQL_PASSWORD=\"$(openssl rand -hex 24)\"",
                "MYSQL_PASSWORD=ferrum",
            ),
            ("set +x", "set -x"),
            ("printf '::add-mask::%s\\n' \"$password\"", "echo \"$password\""),
            (
                "printf '::add-mask::%s\\n' \"$postgres_url\" \"$mysql_url\"",
                "echo \"$postgres_url\" \"$mysql_url\"",
            ),
            (">> \"$GITHUB_ENV\"", "| tee -a \"$GITHUB_ENV\""),
            (
                "export PGPASSWORD=\"$POSTGRES_PASSWORD\" MYSQL_PWD=\"$MYSQL_PASSWORD\"",
                "export PGPASSWORD=\"$POSTGRES_PASSWORD\" MYSQL_PWD=wrong",
            ),
        ],
    );
}

#[test]
fn conditional_live_guards_reject_socket_readiness_and_exposed_fixtures() {
    reject_program_mutations(
        START_STEP,
        &[
            ("-p 127.0.0.1:5432:5432", "-p 5432:5432"),
            ("-p 127.0.0.1:3306:3306", "-p 3306:3306"),
            ("--bind_ip 127.0.0.1", "--bind_ip_all"),
            ("--replSet rs0", "--replSet other"),
            (
                "transactionLifetimeLimitSeconds=180",
                "transactionLifetimeLimitSeconds=60",
            ),
            (
                "--name conditional-postgres-client --network host",
                "--name conditional-postgres-client --network bridge",
            ),
            (
                "--name conditional-mysql-client --network host",
                "--name conditional-mysql-client --network bridge",
            ),
            (
                "docker exec conditional-postgres-client psql",
                "docker exec conditional-postgres pg_isready",
            ),
            (
                "docker exec conditional-mysql-client mysql",
                "docker exec conditional-mysql mysql",
            ),
            ("mysql --protocol=TCP", "mysql --protocol=SOCKET"),
            (
                "--host=127.0.0.1 --port=5432",
                "--host=127.0.0.1 --port=5433",
            ),
            (
                "--host=127.0.0.1 --port=3306",
                "--host=127.0.0.1 --port=3307",
            ),
            ("--set=ON_ERROR_STOP=1", "--set=ON_ERROR_STOP=0"),
            (
                "--username=ferrum --dbname=ferrum",
                "--username=postgres --dbname=postgres",
            ),
            ("--user=ferrum --database=ferrum", "--user=root --database=mysql"),
            ("--command='SELECT 1'", "--command='SELECT 0'"),
            ("--execute='SELECT 1'", "--execute='SELECT 0'"),
            ("rs.initiate(", "print("),
            ("db.hello().isWritablePrimary === true", "true"),
            (
                "replicaSet=rs0&serverSelectionTimeoutMS=3000",
                "directConnection=true&serverSelectionTimeoutMS=3000",
            ),
            (
                "postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea",
                "postgres:16-alpine",
            ),
            (
                "mysql:8@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242",
                "mysql:8",
            ),
            (
                "mongo:7@sha256:1f995ad6fdb93244a1addab1b58f934a0bc2f5643c38e02f5e9d7f0c7d227a7b",
                "mongo:7",
            ),
        ],
    );
}

#[test]
fn conditional_live_guards_reject_nonfatal_or_unbounded_failure_handlers() {
    reject_program_mutations(
        STOP_STEP,
        &[
            (
                "echo '::error::conditional live store cleanup failed'; exit 1;",
                "echo '::error::conditional live store cleanup failed'; exit 0;",
            ),
            (
                "echo '::error::conditional live store cleanup could not list containers'; exit 1;",
                "echo '::error::conditional live store cleanup could not list containers'; exit 0;",
            ),
            ("timeout --kill-after=5s 20s docker ps", "docker ps"),
            ("timeout --kill-after=5s 20s docker rm", "docker rm"),
            ("set -euo pipefail", "set -euo pipefail\nexit 0"),
            ("docker rm -f -v", "docker logs"),
        ],
    );
    reject_program_mutations(
        START_STEP,
        &[
            ("deadline=$((SECONDS + 480))", "deadline=$((SECONDS + 48000))"),
            ("[ \"$remaining\" -gt 0 ] || return 124", "[ \"$remaining\" -gt 0 ] || return 0"),
            ("timeout --kill-after=5s \"${limit}s\" \"$@\"", "\"$@\""),
            ("bounded 120 docker pull \"$mysql_image\"", "docker pull \"$mysql_image\""),
            ("until bounded 15 \"$@\"", "until \"$@\""),
            ("bounded 3 sleep 2 || return 1", "bounded 3 sleep 2 || return 0"),
            ("trap cleanup_on_failure EXIT", "trap : EXIT"),
            ("exit \"$status\"", "exit 0"),
            ("timeout --kill-after=5s 20s docker rm", "docker inspect"),
        ],
    );
}

//! Static contracts for the scheduled scaling harness and gate signal (#3892).
//!
//! These pin the workflow-sized admin JWT policy, documented all-or-nothing
//! batch 503 retries, and the fail-closed scaling-gate notification without
//! executing the 10k/30k suites.

use std::time::Duration;

use serde_json::json;

#[path = "../../common/scheduled_scaling.rs"]
mod scheduled_scaling;

use scheduled_scaling::{
    ADMIN_BATCH_REQUEST_TIMEOUT_SECS, APPLY_STATUS_WAIT_MS, BATCH_ROLLBACK_NOT_NEEDED,
    BatchApplyCursor, BatchProvisionDecision, CONFIG_CONVERGENCE_MAX_WAIT_SECS,
    CONFIG_CONVERGENCE_POLL_INTERVAL_SECS, MEASUREMENT_WINDOW_MAX_ATTEMPTS,
    NAMESPACE_FENCE_DEFAULT_RETRY_AFTER_SECS, NAMESPACE_FENCE_MAX_ATTEMPTS,
    NAMESPACE_FENCE_MAX_BACKOFF_SECS, NAMESPACE_FENCE_MAX_RETRY_AFTER_SECS,
    NAMESPACE_FENCE_MAX_TOTAL_RETRY_SECS, NAMESPACE_FENCE_RETRY_MESSAGE,
    SCHEDULED_SCALING_ADMIN_JWT_TTL_SECS, classify_admin_batch_response,
    documented_batch_rollback_not_needed_body, documented_namespace_fence_body,
    namespace_fence_backoff, namespace_fence_retry_after_delay, parse_config_cursor_header,
    scheduled_scaling_admin_jwt_max_ttl_value,
};

const WORKFLOW: &str = include_str!("../../../.github/workflows/scaling-regression.yml");
const FRESHNESS: &str = include_str!("../../../.github/workflows/scaling-gate-freshness.yml");
const SIGNAL: &str = include_str!("../../../.github/scripts/publish_scaling_gate_signal.py");
const VERIFIER: &str =
    include_str!("../../../.github/scripts/verify_scaling_regression_workflow.py");
const SCALE: &str = include_str!("../../../tests/functional/functional_scale_perf_test.rs");
const LOAD: &str = include_str!("../../../tests/functional/functional_load_stress_test.rs");
const CI_CD: &str = include_str!("../../../docs/ci_cd.md");
const PUBLISHER_CONCURRENCY_GROUP: &str = "scaling-gate-publisher";

#[test]
fn admin_jwt_ttl_covers_the_300_minute_job_and_is_accepted_by_configured_max_ttl() {
    assert_eq!(SCHEDULED_SCALING_ADMIN_JWT_TTL_SECS, 6 * 60 * 60);
    // The harness mints ONE admin JWT for the whole run and hands its TTL to
    // the gateway as FERRUM_ADMIN_JWT_MAX_TTL, so the token must outlive the
    // job budget or provisioning fails on auth partway through. Asserted
    // against the real budget: at the old `>= 180 * 60` a 300-minute job
    // (issue #4136) satisfied this with a 240-minute token and would have
    // expired at minute 240, on whichever leg ran long enough to reach it.
    const { assert!(SCHEDULED_SCALING_ADMIN_JWT_TTL_SECS >= 300 * 60) };
    assert_eq!(
        scheduled_scaling_admin_jwt_max_ttl_value(),
        SCHEDULED_SCALING_ADMIN_JWT_TTL_SECS.to_string()
    );
    assert!(
        SCALE.contains("FERRUM_ADMIN_JWT_MAX_TTL")
            && SCALE.contains("SCHEDULED_SCALING_ADMIN_JWT_TTL_SECS"),
        "scale harness must mint and accept the workflow-sized admin JWT"
    );
    assert!(
        LOAD.contains("FERRUM_ADMIN_JWT_MAX_TTL")
            && LOAD.contains("SCHEDULED_SCALING_ADMIN_JWT_TTL_SECS"),
        "load harness must mint and accept the workflow-sized admin JWT"
    );
}

#[test]
fn consumer_jwt_minting_stays_separate_from_the_admin_workflow_ttl() {
    assert!(
        LOAD.contains("fn generate_consumer_jwt"),
        "load harness must keep a dedicated consumer JWT helper"
    );
    let consumer_fn = LOAD
        .split("fn generate_consumer_jwt")
        .nth(1)
        .expect("consumer JWT helper")
        .split("fn ")
        .next()
        .expect("consumer JWT helper body");
    assert!(
        consumer_fn.contains("chrono::Duration::seconds(3600)"),
        "consumer JWTs must remain on the 1-hour mint path"
    );
    assert!(
        !consumer_fn.contains("SCHEDULED_SCALING_ADMIN_JWT_TTL_SECS"),
        "consumer JWT minting must not reuse the admin workflow TTL"
    );
}

#[test]
fn documented_retryable_503s_are_retried_and_other_outcomes_stay_fatal() {
    let fence = serde_json::to_string(&documented_namespace_fence_body()).expect("json");
    assert_eq!(
        classify_admin_batch_response(503, Some("1"), &fence),
        BatchProvisionDecision::Retry {
            delay: Duration::from_secs(1)
        }
    );
    assert_eq!(
        classify_admin_batch_response(503, Some("99"), &fence),
        BatchProvisionDecision::Retry {
            delay: Duration::from_secs(NAMESPACE_FENCE_MAX_RETRY_AFTER_SECS)
        }
    );

    let lease_lost = serde_json::to_string(&documented_batch_rollback_not_needed_body(
        "Namespace config admission was lost before the batch could commit; nothing was applied",
    ))
    .expect("json");
    assert_eq!(
        classify_admin_batch_response(503, Some("1"), &lease_lost),
        BatchProvisionDecision::Retry {
            delay: Duration::from_secs(1)
        }
    );

    let persistence = serde_json::to_string(&documented_batch_rollback_not_needed_body(
        "database is temporarily unavailable",
    ))
    .expect("json");
    assert_eq!(
        classify_admin_batch_response(503, None, &persistence),
        BatchProvisionDecision::Retry {
            delay: Duration::from_secs(NAMESPACE_FENCE_DEFAULT_RETRY_AFTER_SECS)
        }
    );

    assert_eq!(
        classify_admin_batch_response(201, None, "{}"),
        BatchProvisionDecision::Success
    );

    match classify_admin_batch_response(200, None, "") {
        BatchProvisionDecision::Fatal { status, .. } => assert_eq!(status, 200),
        other => panic!("undocumented 2xx statuses must be fatal, got {other:?}"),
    }

    let other_503 = json!({"error": "Service Unavailable"}).to_string();
    match classify_admin_batch_response(503, Some("1"), &other_503) {
        BatchProvisionDecision::Fatal { status, body } => {
            assert_eq!(status, 503);
            assert!(body.contains("Service Unavailable"));
        }
        other => panic!("other 503s must be fatal, got {other:?}"),
    }

    match classify_admin_batch_response(503, Some("1"), "retry later") {
        BatchProvisionDecision::Fatal { status, .. } => assert_eq!(status, 503),
        other => panic!("malformed 503 bodies must be fatal, got {other:?}"),
    }

    match classify_admin_batch_response(500, Some("1"), &fence) {
        BatchProvisionDecision::Fatal { status, .. } => assert_eq!(status, 500),
        other => panic!("non-503 statuses must be fatal, got {other:?}"),
    }

    match classify_admin_batch_response(207, None, "{\"accepted\":1}") {
        BatchProvisionDecision::Fatal { status, .. } => assert_eq!(status, 207),
        other => panic!("partial-success statuses must be fatal, got {other:?}"),
    }

    match classify_admin_batch_response(409, None, &persistence) {
        BatchProvisionDecision::Fatal { status, .. } => assert_eq!(status, 409),
        other => panic!("conflict rollback bodies must stay fatal, got {other:?}"),
    }

    assert_eq!(
        NAMESPACE_FENCE_RETRY_MESSAGE,
        "Namespace mutation is temporarily unavailable; retry later"
    );
    assert_eq!(BATCH_ROLLBACK_NOT_NEEDED, "not_needed");
}

#[test]
fn namespace_fence_retries_are_bounded_by_wall_clock_not_attempt_count() {
    // The gateway always answers the fence with `Retry-After: 1`, so a
    // header-only schedule would retry roughly once a second and add load to
    // the serialized admission queue it is waiting on (issue #3895).
    assert_eq!(
        namespace_fence_retry_after_delay(Some("1")),
        Duration::from_secs(1)
    );
    let ramp: Vec<u64> = (1..=6)
        .map(|attempt| {
            namespace_fence_retry_after_delay(Some("1"))
                .max(namespace_fence_backoff(attempt))
                .as_secs()
        })
        .collect();
    assert_eq!(ramp, [1, 2, 4, 8, 16, 30]);
    assert_eq!(
        namespace_fence_backoff(NAMESPACE_FENCE_MAX_ATTEMPTS).as_secs(),
        NAMESPACE_FENCE_MAX_BACKOFF_SECS,
        "backoff must saturate rather than grow without bound"
    );

    // An attempt-counted budget is the wrong shape for a documented-transient
    // contention 503: what decides whether the fence clears is how long the
    // serialized admission queue takes to drain, not how many times the client
    // asks (issue #4116). The attempt ceiling must therefore only ever be a
    // spin guard — the backoff schedule has to outrun the wall-clock budget
    // before the ceiling can bind.
    let attempt_ceiling_wait: u64 = (1..NAMESPACE_FENCE_MAX_ATTEMPTS)
        .map(|attempt| {
            namespace_fence_retry_after_delay(Some("1"))
                .max(namespace_fence_backoff(attempt))
                .as_secs()
        })
        .sum();
    assert!(
        attempt_ceiling_wait > NAMESPACE_FENCE_MAX_TOTAL_RETRY_SECS,
        "the attempt ceiling ({NAMESPACE_FENCE_MAX_ATTEMPTS}) must not bind before the \
         wall-clock budget ({NAMESPACE_FENCE_MAX_TOTAL_RETRY_SECS}s); schedule totals \
         {attempt_ceiling_wait}s"
    );

    assert_eq!(NAMESPACE_FENCE_MAX_TOTAL_RETRY_SECS, 10 * 60);
    // The first exhausted body aborts provisioning, so the budget plus one
    // in-flight request timeout is the entire added cost of a fence that never
    // clears.
    const {
        assert!(
            NAMESPACE_FENCE_MAX_TOTAL_RETRY_SECS + ADMIN_BATCH_REQUEST_TIMEOUT_SECS < 300 * 60,
            "one atomic body's fence-retry budget must stay inside the job timeout"
        )
    };
    const {
        assert!(
            NAMESPACE_FENCE_MAX_TOTAL_RETRY_SECS > 10 * NAMESPACE_FENCE_DEFAULT_RETRY_AFTER_SECS,
            "the retry budget must not collapse back onto the server's minimum"
        )
    };

    let helper = include_str!("../../common/scheduled_scaling.rs");
    assert!(
        helper.contains("if started.elapsed() + wait >= retry_budget {"),
        "the wall-clock budget must be checked before sleeping, not after"
    );
    assert!(
        helper.contains("was still refused as transient namespace-admission contention after"),
        "an exhausted budget must be reported as an admission outage, not as a retry count"
    );
}

#[test]
fn atomic_admin_batches_have_a_bounded_timeout_without_transport_retries() {
    // 10 minutes: comfortably above the ~300s slow-but-healthy late-wave
    // chunks observed on the 30k PostgreSQL leg (run 32832589798), because a
    // client timeout on an in-flight all-or-nothing body is an ambiguous
    // outcome that can never be safely retried. Still bounded and pinned
    // against the fence budget + job timeout below.
    assert_eq!(ADMIN_BATCH_REQUEST_TIMEOUT_SECS, 10 * 60);
    let helper = include_str!("../../common/scheduled_scaling.rs");
    assert!(
        helper.contains(".timeout(Duration::from_secs(ADMIN_BATCH_REQUEST_TIMEOUT_SECS))"),
        "each admin batch request must override the shorter data-plane client timeout"
    );
    assert!(
        helper.contains("{operation} transport error: {err}"),
        "ambiguous transport failures must remain fatal instead of being retried"
    );
}

#[test]
fn documented_namespace_fence_error_plus_extra_field_is_fatal() {
    let extra = json!({
        "error": NAMESPACE_FENCE_RETRY_MESSAGE,
        "retry": true
    })
    .to_string();
    match classify_admin_batch_response(503, Some("1"), &extra) {
        BatchProvisionDecision::Fatal { status, body } => {
            assert_eq!(status, 503);
            assert!(body.contains("retry"));
        }
        other => panic!("documented error plus an extra field must be fatal, got {other:?}"),
    }

    let extra_rollback = json!({
        "error": "database is temporarily unavailable",
        "rollback": BATCH_ROLLBACK_NOT_NEEDED,
        "detail": "nope"
    })
    .to_string();
    match classify_admin_batch_response(503, Some("1"), &extra_rollback) {
        BatchProvisionDecision::Fatal { status, .. } => assert_eq!(status, 503),
        other => panic!("rollback body plus an extra field must be fatal, got {other:?}"),
    }

    let wrong_rollback = json!({
        "error": "database is temporarily unavailable",
        "rollback": "needed"
    })
    .to_string();
    match classify_admin_batch_response(503, Some("1"), &wrong_rollback) {
        BatchProvisionDecision::Fatal { status, .. } => assert_eq!(status, 503),
        other => panic!("non-not_needed rollback must be fatal, got {other:?}"),
    }
}

#[test]
fn retry_after_honors_delay_seconds_with_a_bounded_default() {
    assert_eq!(
        namespace_fence_retry_after_delay(None),
        Duration::from_secs(NAMESPACE_FENCE_DEFAULT_RETRY_AFTER_SECS)
    );
    assert_eq!(
        namespace_fence_retry_after_delay(Some("2")),
        Duration::from_secs(2)
    );
    assert_eq!(
        namespace_fence_retry_after_delay(Some("0")),
        Duration::from_secs(NAMESPACE_FENCE_DEFAULT_RETRY_AFTER_SECS)
    );
    assert_eq!(
        namespace_fence_retry_after_delay(Some("99")),
        Duration::from_secs(NAMESPACE_FENCE_MAX_RETRY_AFTER_SECS)
    );
    assert_eq!(
        namespace_fence_retry_after_delay(Some("Wed, 21 Oct 2015 07:28:00 GMT")),
        Duration::from_secs(NAMESPACE_FENCE_DEFAULT_RETRY_AFTER_SECS)
    );
}

#[test]
fn both_harnesses_route_every_batch_phase_through_the_shared_helper() {
    // Three provisioning phases, plus the reload-under-load test's proxy and
    // plugin-config batches.
    assert_eq!(SCALE.matches("post_admin_batch(").count(), 5);
    assert_eq!(LOAD.matches("post_admin_batch(").count(), 4);
    assert!(
        !SCALE.contains(".post(format!(\"{}/batch\"")
            && !LOAD.contains(".post(format!(\"{}/batch\""),
        "neither harness may POST /batch outside the shared helper"
    );
}

#[test]
fn both_harnesses_gate_measurement_on_bounded_convergence_not_a_fixed_sleep() {
    // The red PostgreSQL legs of issue #4116 measured throughput while the
    // gateway was still executing the full reload that provisioning forced
    // (`load_config_changes_after` bails past `CHANGE_LOG_MAX_ROWS`). Both
    // harnesses detected the unroutable sample, printed a warning, slept a
    // fixed five seconds, and measured anyway. Convergence must be a gate, not
    // a warning.
    assert_eq!(CONFIG_CONVERGENCE_MAX_WAIT_SECS, 5 * 60);
    const { assert!(CONFIG_CONVERGENCE_POLL_INTERVAL_SECS > 0) };
    const {
        assert!(
            CONFIG_CONVERGENCE_POLL_INTERVAL_SECS < CONFIG_CONVERGENCE_MAX_WAIT_SECS,
            "the poll interval must fit many times inside the convergence bound"
        )
    };
    // The scale harness pays this bound once per batch, so the worst case must
    // still leave the 300-minute job room for provisioning and measurement.
    let scale_batches = 30_000 / 3_000;
    assert!(
        scale_batches * CONFIG_CONVERGENCE_MAX_WAIT_SECS < 60 * 60,
        "a per-batch convergence bound must not be able to consume the job budget"
    );

    let helper = include_str!("../../common/scheduled_scaling.rs");
    assert!(
        helper.contains("config convergence never completed for"),
        "an exhausted convergence bound must name itself explicitly"
    );
    assert!(
        helper.contains("This is a configuration-publication failure, not a throughput"),
        "the convergence failure must not be mistakable for a throughput regression"
    );

    for (name, source) in [("scale", SCALE), ("load", LOAD)] {
        assert!(
            source.contains("wait_for_config_convergence("),
            "{name} harness must gate measurement on the bounded convergence helper"
        );
        assert!(
            !source.contains("waiting longer"),
            "{name} harness must not fall back to a fixed sleep after a failed sample probe"
        );
    }

    assert_eq!(MEASUREMENT_WINDOW_MAX_ATTEMPTS, 2);
    assert!(SCALE.contains("convergence_interruption.notified()"));
    assert!(SCALE.contains("Ok(status) if status == reqwest::StatusCode::NOT_FOUND"));
    assert!(SCALE.contains("discarding interrupted measurement window"));
    assert!(SCALE.contains("Configuration convergence instability interrupted all"));
}

#[test]
fn load_harness_provisions_credentials_on_the_atomic_consumer_batch() {
    // 10,000 individual `PUT /consumers/{id}/credentials/{type}` calls are
    // 10,000 separate namespace mutations against a deliberately serialized
    // admission critical section. That self-inflicted contention is what
    // produced the transient 503s the harness then reported as a provisioning
    // failure, and the per-consumer path logged those failures to stderr while
    // still handing back an `AuthEntry` for a credential that was never
    // written (issue #4116).
    for path in [
        "/credentials/keyauth",
        "/credentials/basicauth",
        "/credentials/jwt",
    ] {
        assert!(
            !LOAD.contains(path),
            "load harness must not provision credentials through per-consumer {path} mutations"
        );
    }
    assert!(
        !LOAD.contains("Credential set failed"),
        "provisioning must not swallow failed credential writes and keep measuring"
    );
    assert!(
        LOAD.contains("\"keyauth\": [{ \"key\": api_key.clone() }]")
            && LOAD.contains("\"basicauth\": [{ \"password\": password.clone() }]")
            && LOAD.contains("\"jwt\": [{ \"secret\": jwt_secret.clone() }]"),
        "each auth group's credentials must ride the atomic consumer batch"
    );
    assert!(
        SCALE.contains("\"keyauth\": [{\"key\": api_key}]"),
        "the scale harness's inline-credential batch shape is the reference"
    );
}

#[test]
fn scheduled_scaling_workflow_keeps_the_300_minute_matrix_and_signal_job() {
    assert!(WORKFLOW.contains("timeout-minutes: 300"));
    assert!(WORKFLOW.contains("cron: \"0 4 * * 6\""));
    assert!(WORKFLOW.contains("  scaling-gate-signal:"));
    assert!(WORKFLOW.contains("issues: write"));
    assert!(WORKFLOW.contains("actions: read"));
    assert!(WORKFLOW.contains("if: always()"));
    assert!(WORKFLOW.contains("publish_scaling_gate_signal.py"));
    assert!(WORKFLOW.contains("verify_scaling_regression_workflow.py --self-test"));
    assert!(!WORKFLOW.contains("pull_request:"));
    assert!(!WORKFLOW.contains("LAUNCH_ADVISORY_READ_TOKEN"));
    assert!(!WORKFLOW.contains("Launch Readiness Gate"));
    assert!(!WORKFLOW.contains("contents: write"));
}

#[test]
fn scaling_gate_publisher_jobs_preserve_queued_work() {
    assert!(
        VERIFIER.contains("PUBLISHER_CONCURRENCY_GROUP = \"scaling-gate-publisher\""),
        "verifier must pin the shared scaling-gate publisher concurrency group"
    );
    assert!(
        VERIFIER.contains("queue: max"),
        "verifier must pin queue: max so pending publishers are preserved"
    );
    for (workflow, job_name) in [
        (WORKFLOW, "scaling-gate-signal"),
        (FRESHNESS, "scaling-gate-freshness"),
    ] {
        let job_header = format!("  {job_name}:");
        let job = workflow
            .lines()
            .skip_while(|line| *line != job_header)
            .skip(1)
            .take_while(|line| line.trim().is_empty() || line.starts_with("    "))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!job.is_empty(), "missing {job_name} job body");
        assert!(
            job.contains("concurrency:")
                && job.contains(&format!("group: {PUBLISHER_CONCURRENCY_GROUP}"))
                && job.contains("cancel-in-progress: false")
                && job.contains("queue: max"),
            "{job_name} publisher job must queue pending scaling-gate publishers without canceling in-progress work"
        );
        assert!(
            !job.contains("cancel-in-progress: true"),
            "{job_name} must not combine queue: max with cancel-in-progress: true"
        );
    }
}

#[test]
fn scaling_gate_signal_is_generation_aware() {
    assert!(
        SIGNAL.contains("current_run_id == latest.run_id"),
        "weekly SCALING_JOB_RESULT may be authoritative only for the exact latest scaling-regression run"
    );
    assert!(
        SIGNAL.contains("latest_run_on_main(repo, token, now)"),
        "every live invocation must query the latest scaling-regression run on main"
    );
    assert!(
        SIGNAL.contains("parse_github_run_id"),
        "signal must bind GITHUB_RUN_ID before mutating issues"
    );
    assert!(
        !SIGNAL
            .split("def self_test")
            .next()
            .expect("production signal")
            .contains("GREEN_RESULTS | RED_RESULTS"),
        "weekly success/failure must not skip the latest-run query"
    );
    for label in [
        "stale older success over newer failure",
        "stale older failure over newer fresh success",
        "latest nonterminal",
        "missing current run identity",
        "malformed current run identity",
        "history API failure",
        "exact current run success",
        "exact current run failure",
        "numeric run-id is not generation order",
        "missing head_branch is not on main",
        "must not close when recorded run id is newer than the decision",
        "must not close when recorded run id is unreadable",
    ] {
        assert!(
            SIGNAL.contains(label),
            "signal self-test must cover {label}"
        );
    }
    assert!(
        VERIFIER.contains("stale older success over newer failure")
            && VERIFIER.contains("exact current run success")
            && VERIFIER.contains("queue: max"),
        "verifier must pin generation-aware and queue-preservation contracts"
    );
}

#[test]
fn freshness_workflow_is_fail_closed_and_does_not_run_the_suites() {
    assert!(FRESHNESS.contains("cron: \"0 12 * * *\""));
    assert!(FRESHNESS.contains("publish_scaling_gate_signal.py"));
    assert!(FRESHNESS.contains("issues: write"));
    assert!(FRESHNESS.contains("actions: read"));
    let publish = FRESHNESS
        .split("- name: Publish scaling gate freshness")
        .nth(1)
        .expect("freshness publish step");
    let publish_step = publish
        .split("\n      - ")
        .next()
        .expect("freshness publish step body");
    assert!(
        publish_step.contains("if: always()"),
        "freshness publish must still run when static verification fails"
    );
    assert!(!FRESHNESS.contains("cargo test"));
    assert!(!FRESHNESS.contains("cargo build"));
    assert!(!FRESHNESS.contains("pull_request:"));
    assert!(!FRESHNESS.contains("LAUNCH_ADVISORY_READ_TOKEN"));
    assert!(!FRESHNESS.contains("Launch Readiness Gate"));
    assert!(SIGNAL.contains("MAX_AGE_SECONDS = 8 * 24 * 60 * 60"));
    // PR #4010 deleted the launch-readiness lane, so nothing consumes a
    // `launch-blocker` label any more; the signal issue carries severity only.
    assert!(SIGNAL.contains("severity:high"));
    assert!(!SIGNAL.contains("launch-blocker"));
    assert!(SIGNAL.contains("refs/heads/main"));
    assert!(VERIFIER.contains("verify_scaling_regression_workflow.py"));
    assert!(CI_CD.contains("scaling-gate-freshness.yml"));
}

#[test]
fn scaling_gate_publisher_spoof_and_discovery_contracts_are_pr_gated() {
    let production = SIGNAL
        .split("def self_test")
        .next()
        .expect("production publisher");
    let author_line = production
        .lines()
        .find(|line| line.starts_with("SIGNAL_AUTHOR = "))
        .expect("SIGNAL_AUTHOR assignment");
    assert_eq!(author_line, "SIGNAL_AUTHOR = \"github-actions[bot]\"");
    let login_checks = production
        .lines()
        .filter(|line| line.trim() == "if login != SIGNAL_AUTHOR:")
        .count();
    assert_eq!(
        login_checks, 2,
        "listing skip and require_publisher_owned_signal must both reject non-bot authors"
    );

    let listing = production
        .split("def find_signal_issue")
        .nth(1)
        .expect("find_signal_issue")
        .split("def apply_decision")
        .next()
        .expect("find_signal_issue body");
    assert!(
        listing.contains("\"state\": \"all\""),
        "discovery must list state=all so a closed signal can be reopened"
    );
    assert!(
        listing.contains("\"sort\": \"updated\"") && listing.contains("\"direction\": \"desc\""),
        "discovery must sort by updated desc so the live signal stays in the window"
    );
    assert!(
        listing.contains("\"creator\": SIGNAL_AUTHOR"),
        "discovery must filter by publisher creator so PRs and unrelated issues cannot consume the bound"
    );
    assert!(
        listing.contains("ISSUE_LIST_PER_PAGE") && listing.contains("ISSUE_LIST_MAX_PAGES"),
        "discovery must keep a finite listing bound"
    );
    assert!(
        listing.contains("if len(matches) == 1:")
            && listing.contains("issue listing exceeded pagination bound"),
        "a unique match in a full window must be returned; absence on a full window stays fail-closed"
    );

    let latest = production
        .split("def latest_run_on_main")
        .nth(1)
        .expect("latest_run_on_main")
        .split("def _issue_number")
        .next()
        .expect("latest_run_on_main body");
    assert!(
        latest.contains("if head_branch != \"main\":"),
        "missing or null head_branch must fail closed rather than counting as main"
    );
    assert!(
        !latest.contains("html_url"),
        "latest-run parsing must not stash an API-supplied html_url"
    );

    let apply = production
        .split("def apply_decision")
        .nth(1)
        .expect("apply_decision")
        .split("def run_live")
        .next()
        .expect("apply_decision body");
    assert!(
        apply.contains("close_blocked_by_recorded_generation"),
        "close must compare the recorded Run id against the decision generation"
    );
    assert!(
        apply.contains("\"labels\": list(ISSUE_LABELS)"),
        "creation must still set the severity label"
    );
    assert!(
        apply.contains("patch: dict[str, Any] = {\"body\": body}"),
        "open-path updates must patch body only and not replace maintainer labels"
    );

    assert!(
        production.contains("def public_issue_reason")
            && production.contains("ISSUE_REASON_MAX_CHARS = 200"),
        "public issue reasons must be sanitized and truncated before they reach the issue body"
    );
}

/// A committed-but-not-live `POST /batch` answer must not abort provisioning.
///
/// Observed on the 2026-08-24 dispatched scaling run (32675684731) on `main`
/// AFTER read-your-write live apply (#3960) landed: both 30k legs — SQLite as
/// well as PostgreSQL — died at batch 2 with
/// `503 {"applied":false,"reason":"reload_timeout"}`. The write is DURABLE
/// there ("Configuration was committed but is not live"), so failing loses
/// nothing but the run, and retrying the same all-or-nothing body would
/// collide with the resources it just created. The only correct move is to
/// carry on and let the bounded convergence gate decide.
#[test]
fn committed_but_not_live_batches_continue_to_the_convergence_gate() {
    for reason in ["reload_timeout", "sequence_unavailable"] {
        let body = json!({
            "error": "Configuration was committed but is not live: runtime reload did not apply in time",
            "applied": false,
            "reason": reason,
        })
        .to_string();
        assert!(
            matches!(
                classify_admin_batch_response(503, None, &body),
                BatchProvisionDecision::CommittedNotLive { .. }
            ),
            "{reason} must be treated as committed, not fatal and not retryable"
        );
    }

    // `config_rejected` is the opposite case: the runtime REFUSED the
    // candidate, so it will never go live and the harness must fail loudly.
    let rejected = json!({
        "error": "Configuration was committed but is not live: runtime reload rejected the candidate",
        "applied": false,
        "reason": "config_rejected",
    })
    .to_string();
    assert!(
        matches!(
            classify_admin_batch_response(503, None, &rejected),
            BatchProvisionDecision::Fatal { .. }
        ),
        "a rejected candidate must never be mistaken for a committed one"
    );

    // A 503 that does not carry the documented shape stays fatal.
    let opaque = json!({"error": "something else"}).to_string();
    assert!(
        matches!(
            classify_admin_batch_response(503, None, &opaque),
            BatchProvisionDecision::Fatal { .. }
        ),
        "only the documented applied/reason shape may be treated as committed"
    );
}

/// Issue #4139: deferred provisioning contracts.
///
/// `POST /batch?apply=async` answers `202 Accepted` for a durably committed
/// whole graph; the harness treats that as success, keeps the highest
/// `X-Ferrum-Config-Cursor` seen, and proves the wave live with one blocking
/// `GET /config/apply-status` instead of one synchronous reload per chunk —
/// the cost that outgrew the 30k job budget in issue #4136.
#[test]
fn deferred_batch_202_is_success_and_cursors_parse_epoch_major() {
    assert_eq!(
        classify_admin_batch_response(202, None, "{}"),
        BatchProvisionDecision::Success,
        "the deferred 202 is a fully committed graph, not a partial apply"
    );
    // Other 2xx stay fatal: only the two documented success shapes exist.
    assert!(matches!(
        classify_admin_batch_response(204, None, ""),
        BatchProvisionDecision::Fatal { .. }
    ));

    assert_eq!(
        parse_config_cursor_header("3:41"),
        Some(BatchApplyCursor {
            epoch: 3,
            sequence: 41
        })
    );
    for bad in ["", "3", "3:", ":41", "3:41:5", "a:b", "-1:2"] {
        assert_eq!(
            parse_config_cursor_header(bad),
            None,
            "malformed cursor {bad:?} must not parse"
        );
    }

    // Epoch-major ordering: a cursor from a later database topology
    // supersedes any sequence from an earlier one, so max-tracking across a
    // mid-provisioning reconnect keeps the right cursor.
    let old_topology_high = BatchApplyCursor {
        epoch: 1,
        sequence: 999_999,
    };
    let new_topology_low = BatchApplyCursor {
        epoch: 2,
        sequence: 1,
    };
    assert!(new_topology_low > old_topology_high);
    assert_eq!(
        Some(new_topology_low).max(Some(old_topology_high)),
        Some(new_topology_low)
    );
    assert_eq!(None.max(Some(old_topology_high)), Some(old_topology_high));
}

/// The status probe's server-side wait must match the endpoint's documented
/// maximum (the synchronous mutation path's own budget); a larger value is a
/// `400` and a smaller one only adds probe round-trips.
#[test]
fn apply_status_wait_matches_the_documented_endpoint_bound() {
    assert_eq!(APPLY_STATUS_WAIT_MS, 30_000);
    let openapi = include_str!("../../../openapi.yaml");
    assert!(
        openapi.contains("maximum: 30000"),
        "openapi.yaml must pin the same wait_ms bound the harness relies on"
    );
}

/// Both harnesses must post through the deferred helper and then gate on the
/// covering cursor before any measurement phase.
#[test]
fn harnesses_provision_deferred_and_gate_on_the_cursor() {
    assert!(
        SCALE.contains("wait_for_batch_apply_cursor(")
            && LOAD.contains("wait_for_batch_apply_cursor("),
        "both harnesses must prove the deferred wave live before measuring"
    );
    let helper = include_str!("../../common/scheduled_scaling.rs");
    assert!(
        helper.contains("/batch?apply=async"),
        "the shared helper must provision with the deferred opt-in"
    );
    assert!(
        helper.contains("/config/apply-status?epoch="),
        "the cursor gate must use the documented status endpoint"
    );
}

/// The pre-persist admission-lease re-check refuses with NOTHING persisted, so
/// its 503 must carry the documented retryable `rollback: not_needed` shape
/// the harness (and any bulk client) retries under the bounded fence budget.
/// Without it, a transient lease-renewal miss under heavy reload load aborts
/// provisioning as fatal (observed on the 30k PostgreSQL leg, issue #4139).
#[test]
fn batch_pre_persist_lease_loss_is_the_documented_retryable_shape() {
    let admin = include_str!("../../../src/admin/mod.rs");
    let branch = admin
        .split("batch_namespace_admission_before_persist")
        .nth(1)
        .map(|tail| &tail[..tail.len().min(1500)])
        .expect("pre-persist ensure_held branch remains inspectable");
    assert!(
        branch.contains(r#""rollback": "not_needed""#),
        "pre-persist lease loss must report rollback: not_needed"
    );
    assert!(
        branch.contains("RETRY_AFTER"),
        "pre-persist lease loss must carry Retry-After like the mid-transaction variant"
    );
    // And the harness classifier accepts exactly that shape as a bounded retry.
    let body =
        documented_batch_rollback_not_needed_body("Config admission unavailable").to_string();
    assert!(matches!(
        classify_admin_batch_response(503, Some("1"), &body),
        BatchProvisionDecision::Retry { .. }
    ));
}

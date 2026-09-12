//! Live-artifact GA contract validator (M5 Stage 4).
//!
//! The live Kubernetes suites under `tests/k8s/` emit a `live-assertions.json`
//! artifact through `tests/k8s/lib/live_assertions.sh`. This module validates
//! such an artifact against `ga_contract.yaml`: every GA capability whose
//! `live_suite` matches the artifact must have each declared live assertion
//! PRESENT with status `pass` — a required `skip` is a failure, exactly as the
//! emitter's header prescribes — for the expected suite, platform profile, and
//! commit, with no duplicate assertion ids and no stale artifact. Capabilities
//! marked `live_deferred` are REPORTED, not enforced (see the field docs in
//! [`super::contract`]); deleting the marker is the act of enrolling a row in
//! this gate.
//!
//! The enforcing test ([`live_contract_artifact_gate`]) is env-gated: it
//! validates only when `FERRUM_LIVE_ASSERTIONS_FILE` points at an artifact.
//! The live suite workflows set it right after their fixture run (see
//! `.github/workflows/mesh-e2e-sidecar-live.yml`), together with:
//!
//! - `FERRUM_LIVE_SUITE` — the suite the artifact MUST declare (guards
//!   against gating one suite's contract rows with another suite's artifact);
//! - `FERRUM_LIVE_EXPECTED_COMMIT` — the commit the artifact MUST have been
//!   produced from (rejects stale artifacts from an earlier push);
//! - `FERRUM_LIVE_MAX_AGE_HOURS` — optional freshness bound on `created_at`.
//!
//! In the ordinary conformance job none of these are set, the test self-skips,
//! and the suite stays hermetic. Validation itself is a pure function
//! ([`validate_live_artifact`]) so the rules are unit-tested below without any
//! filesystem or clock dependence.

use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;

use super::contract::{Contract, ContractMaturity, load_contract};

const SUPPORTED_ARTIFACT_SCHEMA_VERSION: u32 = 1;

/// The subset of the live-assertions artifact this validator consumes. Extra
/// fields (workload names, SPIFFE ids, diagnostics) are intentionally ignored
/// so the artifact schema can grow without breaking the gate.
#[derive(Debug, Deserialize)]
struct LiveArtifact {
    schema_version: u32,
    suite: String,
    commit: String,
    platform_profile: String,
    created_at: String,
    #[serde(default)]
    assertions: Vec<LiveAssertionRecord>,
}

#[derive(Debug, Deserialize)]
struct LiveAssertionRecord {
    id: String,
    status: String,
}

/// What the invoking workflow expects of the artifact. `None` fields are not
/// enforced (the env-gated test maps unset env vars here), but a live gate
/// should set all of them — suite and commit pinning are what make a stale or
/// mis-routed artifact rejectable.
#[derive(Debug, Default)]
pub(crate) struct ExpectedArtifact {
    pub suite: Option<String>,
    pub commit: Option<String>,
    pub max_age_hours: Option<f64>,
}

/// Validate `artifact_json` against the GA contract. Returns human-readable
/// summary lines on success and the COMPLETE list of violations on failure
/// (all problems at once, not first-failure, so a red CI run is diagnosable
/// from one message).
pub(crate) fn validate_live_artifact(
    contract: &Contract,
    artifact_json: &str,
    expected: &ExpectedArtifact,
    now: DateTime<Utc>,
) -> Result<Vec<String>, Vec<String>> {
    let artifact: LiveArtifact = match serde_json::from_str(artifact_json) {
        Ok(artifact) => artifact,
        Err(err) => return Err(vec![format!("artifact is not parseable JSON: {err}")]),
    };

    let mut errors = Vec::new();

    if artifact.schema_version != SUPPORTED_ARTIFACT_SCHEMA_VERSION {
        errors.push(format!(
            "artifact schema_version {} is unsupported (expected {})",
            artifact.schema_version, SUPPORTED_ARTIFACT_SCHEMA_VERSION
        ));
    }

    if let Some(expected_suite) = &expected.suite
        && artifact.suite != *expected_suite
    {
        errors.push(format!(
            "artifact suite `{}` does not match expected suite `{expected_suite}`",
            artifact.suite
        ));
    }

    if let Some(expected_commit) = &expected.commit
        && artifact.commit != *expected_commit
    {
        errors.push(format!(
            "artifact commit `{}` does not match expected commit `{expected_commit}` — \
             stale artifact from an earlier build?",
            artifact.commit
        ));
    }

    match DateTime::parse_from_rfc3339(&artifact.created_at) {
        Ok(created_at) => {
            if let Some(max_age_hours) = expected.max_age_hours {
                let age = now.signed_duration_since(created_at.with_timezone(&Utc));
                let max_age = Duration::seconds((max_age_hours * 3600.0) as i64);
                if age > max_age {
                    errors.push(format!(
                        "artifact created_at `{}` is older than the {max_age_hours}h freshness \
                         bound — stale artifact",
                        artifact.created_at
                    ));
                }
                if age < Duration::zero() - Duration::minutes(5) {
                    errors.push(format!(
                        "artifact created_at `{}` is in the future — clock skew or a corrupt \
                         artifact",
                        artifact.created_at
                    ));
                }
            }
        }
        Err(err) => errors.push(format!(
            "artifact created_at `{}` is not RFC3339: {err}",
            artifact.created_at
        )),
    }

    // Duplicate assertion ids make the artifact ambiguous (which record
    // counts?) and usually mean a fixture recorded one probe twice — reject
    // regardless of whether the id is contract-enforced.
    let mut seen = BTreeSet::new();
    for record in &artifact.assertions {
        if !seen.insert(record.id.as_str()) {
            errors.push(format!(
                "artifact records assertion `{}` more than once",
                record.id
            ));
        }
    }
    let statuses: BTreeMap<&str, &str> = artifact
        .assertions
        .iter()
        .map(|record| (record.id.as_str(), record.status.as_str()))
        .collect();

    let mut summary = Vec::new();
    let mut enforced_rows = 0usize;
    for capability in contract.ga_capabilities() {
        if capability.live_suite != artifact.suite {
            continue;
        }
        if let Some(reason) = &capability.live_deferred {
            summary.push(format!(
                "capability `{}`: live assertions DEFERRED (not enforced): {reason}",
                capability.id
            ));
            continue;
        }
        enforced_rows += 1;
        if capability.platform_profile != artifact.platform_profile {
            errors.push(format!(
                "capability `{}` expects platform_profile `{}` but the artifact declares `{}`",
                capability.id, capability.platform_profile, artifact.platform_profile
            ));
        }
        for assertion_id in &capability.live_assertions {
            match statuses.get(assertion_id.as_str()) {
                Some(&"pass") => summary.push(format!(
                    "capability `{}`: live assertion `{assertion_id}` passed",
                    capability.id
                )),
                Some(status) => errors.push(format!(
                    "capability `{}`: live assertion `{assertion_id}` has status `{status}` \
                     (required assertions must be `pass`; a required skip is a failure)",
                    capability.id
                )),
                None => errors.push(format!(
                    "capability `{}`: live assertion `{assertion_id}` is missing from the \
                     artifact — the suite never emitted it",
                    capability.id
                )),
            }
        }
    }

    // An artifact whose suite gates nothing is a misconfiguration (a typo'd
    // suite name would otherwise "pass" vacuously). Deferred-only suites are
    // fine — the deferral is the documented state.
    if enforced_rows == 0
        && !contract
            .ga_capabilities()
            .iter()
            .any(|capability| capability.live_suite == artifact.suite)
    {
        errors.push(format!(
            "artifact suite `{}` matches no GA-contract capability — nothing to gate \
             (suite name typo, or the contract rows were removed?)",
            artifact.suite
        ));
    }

    if errors.is_empty() {
        summary.push(format!(
            "validated {} enforced GA capability row(s) for suite `{}` at commit `{}`",
            enforced_rows, artifact.suite, artifact.commit
        ));
        Ok(summary)
    } else {
        Err(errors)
    }
}

/// Env-gated enforcement test — see module docs for the contract the live
/// workflows follow. Self-skips (with a printed note) when
/// `FERRUM_LIVE_ASSERTIONS_FILE` is unset so the ordinary conformance job
/// stays hermetic.
#[test]
fn live_contract_artifact_gate() {
    let Some(path) = std::env::var_os("FERRUM_LIVE_ASSERTIONS_FILE") else {
        println!(
            "live_contract: FERRUM_LIVE_ASSERTIONS_FILE unset; skipping live-artifact validation"
        );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read live assertions artifact {path:?}: {err}"));
    let expected = ExpectedArtifact {
        suite: std::env::var("FERRUM_LIVE_SUITE").ok(),
        commit: std::env::var("FERRUM_LIVE_EXPECTED_COMMIT").ok(),
        max_age_hours: std::env::var("FERRUM_LIVE_MAX_AGE_HOURS").ok().map(|raw| {
            raw.parse()
                .expect("FERRUM_LIVE_MAX_AGE_HOURS must be a number of hours")
        }),
    };
    let contract = load_contract().expect("ga_contract.yaml must be valid");
    match validate_live_artifact(&contract, &raw, &expected, Utc::now()) {
        Ok(lines) => {
            for line in lines {
                println!("live_contract: {line}");
            }
        }
        Err(errors) => panic!(
            "live-assertions artifact failed GA-contract validation:\n  - {}",
            errors.join("\n  - ")
        ),
    }
}

// ── validator unit tests (synthetic contract + artifacts; no env, no fs) ────

fn test_contract(live_deferred_line: &str) -> Contract {
    let yaml = format!(
        r#"
schema_version: 1
capabilities:
  - id: mesh.sample.enforced
    display_name: Sample enforced capability
    maturity: ga
    topology: sidecar
    config_protocol: istio
    semantic_assertions:
      - category: sample
        feature: enforced.feature
    live_suite: sample-suite
    live_assertions:
      - sample.enforced.assertion
    platform_profile: sample-profile
    docs_anchor: docs/mesh.md#sample
    owner: mesh
  - id: mesh.sample.deferred
    display_name: Sample deferred capability
    maturity: ga
    topology: sidecar
    config_protocol: istio
    semantic_assertions:
      - category: sample
        feature: deferred.feature
    live_suite: sample-suite
    live_assertions:
      - sample.deferred.assertion
{live_deferred_line}
    platform_profile: sample-profile
    docs_anchor: docs/mesh.md#sample
    owner: mesh
  - id: mesh.sample.other_suite
    display_name: Sample other-suite capability
    maturity: ga
    topology: sidecar
    config_protocol: istio
    semantic_assertions:
      - category: sample
        feature: other.feature
    live_suite: other-suite
    live_assertions:
      - sample.other.assertion
    platform_profile: other-profile
    docs_anchor: docs/mesh.md#sample
    owner: mesh
"#
    );
    let contract: Contract = serde_yaml::from_str(&yaml).expect("test contract parses");
    contract.validate().expect("test contract is schema-valid");
    contract
}

fn deferred_contract() -> Contract {
    test_contract("    live_deferred: deferred for testing (tracked in issue #0)")
}

fn artifact_json(
    suite: &str,
    commit: &str,
    profile: &str,
    created_at: &str,
    assertions: &[(&str, &str)],
) -> String {
    let assertions: Vec<serde_json::Value> = assertions
        .iter()
        .map(|(id, status)| serde_json::json!({"id": id, "status": status}))
        .collect();
    serde_json::json!({
        "schema_version": 1,
        "suite": suite,
        "commit": commit,
        "platform_profile": profile,
        "created_at": created_at,
        "assertions": assertions,
    })
    .to_string()
}

fn fixed_now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-07-01T12:00:00Z")
        .expect("fixed now parses")
        .with_timezone(&Utc)
}

fn expected_all() -> ExpectedArtifact {
    ExpectedArtifact {
        suite: Some("sample-suite".to_string()),
        commit: Some("abc123".to_string()),
        max_age_hours: Some(6.0),
    }
}

#[test]
fn live_contract_passes_when_enforced_assertions_pass_and_deferred_are_reported() {
    let contract = deferred_contract();
    let artifact = artifact_json(
        "sample-suite",
        "abc123",
        "sample-profile",
        "2026-07-01T11:00:00Z",
        &[("sample.enforced.assertion", "pass")],
    );
    let summary = validate_live_artifact(&contract, &artifact, &expected_all(), fixed_now())
        .expect("artifact must validate");
    assert!(
        summary.iter().any(|line| line.contains("DEFERRED")),
        "deferred capability must be reported: {summary:?}"
    );
    assert!(
        summary
            .iter()
            .any(|line| line.contains("`sample.enforced.assertion` passed")),
        "enforced pass must be reported: {summary:?}"
    );
}

#[test]
fn live_contract_rejects_missing_required_assertion() {
    let contract = deferred_contract();
    let artifact = artifact_json(
        "sample-suite",
        "abc123",
        "sample-profile",
        "2026-07-01T11:00:00Z",
        &[],
    );
    let errors = validate_live_artifact(&contract, &artifact, &expected_all(), fixed_now())
        .expect_err("missing assertion must fail");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("missing from the artifact")),
        "{errors:?}"
    );
}

#[test]
fn live_contract_rejects_failed_and_skipped_required_assertions() {
    let contract = deferred_contract();
    for status in ["fail", "skip"] {
        let artifact = artifact_json(
            "sample-suite",
            "abc123",
            "sample-profile",
            "2026-07-01T11:00:00Z",
            &[("sample.enforced.assertion", status)],
        );
        let errors = validate_live_artifact(&contract, &artifact, &expected_all(), fixed_now())
            .expect_err("non-pass required assertion statuses must fail validation");
        assert!(
            errors
                .iter()
                .any(|error| error.contains(&format!("has status `{status}`"))),
            "{errors:?}"
        );
    }
}

#[test]
fn live_contract_does_not_enforce_deferred_assertions() {
    let contract = deferred_contract();
    // The deferred capability's assertion is absent AND a stray fail record
    // exists for it — neither may gate while the row is deferred.
    let artifact = artifact_json(
        "sample-suite",
        "abc123",
        "sample-profile",
        "2026-07-01T11:00:00Z",
        &[
            ("sample.enforced.assertion", "pass"),
            ("sample.deferred.assertion", "fail"),
        ],
    );
    validate_live_artifact(&contract, &artifact, &expected_all(), fixed_now())
        .expect("deferred rows must not gate");

    // But the SAME artifact fails once the deferral marker is removed.
    let enforced_contract = test_contract("");
    let errors =
        validate_live_artifact(&enforced_contract, &artifact, &expected_all(), fixed_now())
            .expect_err("undeferring the row must enforce its assertion");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("sample.deferred.assertion")),
        "{errors:?}"
    );
}

#[test]
fn live_contract_rejects_duplicate_assertion_ids() {
    let contract = deferred_contract();
    let artifact = artifact_json(
        "sample-suite",
        "abc123",
        "sample-profile",
        "2026-07-01T11:00:00Z",
        &[
            ("sample.enforced.assertion", "pass"),
            ("sample.enforced.assertion", "pass"),
        ],
    );
    let errors = validate_live_artifact(&contract, &artifact, &expected_all(), fixed_now())
        .expect_err("duplicate ids must fail");
    assert!(
        errors.iter().any(|error| error.contains("more than once")),
        "{errors:?}"
    );
}

#[test]
fn live_contract_rejects_suite_commit_profile_and_schema_mismatches() {
    let contract = deferred_contract();

    let wrong_suite = artifact_json(
        "typo-suite",
        "abc123",
        "sample-profile",
        "2026-07-01T11:00:00Z",
        &[("sample.enforced.assertion", "pass")],
    );
    let errors = validate_live_artifact(&contract, &wrong_suite, &expected_all(), fixed_now())
        .expect_err("suite mismatch must fail");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("does not match expected suite")),
        "{errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("matches no GA-contract capability")),
        "a typo'd suite must not pass vacuously: {errors:?}"
    );

    let wrong_commit = artifact_json(
        "sample-suite",
        "stale00",
        "sample-profile",
        "2026-07-01T11:00:00Z",
        &[("sample.enforced.assertion", "pass")],
    );
    let errors = validate_live_artifact(&contract, &wrong_commit, &expected_all(), fixed_now())
        .expect_err("commit mismatch must fail");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("stale artifact from an earlier build")),
        "{errors:?}"
    );

    let wrong_profile = artifact_json(
        "sample-suite",
        "abc123",
        "typo-profile",
        "2026-07-01T11:00:00Z",
        &[("sample.enforced.assertion", "pass")],
    );
    let errors = validate_live_artifact(&contract, &wrong_profile, &expected_all(), fixed_now())
        .expect_err("profile mismatch must fail");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("expects platform_profile")),
        "{errors:?}"
    );

    let wrong_schema = serde_json::json!({
        "schema_version": 2,
        "suite": "sample-suite",
        "commit": "abc123",
        "platform_profile": "sample-profile",
        "created_at": "2026-07-01T11:00:00Z",
        "assertions": [{"id": "sample.enforced.assertion", "status": "pass"}],
    })
    .to_string();
    let errors = validate_live_artifact(&contract, &wrong_schema, &expected_all(), fixed_now())
        .expect_err("schema_version mismatch must fail");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("schema_version 2 is unsupported")),
        "{errors:?}"
    );
}

#[test]
fn live_contract_rejects_stale_and_unparseable_created_at() {
    let contract = deferred_contract();
    let stale = artifact_json(
        "sample-suite",
        "abc123",
        "sample-profile",
        "2026-06-28T11:00:00Z",
        &[("sample.enforced.assertion", "pass")],
    );
    let errors = validate_live_artifact(&contract, &stale, &expected_all(), fixed_now())
        .expect_err("stale created_at must fail");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("older than the 6h freshness bound")),
        "{errors:?}"
    );

    let garbled = artifact_json(
        "sample-suite",
        "abc123",
        "sample-profile",
        "not-a-timestamp",
        &[("sample.enforced.assertion", "pass")],
    );
    let errors = validate_live_artifact(&contract, &garbled, &expected_all(), fixed_now())
        .expect_err("unparseable created_at must fail");
    assert!(
        errors.iter().any(|error| error.contains("not RFC3339")),
        "{errors:?}"
    );
}

#[test]
fn live_contract_real_contract_declares_the_sidecar_suite_rows() {
    // Pin the real ga_contract.yaml against this validator: the Stable
    // sidecar surface is enrolled vertically (STRICT mTLS, authz ALLOW/DENY,
    // RequestAuth JWT, DR connectTimeout + maxConnections, VS CORS, SPIFFE
    // identity plumbing, DestinationRule namespace security, and the native
    // MeshSubscribe config transport are ENFORCED and emitted by
    // tests/k8s/mesh_e2e_sidecar/run.sh.
    let contract = load_contract().expect("real contract loads");
    let sidecar_rows: Vec<_> = contract
        .ga_capabilities()
        .into_iter()
        .filter(|capability| capability.live_suite == "mesh-e2e-sidecar")
        .collect();
    assert!(
        !sidecar_rows.is_empty(),
        "the mesh-e2e-sidecar suite must have GA contract rows"
    );
    let enforced_ids: Vec<&str> = sidecar_rows
        .iter()
        .filter(|capability| capability.live_deferred.is_none())
        .flat_map(|capability| capability.live_assertions.iter().map(String::as_str))
        .collect();
    for required in [
        "sidecar.spire.workload_entries",
        "sidecar.peer_auth.strict_mtls_authenticated",
        "sidecar.peer_auth.strict_mtls_plaintext_rejected",
        "sidecar.authz.denied_principal_rejected",
        "sidecar.request_auth.valid_jwt_admitted",
        "sidecar.request_auth.missing_jwt_rejected",
        "sidecar.request_auth.invalid_jwt_rejected",
        "sidecar.destination_rule.tcp_connect_timeout",
        "sidecar.destination_rule.export_to_namespace_visibility",
        "sidecar.destination_rule.lookup_tier_client_wins",
        "sidecar.destination_rule.tcp_max_connections",
        "sidecar.virtual_service.cors_policy",
        "sidecar.config.native_subscribe_delivered",
        "sidecar.config.native_subscribe_mtls_omitted_client_rejected",
        "sidecar.config.native_subscribe_mtls_foreign_client_rejected",
        "sidecar.config.native_subscribe_tls_untrusted_server_ca_rejected",
        "sidecar.config.native_subscribe_tls_wrong_san_rejected",
        "sidecar.config.native_subscribe_jwt_rejected",
        "sidecar.config.native_subscribe_tls_rotation_reconnects",
    ] {
        assert!(
            enforced_ids.contains(&required),
            "`{required}` must be an enforced GA live assertion"
        );
    }
    let deferred: Vec<&str> = sidecar_rows
        .iter()
        .filter(|capability| capability.live_deferred.is_some())
        .map(|capability| capability.id.as_str())
        .collect();
    assert!(
        deferred.is_empty(),
        "no sidecar GA contract row may remain live-deferred (found: {deferred:?})"
    );
    for capability in sidecar_rows
        .iter()
        .filter(|capability| capability.live_deferred.is_none())
    {
        assert_eq!(
            capability.platform_profile, "kind-spire-sidecar",
            "enforced sidecar rows must pin the fixture's platform profile"
        );
    }
    assert!(
        matches!(contract.ga_capabilities().first(), Some(first) if first.maturity == ContractMaturity::Ga),
        "ga_capabilities must return GA rows"
    );
}

/// Bind the sidecar fixture's `REQUIRED_LIVE_ASSERTIONS` to the enforced
/// `mesh-e2e-sidecar` GA-contract ids (same shape as the multicluster
/// fixture/gate tests). Dropping a native mTLS/JWT/SAN/rotation negative from
/// the array, or adding an enforced contract row the fixture never requires,
/// fails ordinary conformance CI.
#[test]
fn live_contract_sidecar_fixture_requires_exactly_the_enforced_rows() {
    const RUN_SH: &str = include_str!("../k8s/mesh_e2e_sidecar/run.sh");

    let mut lines = RUN_SH.lines();
    assert!(
        lines.any(|line| line.trim_end() == "REQUIRED_LIVE_ASSERTIONS=("),
        "tests/k8s/mesh_e2e_sidecar/run.sh must declare REQUIRED_LIVE_ASSERTIONS=( \
         on its own line — the fixture's fail-closed gate is what this test binds \
         to the GA contract"
    );
    let mut fixture_required: BTreeSet<&str> = BTreeSet::new();
    let mut closed = false;
    for line in lines {
        let trimmed = line.trim();
        if trimmed == ")" {
            closed = true;
            break;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        assert!(
            fixture_required.insert(trimmed),
            "run.sh REQUIRED_LIVE_ASSERTIONS lists `{trimmed}` more than once"
        );
    }
    assert!(
        closed,
        "run.sh REQUIRED_LIVE_ASSERTIONS array is unterminated — refusing to \
         validate a partially parsed required set"
    );

    let contract = load_contract().expect("real contract loads");
    let contract_required: BTreeSet<&str> = contract
        .ga_capabilities()
        .into_iter()
        .filter(|capability| {
            capability.live_suite == "mesh-e2e-sidecar" && capability.live_deferred.is_none()
        })
        .flat_map(|capability| capability.live_assertions.iter().map(String::as_str))
        .collect();
    assert!(
        !contract_required.is_empty(),
        "the mesh-e2e-sidecar suite must have enforced GA contract rows"
    );

    let missing_in_fixture: Vec<&&str> = contract_required.difference(&fixture_required).collect();
    assert!(
        missing_in_fixture.is_empty(),
        "GA-contract assertions the live fixture does not REQUIRE (they could be \
         skipped or absent without failing the live job): {missing_in_fixture:?}"
    );
    let missing_in_contract: Vec<&&str> = fixture_required.difference(&contract_required).collect();
    assert!(
        missing_in_contract.is_empty(),
        "live fixture requires assertions with no enforced GA-contract row \
         (add the row, or drop the id from REQUIRED_LIVE_ASSERTIONS): \
         {missing_in_contract:?}"
    );
}

/// Unquoted `<<YAML` heredocs expand shell metacharacters. Backticks inside
/// heredoc data (even YAML comments) are executed as command substitution —
/// the hosted mesh-e2e-sidecar live job failed at `render_client_config` when
/// a `beta/drsvc` comment was interpreted as a command.
#[test]
fn live_contract_sidecar_run_sh_unquoted_yaml_heredocs_avoid_backticks() {
    const RUN_SH: &str = include_str!("../k8s/mesh_e2e_sidecar/run.sh");
    let mut in_unquoted_yaml_heredoc = false;
    for (line_no, line) in RUN_SH.lines().enumerate() {
        let trimmed = line.trim();
        if !in_unquoted_yaml_heredoc {
            if line.contains("<<YAML") && !line.contains("<<'YAML'") && !line.contains("<<\"YAML\"")
            {
                in_unquoted_yaml_heredoc = true;
            }
            continue;
        }
        if trimmed == "YAML" || trimmed.starts_with("YAML)") {
            in_unquoted_yaml_heredoc = false;
            continue;
        }
        assert!(
            !line.contains('`'),
            "run.sh:{}: backticks inside an unquoted YAML heredoc are executed \
             as command substitution — keep shell metacharacters out of heredoc data",
            line_no + 1
        );
    }
    assert!(
        !in_unquoted_yaml_heredoc,
        "run.sh ended while still inside an unquoted YAML heredoc — parse guard is broken"
    );
}

/// Unquoted `<<EOF` heredocs in the NodeWaypoint eBPF live harness interpolate
/// `$UNMANAGED_NS` / `$DTLS_CLIENT_IMAGE`. Markdown backticks in YAML comments
/// inside that expandable body are command substitutions: hosted run
/// 33219677886 failed with `skb_scrub_packet: command not found` before
/// admission.
#[test]
fn live_contract_node_waypoint_ebpf_run_sh_unquoted_eof_heredocs_avoid_backticks() {
    const RUN_SH: &str = include_str!("../k8s/node_waypoint_ebpf_live/run.sh");
    let mut in_unquoted_eof_heredoc = false;
    for (line_no, line) in RUN_SH.lines().enumerate() {
        let trimmed = line.trim();
        if !in_unquoted_eof_heredoc {
            if line.contains("<<EOF") && !line.contains("<<'EOF'") && !line.contains("<<\"EOF\"") {
                in_unquoted_eof_heredoc = true;
            }
            continue;
        }
        if trimmed == "EOF" || trimmed.starts_with("EOF)") {
            in_unquoted_eof_heredoc = false;
            continue;
        }
        assert!(
            !line.contains('`'),
            "run.sh:{}: backticks inside an unquoted EOF heredoc are executed \
             as command substitution — keep shell metacharacters out of heredoc data",
            line_no + 1
        );
    }
    assert!(
        !in_unquoted_eof_heredoc,
        "run.sh ended while still inside an unquoted EOF heredoc — parse guard is broken"
    );
}

/// Issue #3855: the release-blocking native MeshSubscribe deployments must
/// keep the production mTLS + JWT + Service-DNS posture. A PR that silently
/// restores plaintext h2c, TLS_NO_VERIFY, or drops client-CA/client-cert
/// controls fails this hosted conformance pin even if the live job is skipped.
#[test]
fn live_contract_sidecar_native_subscribe_fixture_is_mtls_jwt() {
    const MANIFESTS: &str = include_str!("../k8s/mesh_e2e_sidecar/manifests.yaml");
    const RUN_SH: &str = include_str!("../k8s/mesh_e2e_sidecar/run.sh");
    const CONTRACT: &str = include_str!("ga_contract.yaml");

    for required in [
        "FERRUM_CP_GRPC_TLS_CERT_PATH",
        "FERRUM_CP_GRPC_TLS_KEY_PATH",
        "FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH",
        "FERRUM_DP_GRPC_TLS_CA_CERT_PATH",
        "FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH",
        "FERRUM_DP_GRPC_TLS_CLIENT_KEY_PATH",
        "https://ferrum-cp.__NAMESPACE__.svc.cluster.local:50051",
        "ferrum-native-mtls-cp",
        "ferrum-native-mtls-dp",
        "projected:",
        "native-mtls-probe",
        "FERRUM_CP_DP_GRPC_JWT_SECRET",
    ] {
        assert!(
            MANIFESTS.contains(required),
            "mesh-e2e-sidecar manifests must keep `{required}` on the native MeshSubscribe leg"
        );
    }
    assert!(
        !MANIFESTS.contains("FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT"),
        "release-blocking native MeshSubscribe manifests must not enable plaintext"
    );
    assert!(
        !MANIFESTS.contains("FERRUM_DP_GRPC_TLS_NO_VERIFY"),
        "release-blocking native MeshSubscribe manifests must not skip TLS verify"
    );
    assert!(
        !MANIFESTS.contains("http://ferrum-cp."),
        "release-blocking native MeshSubscribe DP URL must not be plaintext h2c"
    );
    assert!(
        !RUN_SH.contains("FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT"),
        "run.sh must not restore the plaintext CP/DP gRPC override"
    );
    assert!(
        !RUN_SH.contains("FERRUM_DP_GRPC_TLS_NO_VERIFY"),
        "run.sh must not restore TLS_NO_VERIFY"
    );
    assert!(
        !RUN_SH.contains("http://ferrum-cp."),
        "run.sh must not restore a plaintext h2c ferrum-cp URL"
    );
    assert!(
        RUN_SH.contains("mint_native_mtls_pki"),
        "run.sh must mint ephemeral native MeshSubscribe PKI at run time"
    );
    assert!(
        RUN_SH.contains("apply_native_mtls_secrets gen2"),
        "run.sh must swap projected Secret generations for the rotation proof"
    );
    assert!(
        RUN_SH.contains("openssl s_client"),
        "run.sh must observe the post-rotation CP leaf over a real TLS handshake"
    );
    assert!(
        RUN_SH.contains("sidecar.config.native_subscribe_mtls_omitted_client_rejected"),
        "run.sh must emit the omitted-client negative"
    );
    assert!(
        RUN_SH.contains("sidecar.config.native_subscribe_tls_rotation_reconnects"),
        "run.sh must emit the projected-Secret rotation assertion"
    );
    assert!(
        !CONTRACT.contains("plaintext h2c with JWT"),
        "ga_contract.yaml must not describe the native transport row as plaintext-only"
    );
    assert!(
        !CONTRACT.contains("CP-DP gRPC TLS is an orthogonal"),
        "ga_contract.yaml must not describe CP/DP TLS as orthogonal to the native live row"
    );
}

fn native_evid_assignment_line(trimmed_line: &str, reason: &str) -> bool {
    let Some((name, value)) = trimmed_line.split_once('=') else {
        return false;
    };
    let allowed_name = match reason {
        "peer sent no certificates" => "NATIVE_EVID_CP_NO_CERT",
        "Invalid token: authentication failed" => "NATIVE_EVID_CP_JWT_AUTH_FAILED",
        _ => return false,
    };

    name == allowed_name
        && value.len() >= 2
        && value.starts_with('\'')
        && value.ends_with('\'')
        && !value[1..value.len() - 1].contains('\'')
}

/// CP rejection reason literals are allowed only on closed-set `NATIVE_EVID_*`
/// expectation constants (helper-produced evidence labels). Any other line
/// that embeds those reasons is generic ferrum-cp log matching.
fn run_sh_has_generic_cp_reason_literal(run_sh: &str, reason: &str) -> bool {
    run_sh.lines().any(|line| {
        let trimmed = line.trim_start();
        !native_evid_assignment_line(trimmed, reason) && line.contains(reason)
    })
}

fn native_probe_classifier_contract_violations(
    run_sh: &str,
    helper: &str,
    manifests: &str,
) -> Vec<String> {
    let mut errors = Vec::new();

    for (needle, desc) in [
        (
            "native_probe_classify.py",
            "run.sh must invoke the native probe classifier helper",
        ),
        (
            "--running-identity",
            "run.sh must obtain the running probe pod identity from the API",
        ),
        (
            "--classify",
            "run.sh must classify through the helper, not a client-log-only grep",
        ),
        (
            "--evidence-out",
            "run.sh must store redacted server-side probe evidence",
        ),
        (
            "--pod-name",
            "run.sh must pass the exact probe pod/node name into classification",
        ),
        (
            "--pod-ip",
            "run.sh must pass the exact probe pod IP into classification",
        ),
        (
            "logs deploy/ferrum-cp",
            "run.sh must collect ferrum-cp logs for correlated CP evidence",
        ),
        (
            "get pod -l \"app=${deploy}\"",
            "run.sh must read the running probe pod from the Kubernetes API",
        ),
    ] {
        if !run_sh.contains(needle) {
            errors.push(format!(
                "native probe classifier missing {desc} (`{needle}`)"
            ));
        }
    }

    for banned in [
        "peer sent no certificates",
        "Tenant subscription rejected",
        "Invalid token: authentication failed",
    ] {
        if run_sh_has_generic_cp_reason_literal(run_sh, banned) {
            errors.push(format!(
                "run.sh must not match CP rejection reason `{banned}` itself — \
                 that is generic CP-log matching; the helper owns exact correlation"
            ));
        }
    }

    for (needle, desc) in [
        (
            "exact_field_equals",
            "literal field equality so pod IPs/node ids are never regex-interpolated",
        ),
        (
            "cp_tls_rejection_for_pod",
            "TLS rejection correlated to the exact probe pod IP",
        ),
        (
            "cp_jwt_rejection_for_node",
            "JWT rejection correlated to the exact probe node_id",
        ),
        (
            "CP gRPC TLS handshake failed",
            "fixed CP TLS handshake rejection message",
        ),
        (
            "peer sent no certificates",
            "fixed omit-client rustls reason",
        ),
        (
            "invalid peer certificate: UnknownIssuer",
            "fixed foreign-client rustls reason",
        ),
        (
            "Tenant subscription rejected",
            "fixed CP tenant-subscription rejection message",
        ),
        (
            "Invalid token: authentication failed",
            "fixed invalid-JWT reason",
        ),
        (
            "MeshConfigSync.MeshSubscribe",
            "JWT evidence bound to the MeshSubscribe surface",
        ),
        (
            "slice-accepted-overrides-cp-reject",
            "self-test that a delivered slice remains slice-accepted",
        ),
        (
            "reject-unrelated-cp-ip",
            "self-test that an unrelated CP TLS rejection is not accepted",
        ),
        (
            "reject-unrelated-node-id",
            "self-test that an unrelated CP JWT rejection is not accepted",
        ),
        (
            "connected-does-not-override-cp-tls",
            "self-test that Connected to CP does not hide CP TLS rejection",
        ),
        (
            "connected-does-not-override-cp-jwt",
            "self-test that Connected to CP does not hide CP JWT rejection",
        ),
        (
            "untrusted-ca-stays-client-side",
            "self-test that untrusted-CA stays a client-side tls-verify class",
        ),
        (
            "wrong-san-stays-client-side",
            "self-test that wrong-SAN stays a client-side tls-name class",
        ),
        (
            "hosted-untrusted-ca-native-tls-class",
            "self-test that hosted native_tls_class=client_tls_verify pins tls-verify",
        ),
        (
            "hosted-wrong-san-native-tls-class",
            "self-test that hosted native_tls_class=client_tls_name pins tls-name",
        ),
        (
            "flattened-tonic-error-is-not-client-verify-proof",
            "self-test that a flattened tonic transport error is not tls-verify",
        ),
        (
            "json-error-text-is-not-native-tls-class",
            "self-test that native_tls_class mentioned only in error text is ignored",
        ),
        (
            "native_tls_class",
            "classifier consumes the closed-set native_tls_class log field",
        ),
        (
            "preserve-client-jwt-negative",
            "self-test that client UNAUTHENTICATED still classifies as jwt",
        ),
        (
            "client_slice_accepted",
            "slice-delivery false-positive evidence label",
        ),
        (
            "is_dns1123_label",
            "Kubernetes-safe pod/node identity validation",
        ),
        ("is_pod_ip", "Kubernetes-safe pod IP validation"),
        (
            "ROTATION_ACCEPTED_EVIDENCE",
            "classifier pins rotation accepted-connect evidence",
        ),
        (
            "Tenant subscription accepted",
            "exact CP MeshSubscribe success audit message",
        ),
        (
            "cp_subscribe_accepted_count",
            "CP MeshSubscribe accept count correlated to exact node_id",
        ),
        (
            "client_tls_connected_count",
            "capp post-TLS connect count correlated to exact node_id",
        ),
        (
            "rotation_fresh_evidence",
            "pre/post freshness comparison for rotation reconnect",
        ),
        (
            "reconnect-attempt-is-not-accepted-proof",
            "self-test that reconnect-attempt logs are not accepts",
        ),
        (
            "reload-log-is-not-accepted-proof",
            "self-test that TLS reload logs are not accepts",
        ),
        (
            "pre-rotation-count-is-not-post-proof",
            "self-test that the pre-swap count cannot satisfy post-swap",
        ),
        (
            "one-half-increase-is-not-fresh-proof",
            "self-test that one half of the rotation proof is not enough",
        ),
        (
            "exact-capp-node-id-accepted",
            "self-test that MeshSubscribe accepts use exact node_id",
        ),
        (
            "connected-without-node-id-is-not-tls-connect-proof",
            "self-test that Connected-to-CP without node_id is not proof",
        ),
        (
            "ROTATION_RELOAD_ANCHORS",
            "classifier pins TLS reload surfaces as generation anchors",
        ),
        (
            "TLS_RELOAD_SURFACE_DP",
            "capp dp_grpc reload surface constant",
        ),
        (
            "TLS_RELOAD_SURFACE_CP",
            "CP cp_grpc reload surface constant",
        ),
        (
            "accepts-before-reload-anchor-are-not-fresh-proof",
            "self-test that count increases before reload anchors are not proof",
        ),
        (
            "reload-anchor-without-later-accept-is-not-proof",
            "self-test that reload anchors without later accepts are not proof",
        ),
        (
            "wrong-reload-surface-is-not-anchor",
            "self-test that the wrong TLS reload surface is not an anchor",
        ),
        (
            "one-post-anchor-event-is-not-fresh-proof",
            "self-test that only one post-anchor event is not enough",
        ),
        (
            "prefix-node-id-is-not-post-anchor-proof",
            "self-test that prefix-overlapping node ids are not post-anchor proof",
        ),
    ] {
        if !helper.contains(needle) {
            errors.push(format!(
                "native probe classifier helper missing {desc} (`{needle}`)"
            ));
        }
    }

    if helper.contains("re.compile(pod_ip")
        || helper.contains("re.search(pod_ip")
        || helper.contains("re.search(node_id")
        || helper.contains("re.compile(node_id")
        || helper.contains("grep -Fq 'peer sent no certificates'")
    {
        errors.push(
            "classifier helper must not compile probe identity into a regex or \
             fall back to generic CP reason greps"
                .into(),
        );
    }

    if !manifests.contains("ferrum_edge::modes::control_plane=debug") {
        errors.push(
            "ferrum-cp FERRUM_LOG_LEVEL must emit CP gRPC TLS handshake debug \
             lines so omit-client/foreign-client evidence is collectable"
                .into(),
        );
    }

    errors
}

fn native_mtls_negative_control_contract_violations(run_sh: &str, helper: &str) -> Vec<String> {
    let mut errors = Vec::new();

    for banned in [
        "'tls-handshake|tls-verify'",
        "'tls-verify|tls-handshake'",
        "'tls-name|tls-verify|tls-handshake'",
        "^(tls-handshake|tls-verify)$",
    ] {
        if run_sh.contains(banned) {
            errors.push(format!(
                "run.sh must not accept broad native negative TLS classes (`{banned}`)"
            ));
        }
    }

    for (needle, desc) in [
        (
            "NATIVE_EVID_CP_NO_CERT=",
            "exact CP omit-client evidence constant",
        ),
        (
            "NATIVE_EVID_CP_UNKNOWN_ISSUER=",
            "exact CP UnknownIssuer evidence constant",
        ),
        (
            "NATIVE_EVID_CLIENT_SERVER_VERIFY=",
            "client-side server-verify evidence constant",
        ),
        (
            "NATIVE_EVID_CLIENT_TLS_NAME=",
            "client-side hostname/SAN evidence constant",
        ),
        (
            "NATIVE_EVID_CP_JWT_AUTH_FAILED=",
            "exact CP MeshSubscribe JWT rejection evidence constant",
        ),
        (
            "native-omit-client tls-handshake \"$NATIVE_EVID_CP_NO_CERT\"",
            "omitted-client requires tls-handshake plus CP no-cert evidence",
        ),
        (
            "native-foreign-client tls-verify \"$NATIVE_EVID_CP_UNKNOWN_ISSUER\"",
            "foreign-client requires tls-verify plus CP UnknownIssuer evidence",
        ),
        (
            "native-untrusted-ca tls-verify \"$NATIVE_EVID_CLIENT_SERVER_VERIFY\"",
            "untrusted-server-CA requires client-side tls-verify evidence",
        ),
        (
            "native-wrong-san tls-name \"$NATIVE_EVID_CLIENT_TLS_NAME\"",
            "wrong-SAN requires client-side tls-name evidence",
        ),
        (
            "native-jwt-invalid jwt \"$NATIVE_EVID_CP_JWT_AUTH_FAILED\"",
            "invalid-JWT requires jwt plus CP MeshSubscribe auth-failure evidence",
        ),
        (
            "wait_for_native_probe_class native-stale-client tls-verify",
            "post-rotation stale client requires tls-verify (not generic handshake)",
        ),
        (
            "stale_evidence=$stale_ev",
            "rotation gate records stale-client classifier evidence",
        ),
        (
            "printf '%s' \"$stale_ev\" | grep -Eq \"$NATIVE_EVID_CP_UNKNOWN_ISSUER\"",
            "rotation gate requires CP UnknownIssuer evidence for gen1 stale client",
        ),
        (
            "printf '%s' \"$reconnect_ev\" | grep -Fq \"cp_subscribe_accepted node_id=\"",
            "rotation gate requires helper cp_subscribe_accepted evidence for capp",
        ),
        (
            "printf '%s' \"$reconnect_ev\" | grep -Fq \"client_tls_connect before=\"",
            "rotation gate requires helper client_tls_connect freshness evidence",
        ),
        (
            "printf '%s' \"$reconnect_ev\" | grep -Fq \"dp_grpc_anchor=1\"",
            "rotation gate requires a post-baseline dp_grpc reload anchor",
        ),
        (
            "printf '%s' \"$reconnect_ev\" | grep -Fq \"cp_grpc_anchor=1\"",
            "rotation gate requires a post-baseline cp_grpc reload anchor",
        ),
        (
            "printf '%s' \"$reconnect_ev\" | grep -Fq \"client_post_anchor=1\"",
            "rotation gate requires a Connected-to-CP after the dp_grpc reload",
        ),
        (
            "printf '%s' \"$reconnect_ev\" | grep -Fq \"cp_post_anchor=1\"",
            "rotation gate requires a Tenant subscription accepted after the cp_grpc reload",
        ),
        (
            "wait_for_native_probe_class \"$deploy\" \"$want_pattern\" \"$want_evidence\"",
            "negative wait loop must gate on classifier evidence, not class alone",
        ),
        (
            "normalize_native_evidence_file",
            "server evidence must strip tr newline trailing space before anchored grep",
        ),
        (
            "normalize_native_evidence_file \"$RESULTS_DIR/${deploy}.server-evidence.txt\"",
            "negative wait/record loops must normalize classifier evidence before grep",
        ),
    ] {
        if !run_sh.contains(needle) {
            errors.push(format!("run.sh missing {desc} (`{needle}`)"));
        }
    }

    for (needle, desc) in [
        (
            "CONTROL_EVIDENCE = {",
            "classifier pins per-control evidence expectations",
        ),
        (
            "generic-client-handshake-is-not-cp-omit-proof",
            "classifier self-test that generic handshake is not CP omit proof",
        ),
        (
            "client-jwt-alone-is-not-cp-meshsubscribe-proof",
            "classifier self-test that client UNAUTH alone is not CP JWT proof",
        ),
        (
            "hosted-untrusted-ca-native-tls-class",
            "classifier self-test for hosted untrusted-CA native_tls_class evidence",
        ),
        (
            "hosted-wrong-san-native-tls-class",
            "classifier self-test for hosted wrong-SAN native_tls_class evidence",
        ),
        (
            "flattened-tonic-error-is-not-client-verify-proof",
            "classifier self-test that flattened tonic errors stay handshake",
        ),
        (
            "ROTATION_ACCEPTED_EVIDENCE",
            "classifier pins rotation accepted-connect evidence",
        ),
        (
            "Tenant subscription accepted",
            "exact CP MeshSubscribe success audit message",
        ),
        (
            "cp_subscribe_accepted_count",
            "CP MeshSubscribe accept count correlated to exact node_id",
        ),
        (
            "client_tls_connected_count",
            "capp post-TLS connect count correlated to exact node_id",
        ),
        (
            "rotation_fresh_evidence",
            "pre/post freshness comparison for rotation reconnect",
        ),
        (
            "reconnect-attempt-is-not-accepted-proof",
            "classifier self-test that reconnect-attempt logs are not accepts",
        ),
        (
            "pre-rotation-count-is-not-post-proof",
            "classifier self-test that the pre-swap count cannot satisfy post-swap",
        ),
        (
            "ROTATION_RELOAD_ANCHORS",
            "classifier pins TLS reload surfaces as generation anchors",
        ),
        (
            "accepts-before-reload-anchor-are-not-fresh-proof",
            "classifier self-test that count increases before reload anchors are not proof",
        ),
        (
            "reload-anchor-without-later-accept-is-not-proof",
            "classifier self-test that reload anchors without later accepts are not proof",
        ),
        (
            "wrong-reload-surface-is-not-anchor",
            "classifier self-test that the wrong TLS reload surface is not an anchor",
        ),
        (
            "one-post-anchor-event-is-not-fresh-proof",
            "classifier self-test that only one post-anchor event is not enough",
        ),
        (
            "prefix-node-id-is-not-post-anchor-proof",
            "classifier self-test that prefix-overlapping node ids are not post-anchor proof",
        ),
    ] {
        if !helper.contains(needle) {
            errors.push(format!(
                "native probe classifier helper missing {desc} (`{needle}`)"
            ));
        }
    }

    errors
}

/// Issue #3855 hosted Mesh E2E Sidecar: omit-client, foreign-client, and
/// invalid-JWT were classified `connected-without-jwt-class` from the client
/// `Connected to CP` line even though ferrum-cp had already rejected each
/// probe. Classification must consume CP evidence correlated to the exact
/// running pod IP (TLS) or node_id (JWT), keep slice-accepted as a hard
/// false-positive, and must not treat an unrelated CP rejection as proof.
#[test]
fn live_contract_sidecar_native_probe_classifier_correlates_cp_evidence() {
    const RUN_SH: &str = include_str!("../k8s/mesh_e2e_sidecar/run.sh");
    const HELPER: &str = include_str!("../k8s/lib/native_probe_classify.py");
    const MANIFESTS: &str = include_str!("../k8s/mesh_e2e_sidecar/manifests.yaml");

    let violations = native_probe_classifier_contract_violations(RUN_SH, HELPER, MANIFESTS);
    assert!(
        violations.is_empty(),
        "native probe classifier must correlate exact CP evidence: {violations:?}"
    );

    let negative_violations = native_mtls_negative_control_contract_violations(RUN_SH, HELPER);
    assert!(
        negative_violations.is_empty(),
        "native negative controls must require control-specific evidence: {negative_violations:?}"
    );

    let broad_negative_proof = r#"
record_native_negative sidecar.config.native_subscribe_mtls_omitted_client_rejected \
  native-omit-client 'tls-handshake|tls-verify' || failed=true
record_native_negative sidecar.config.native_subscribe_tls_wrong_san_rejected \
  native-wrong-san 'tls-name|tls-verify|tls-handshake' || failed=true
stale_class="$(wait_for_native_probe_class native-stale-client 'tls-handshake|tls-verify')"
"#;
    let broad_violations =
        native_mtls_negative_control_contract_violations(broad_negative_proof, HELPER);
    assert!(
        !broad_violations.is_empty(),
        "contract must reject broad native negative TLS class alternation"
    );
    assert!(
        broad_violations
            .iter()
            .any(|error| error.contains("broad native negative TLS")),
        "broad-pattern rejection must name the alternation, got {broad_violations:?}"
    );

    let generic_cp_grep = r#"
classify_native_probe() {
  logs="$(native_probe_logs "$deploy")"
  cp="$(kubectl logs deploy/ferrum-cp)"
  if printf '%s' "$cp" | grep -Fq 'peer sent no certificates'; then
    printf 'tls-handshake'
  elif printf '%s' "$cp" | grep -Fq 'Tenant subscription rejected'; then
    printf 'jwt'
  elif printf '%s' "$logs" | grep -Fq 'Connected to CP, subscribing for native mesh config'; then
    printf 'connected-without-jwt-class'
  fi
}
"#;
    let generic_violations =
        native_probe_classifier_contract_violations(generic_cp_grep, HELPER, MANIFESTS);
    assert!(
        generic_violations.iter().any(|error| {
            error.contains("generic CP-log matching") || error.contains("native_probe_classify.py")
        }),
        "contract must reject generic ferrum-cp reason greps, got {generic_violations:?}"
    );

    let renamed_cp_grep = r#"
native_probe_classify.py
--running-identity
--classify
--evidence-out
--pod-name
--pod-ip
logs deploy/ferrum-cp
get pod -l "app=${deploy}"
classify_native_probe() {
  cp="$(kubectl logs deploy/ferrum-cp)"
  peer_reason='peer sent no certificates'
  if printf '%s' "$cp" | grep -Fq "$peer_reason"; then
    printf 'tls-handshake'
  fi
}
"#;
    let renamed_violations =
        native_probe_classifier_contract_violations(renamed_cp_grep, HELPER, MANIFESTS);
    assert!(
        renamed_violations
            .iter()
            .any(|error| error.contains("generic CP-log matching")),
        "contract must reject CP reason literals even when grep uses a renamed variable, \
         got {renamed_violations:?}"
    );

    let prefixed_renamed_cp_grep = renamed_cp_grep.replace(
        "peer_reason='peer sent no certificates'",
        "NATIVE_EVID_PEER_REASON='peer sent no certificates'",
    );
    let prefixed_renamed_cp_grep =
        prefixed_renamed_cp_grep.replace("$peer_reason", "$NATIVE_EVID_PEER_REASON");
    let prefixed_renamed_violations =
        native_probe_classifier_contract_violations(&prefixed_renamed_cp_grep, HELPER, MANIFESTS);
    assert!(
        prefixed_renamed_violations
            .iter()
            .any(|error| error.contains("generic CP-log matching")),
        "contract must reject CP reason literals hidden behind arbitrary NATIVE_EVID_ names, \
         got {prefixed_renamed_violations:?}"
    );

    let no_slice_guard = r#"
native_probe_classify.py
--running-identity
--classify
--evidence-out
--pod-name
--pod-ip
logs deploy/ferrum-cp
get pod -l "app=${deploy}"
"#;
    let helper_no_slice =
        HELPER.replace("slice-accepted-overrides-cp-reject", "removed-slice-guard");
    let no_slice_violations =
        native_probe_classifier_contract_violations(no_slice_guard, &helper_no_slice, MANIFESTS);
    assert!(
        no_slice_violations
            .iter()
            .any(|error| error.contains("slice-accepted-overrides-cp-reject")),
        "contract must notice removal of the slice-delivery false-positive guard, \
         got {no_slice_violations:?}"
    );

    let helper_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/k8s/lib/native_probe_classify.py");
    let output = Command::new("python3")
        .arg("-I")
        .arg(&helper_path)
        .arg("--self-test")
        .output()
        .expect("spawn python3 for native_probe_classify.py --self-test");
    assert!(
        output.status.success(),
        "native_probe_classify.py --self-test failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn bash_function_name(trimmed: &str) -> Option<&str> {
    let idx = trimmed.find("()")?;
    let name = trimmed[..idx].trim();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    if trimmed[idx + 2..].trim_start().starts_with('{') {
        Some(name)
    } else {
        None
    }
}

fn bash_function_body(source: &str, name: &str) -> String {
    let needle = format!("{name}()");
    let lines: Vec<&str> = source.lines().collect();
    let Some(start) = lines.iter().position(|line| {
        let trimmed = line.trim();
        trimmed.starts_with(&needle) && trimmed[needle.len()..].trim_start().starts_with('{')
    }) else {
        return String::new();
    };
    let mut collected = Vec::new();
    let mut depth = 0i32;
    let mut started = false;
    for line in &lines[start..] {
        for ch in line.chars() {
            if ch == '{' {
                depth += 1;
                started = true;
            } else if ch == '}' {
                depth -= 1;
            }
        }
        collected.push(*line);
        if started && depth <= 0 {
            break;
        }
    }
    collected.join("\n")
}

fn non_comment_lines(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

fn bash_functions_publishing_observe_pid(source: &str) -> Vec<&str> {
    let mut names = Vec::new();
    let mut current = None;
    for line in source.lines() {
        let trimmed = line.trim();
        if let Some(name) = bash_function_name(trimmed) {
            current = Some(name);
            continue;
        }
        let Some(name) = current else {
            continue;
        };
        if trimmed.starts_with('#') || !line.contains("NATIVE_OBSERVE_PF_PID=\"$") {
            continue;
        }
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

fn command_word_is(s: &str, name: &str) -> bool {
    s.starts_with(name)
        && s[name.len()..]
            .chars()
            .next()
            .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'))
}

fn substitution_contains_command(source: &str, open: &str, close: &str, name: &str) -> bool {
    let mut rest = source;
    while let Some(idx) = rest.find(open) {
        let after_open = &rest[idx + open.len()..];
        let body = match after_open.find(close) {
            Some(end) => &after_open[..end],
            None => after_open,
        };
        if command_word_is(body.trim_start(), name) {
            return true;
        }
        rest = &rest[idx + open.len()..];
    }
    false
}

fn command_substitution_invokes_observe_helper(source: &str, names: &[&str]) -> bool {
    if names.is_empty() {
        return false;
    }
    let mut filtered = String::new();
    for line in source.lines() {
        if line.trim().starts_with('#') {
            continue;
        }
        filtered.push_str(line);
        filtered.push('\n');
    }
    names.iter().any(|name| {
        substitution_contains_command(&filtered, "$(", ")", name)
            || substitution_contains_command(&filtered, "`", "`", name)
    })
}

fn parent_shell_helper_call(trimmed: &str, name: &str) -> bool {
    let call = if let Some(rest) = trimmed.strip_prefix("if ") {
        rest.trim_start()
    } else {
        trimmed
    };
    if !call.starts_with(name) {
        return false;
    }
    match call[name.len()..].chars().next() {
        None => true,
        Some(c) if c == ';' || c.is_whitespace() => true,
        Some(_) => false,
    }
}

fn observe_helper_invoked_in_parent_shell(source: &str, names: &[&str]) -> bool {
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.contains("$(") || trimmed.contains('`') {
            continue;
        }
        if names
            .iter()
            .any(|name| parent_shell_helper_call(trimmed, name))
        {
            return true;
        }
    }
    false
}

fn live_serial_copied_from_parent_channel(source: &str) -> bool {
    source.lines().any(|line| {
        let trimmed = line.trim();
        !trimmed.starts_with('#')
            && (trimmed.contains("live_serial=\"${NATIVE_CP_SERVED_SERIAL")
                || trimmed.contains("live_serial=\"$NATIVE_CP_SERVED_SERIAL"))
    })
}

fn live_serial_captured_from_command_substitution(source: &str) -> bool {
    source.lines().any(|line| {
        let trimmed = line.trim();
        !trimmed.starts_with('#')
            && (trimmed.contains("live_serial=\"$(")
                || trimmed.contains("live_serial=$(")
                || trimmed.contains("live_serial=\"`")
                || trimmed.contains("live_serial=`"))
    })
}

/// Issue #3855 rotation gate: the live serial must come from the leaf
/// certificate served by the running CP over a verified mTLS handshake.
/// Decoding `Secret.data.server.pem` (or a mounted/expected server cert)
/// only proves the object store changed, not that ferrum-cp reloaded.
/// The helper that publishes `NATIVE_OBSERVE_PF_PID` must run in the parent
/// shell so EXIT cleanup and `NATIVE_CP_SERVED_CLASS`/`SERIAL` propagate.
fn native_rotation_observation_violations(source: &str) -> Vec<String> {
    let mut errors = Vec::new();

    if source.contains(".data.server")
        || source.contains("jsonpath='{.data.server")
        || source.contains("jsonpath=\"{.data.server")
        || source.contains("get secret ferrum-native-mtls-cp")
    {
        errors.push(
            "rotation live serial must not be decoded from Secret.data.server.pem \
             (that only proves the Secret object changed, not that the running CP \
             now serves the replacement leaf)"
                .into(),
        );
    }
    if source.contains("/transport/server.pem") {
        errors.push("rotation live serial must not be read from the mounted CP server cert".into());
    }
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if (trimmed.contains("live_serial=") || trimmed.contains("live_serial=\""))
            && (trimmed.contains("gen2-server.pem")
                || trimmed.contains("/server.pem")
                || trimmed.contains("get secret")
                || trimmed.contains(".data.server"))
        {
            errors.push(
                "live_serial assignment must not use a Kubernetes Secret, mounted \
                 file, or controller-local expected server cert"
                    .into(),
            );
        }
    }
    if source.contains("pkill") || source.contains("killall") {
        errors.push(
            "native CP observe helper must kill only the port-forward PID it created, \
             not pkill/killall"
                .into(),
        );
    }

    let required = [
        (
            "openssl s_client",
            "over-the-wire openssl s_client handshake to the running CP",
        ),
        (
            "-verify_return_error",
            "TLS verification fail-closed (-verify_return_error)",
        ),
        (
            "-verify_hostname",
            "Kubernetes Service DNS SAN verification (-verify_hostname)",
        ),
        ("-CAfile", "verification against the gen2 server CA file"),
        ("gen2-ca.pem", "gen2 server CA"),
        ("gen2-client.pem", "gen2 DP client certificate"),
        (
            "gen2-client-key.pem",
            "gen2 DP client key for required mTLS",
        ),
        (
            "port-forward",
            "kubectl port-forward to the live CP listener",
        ),
        ("50051", "CP gRPC listen port"),
        ("NATIVE_CP_DNS", "real Kubernetes Service DNS name"),
        (
            "NATIVE_SERVER_SERIAL_GEN2",
            "gate success on the gen2 server serial",
        ),
        (
            "NATIVE_CP_SERVED_SERIAL",
            "parent-shell served serial result channel",
        ),
        (
            "NATIVE_CP_SERVED_CLASS",
            "parent-shell observe class channel",
        ),
        (
            "NATIVE_OBSERVE_PF_PID",
            "parent-shell port-forward PID for EXIT cleanup",
        ),
        (
            "apply_native_mtls_secrets gen2",
            "projected Secret generation swap",
        ),
        (
            "sidecar.config.native_subscribe_tls_rotation_reconnects",
            "rotation assertion id",
        ),
        (
            "wait_for_native_rotation_evidence",
            "fresh capp MeshSubscribe accept evidence",
        ),
        (
            "capture_native_rotation_baseline",
            "pre-swap accepted-connect baseline for capp",
        ),
        ("--rotation-count", "helper pre-swap accepted-connect count"),
        ("--rotation-fresh", "helper post-swap freshness comparison"),
        (
            "NATIVE_ROTATION_BASELINE_CAPTURED",
            "rotation wait must require a captured baseline",
        ),
        (
            "native_probe_running_identity capp",
            "rotation baseline must use capp's running pod/node identity",
        ),
        (
            "--baseline-cp",
            "CP accept baseline passed into freshness comparison",
        ),
        (
            "--baseline-client",
            "capp TLS-connect baseline passed into freshness comparison",
        ),
        (
            "--tail=-1",
            "full current-container logs so pre-swap lines cannot slide out of a tail window",
        ),
        (
            "dp_grpc_anchor=1",
            "rotation evidence must report a post-baseline dp_grpc reload anchor",
        ),
        (
            "cp_grpc_anchor=1",
            "rotation evidence must report a post-baseline cp_grpc reload anchor",
        ),
        (
            "client_post_anchor=1",
            "rotation evidence must report Connected-to-CP after the dp_grpc reload",
        ),
        (
            "cp_post_anchor=1",
            "rotation evidence must report Tenant subscription accepted after the cp_grpc reload",
        ),
        (
            "Verify return code: 0",
            "fail-closed verified-handshake check",
        ),
    ];
    for (needle, desc) in required {
        if !source.contains(needle) {
            errors.push(format!(
                "native rotation observation missing {desc} (`{needle}`)"
            ));
        }
    }

    let forwards_cp = source.contains("port-forward")
        && (source.contains("svc/ferrum-cp")
            || source.contains("service/ferrum-cp")
            || source.contains("deploy/ferrum-cp"));
    if !forwards_cp {
        errors.push(
            "rotation observation must port-forward the live ferrum-cp Service or \
             Deployment listener, not a Secret or file"
                .into(),
        );
    }

    let handshake_feeds_serial = source.find("openssl s_client").is_some_and(|idx| {
        let window_end = (idx + 5000).min(source.len());
        let window = &source[idx..window_end];
        window.contains("openssl x509")
            && window.contains("-noout")
            && window.contains("-serial")
            && !window.contains("CAcreateserial")
    });
    if !handshake_feeds_serial {
        errors.push(
            "peer leaf serial must be extracted from the openssl s_client handshake \
             output (openssl x509 -noout -serial), not from a local expected cert"
                .into(),
        );
    }

    let observe_helpers = bash_functions_publishing_observe_pid(source);
    if command_substitution_invokes_observe_helper(source, &observe_helpers) {
        errors.push(
            "stateful native CP observe helper must run in the parent shell, not \
             via command substitution (NATIVE_OBSERVE_PF_PID / NATIVE_CP_SERVED_CLASS \
             / NATIVE_CP_SERVED_SERIAL would not propagate)"
                .into(),
        );
    }
    if !observe_helpers.is_empty()
        && !observe_helper_invoked_in_parent_shell(source, &observe_helpers)
    {
        errors.push(
            "rotation probe must invoke the stateful observe helper directly in \
             the parent shell"
                .into(),
        );
    }
    if live_serial_captured_from_command_substitution(source) {
        errors.push(
            "live_serial must be copied from NATIVE_CP_SERVED_SERIAL after a \
             direct helper call; do not capture the observe helper via command \
             substitution"
                .into(),
        );
    }
    if !live_serial_copied_from_parent_channel(source) {
        errors.push(
            "probe must read live_serial from NATIVE_CP_SERVED_SERIAL after a \
             direct helper call"
                .into(),
        );
    }
    if !source.contains("observe_class=${NATIVE_CP_SERVED_CLASS")
        && !source.contains("observe_class=$NATIVE_CP_SERVED_CLASS")
    {
        errors
            .push("rotation outcome must read NATIVE_CP_SERVED_CLASS from the parent shell".into());
    }

    let wait_body = non_comment_lines(&bash_function_body(
        source,
        "wait_for_native_rotation_evidence",
    ));
    if !wait_body.is_empty() {
        if wait_body.contains("reconnecting native MeshSubscribe stream") {
            errors.push(
                "wait_for_native_rotation_evidence must not treat reconnect-attempt \
                 logs as rotation proof"
                    .into(),
            );
        }
        if wait_body.contains("TLS material sources reloaded") {
            errors.push(
                "wait_for_native_rotation_evidence must not treat TLS reload logs \
                 as rotation proof"
                    .into(),
            );
        }
        if !wait_body.contains("--rotation-fresh")
            && !wait_body.contains("native_rotation_fresh_now")
        {
            errors.push(
                "wait_for_native_rotation_evidence must require helper freshness \
                 comparison, not reload/attempt greps"
                    .into(),
            );
        }
        if !wait_body.contains("NATIVE_ROTATION_BASELINE_CAPTURED") {
            errors.push(
                "wait_for_native_rotation_evidence must refuse to pass without a \
                 captured pre-swap baseline"
                    .into(),
            );
        }
        if !wait_body.contains("seq 1 120") || !wait_body.contains("sleep 2") {
            errors.push(
                "wait_for_native_rotation_evidence must poll for at least 240s of \
                 projected-volume evidence (seq 1 120 * sleep 2)"
                    .into(),
            );
        }
        if wait_body.contains("seq 1 45") {
            errors.push(
                "wait_for_native_rotation_evidence must not use the 90s projected-volume \
                 window; hosted Kind kubelet projection can exceed it"
                    .into(),
            );
        }
    }

    let probe_body = bash_function_body(source, "probe_native_mtls_rotation");
    if !probe_body.is_empty() {
        let idx_base = probe_body.find("capture_native_rotation_baseline");
        let idx_gen2 = probe_body.find("apply_native_mtls_secrets gen2");
        let idx_wait = probe_body.find("wait_for_native_rotation_evidence");
        let ordered = matches!(
            (idx_base, idx_gen2, idx_wait),
            (Some(base), Some(gen2), Some(wait)) if base < gen2 && gen2 < wait
        );
        if !ordered {
            errors.push(
                "probe_native_mtls_rotation must capture the capp baseline, apply \
                 gen2, then wait for a strictly newer accepted MeshSubscribe"
                    .into(),
            );
        }
    }

    errors
}

#[test]
fn live_contract_sidecar_native_rotation_observes_served_leaf_serial() {
    const RUN_SH: &str = include_str!("../k8s/mesh_e2e_sidecar/run.sh");
    const CONTRACT: &str = include_str!("ga_contract.yaml");
    const README: &str = include_str!("../k8s/mesh_e2e_sidecar/README.md");

    let violations = native_rotation_observation_violations(RUN_SH);
    assert!(
        violations.is_empty(),
        "mesh-e2e-sidecar rotation gate must observe the served CP leaf over mTLS: \
         {violations:?}"
    );

    let secret_false_proof = r#"
apply_native_mtls_secrets gen2
wait_for_native_rotation_evidence
live_serial="$(kubectl get secret ferrum-native-mtls-cp \
  -o jsonpath='{.data.server\.pem}' | base64 -d | openssl x509 -noout -serial)"
if [[ "$live_serial" == "$NATIVE_SERVER_SERIAL_GEN2" ]]; then
  record_live_assertion sidecar.config.native_subscribe_tls_rotation_reconnects pass
fi
"#;
    let false_violations = native_rotation_observation_violations(secret_false_proof);
    assert!(
        !false_violations.is_empty(),
        "rotation observation contract must reject decoding Secret.data.server.pem \
         as the live served serial"
    );
    assert!(
        false_violations
            .iter()
            .any(|error| error.contains("Secret")),
        "false-proof rejection must call out Secret decoding, got {false_violations:?}"
    );

    let expected_cert_false_proof = r#"
apply_native_mtls_secrets gen2
wait_for_native_rotation_evidence
live_serial="$(cert_serial "$NATIVE_MTLS_DIR/gen2-server.pem")"
openssl s_client -verify_return_error -verify_hostname "$NATIVE_CP_DNS" \
  -CAfile gen2-ca.pem -cert gen2-client.pem -key gen2-client-key.pem
kubectl port-forward svc/ferrum-cp 50051:50051
Verify return code: 0
record_live_assertion sidecar.config.native_subscribe_tls_rotation_reconnects pass
NATIVE_SERVER_SERIAL_GEN2
"#;
    let expected_cert_violations =
        native_rotation_observation_violations(expected_cert_false_proof);
    assert!(
        expected_cert_violations
            .iter()
            .any(|error| error.contains("live_serial assignment")
                || error.contains("expected server cert")),
        "rotation observation contract must reject using the controller-local \
         gen2-server.pem as live_serial, got {expected_cert_violations:?}"
    );

    let subshell_false_proof = r#"
apply_native_mtls_secrets gen2
wait_for_native_rotation_evidence
NATIVE_CP_SERVED_SERIAL=""
NATIVE_CP_SERVED_CLASS=""
NATIVE_OBSERVE_PF_PID=""
observe_native_cp_served_serial() {
  NATIVE_OBSERVE_PF_PID="$pf_pid"
  kubectl port-forward svc/ferrum-cp "${port}:50051"
  openssl s_client -connect 127.0.0.1:${port} -servername "$NATIVE_CP_DNS" \
    -verify_hostname "$NATIVE_CP_DNS" -verify_return_error \
    -CAfile gen2-ca.pem -cert gen2-client.pem -key gen2-client-key.pem
  openssl x509 -noout -serial
  Verify return code: 0
  NATIVE_CP_SERVED_SERIAL="$serial"
  NATIVE_CP_SERVED_CLASS=ok
  printf '%s\n' "$serial"
}
if live_serial="$(observe_native_cp_served_serial)"; then
  live_serial="${NATIVE_CP_SERVED_SERIAL:-}"
fi
outcome="live_serial=$live_serial observe_class=${NATIVE_CP_SERVED_CLASS:-}"
record_live_assertion sidecar.config.native_subscribe_tls_rotation_reconnects pass
NATIVE_SERVER_SERIAL_GEN2
"#;
    let subshell_violations = native_rotation_observation_violations(subshell_false_proof);
    assert!(
        !subshell_violations.is_empty(),
        "rotation observation contract must reject invoking the observe helper \
         through command substitution"
    );
    assert!(
        subshell_violations.iter().any(|error| {
            error.contains("command substitution") || error.contains("parent shell")
        }),
        "rotation observation contract must name command substitution / parent \
         shell when the observe helper is captured via $(), got {subshell_violations:?}"
    );

    let reload_false_proof = r#"
capture_native_rotation_baseline() { return 0; }
wait_for_native_rotation_evidence() {
  grep -Fq 'TLS material sources reloaded; new handshakes/connections will use rotated material'
  grep -Fq 'Mesh gRPC TLS source changed; reconnecting native MeshSubscribe stream'
  return 0
}
probe_native_mtls_rotation() {
  capture_native_rotation_baseline
  apply_native_mtls_secrets gen2
  wait_for_native_rotation_evidence
  kubectl port-forward svc/ferrum-cp "${port}:50051"
  openssl s_client -connect 127.0.0.1:${port} -servername "$NATIVE_CP_DNS" \
    -verify_hostname "$NATIVE_CP_DNS" -verify_return_error \
    -CAfile gen2-ca.pem -cert gen2-client.pem -key gen2-client-key.pem
  openssl x509 -noout -serial
  Verify return code: 0
  live_serial="${NATIVE_CP_SERVED_SERIAL:-}"
  outcome="observe_class=${NATIVE_CP_SERVED_CLASS:-}"
  record_live_assertion sidecar.config.native_subscribe_tls_rotation_reconnects pass
}
NATIVE_OBSERVE_PF_PID=""
NATIVE_CP_SERVED_SERIAL=""
NATIVE_CP_SERVED_CLASS=""
NATIVE_SERVER_SERIAL_GEN2=""
NATIVE_ROTATION_BASELINE_CAPTURED=true
--rotation-count
--rotation-fresh
--baseline-cp
--baseline-client
native_probe_running_identity capp
"#;
    let reload_violations = native_rotation_observation_violations(reload_false_proof);
    assert!(
        !reload_violations.is_empty(),
        "rotation observation contract must reject reload/reconnect-attempt logs \
         as MeshSubscribe accept proof"
    );
    assert!(
        reload_violations.iter().any(|error| {
            error.contains("reconnect-attempt")
                || error.contains("TLS reload")
                || error.contains("freshness")
        }),
        "rotation observation contract must name reload/attempt-only evidence, \
         got {reload_violations:?}"
    );

    let no_baseline_false_proof = r#"
wait_for_native_rotation_evidence() {
  python3 helper --rotation-fresh --pod-name "$pod"
  return 0
}
probe_native_mtls_rotation() {
  apply_native_mtls_secrets gen2
  wait_for_native_rotation_evidence
  kubectl port-forward svc/ferrum-cp "${port}:50051"
  openssl s_client -connect 127.0.0.1:${port} -servername "$NATIVE_CP_DNS" \
    -verify_hostname "$NATIVE_CP_DNS" -verify_return_error \
    -CAfile gen2-ca.pem -cert gen2-client.pem -key gen2-client-key.pem
  openssl x509 -noout -serial
  Verify return code: 0
  live_serial="${NATIVE_CP_SERVED_SERIAL:-}"
  outcome="observe_class=${NATIVE_CP_SERVED_CLASS:-}"
  record_live_assertion sidecar.config.native_subscribe_tls_rotation_reconnects pass
}
NATIVE_OBSERVE_PF_PID=""
NATIVE_CP_SERVED_SERIAL=""
NATIVE_CP_SERVED_CLASS=""
NATIVE_SERVER_SERIAL_GEN2=""
--rotation-count
--rotation-fresh
--baseline-cp
--baseline-client
native_probe_running_identity capp
"#;
    let no_baseline_violations = native_rotation_observation_violations(no_baseline_false_proof);
    assert!(
        !no_baseline_violations.is_empty(),
        "rotation observation contract must reject a post-swap wait without a \
         pre-swap capp baseline"
    );
    assert!(
        no_baseline_violations.iter().any(|error| {
            error.contains("baseline") || error.contains("capture_native_rotation_baseline")
        }),
        "rotation observation contract must require a pre-swap baseline by name, \
         got {no_baseline_violations:?}"
    );

    assert!(
        CONTRACT.contains("over-the-wire") && CONTRACT.contains("replacement leaf serial"),
        "ga_contract.yaml must describe the rotation proof as an over-the-wire \
         served leaf serial, not merely a Secret update"
    );
    assert!(
        CONTRACT.contains("strictly newer than the")
            && CONTRACT.contains("pre-swap baseline")
            && CONTRACT.contains("Reload and reconnect-attempt logs are not proof")
            && CONTRACT.contains("surface=dp_grpc")
            && CONTRACT.contains("surface=cp_grpc"),
        "ga_contract.yaml must require a fresh post-swap capp MeshSubscribe accept \
         ordered after generation-2 TLS reload anchors, not reload/attempt logs"
    );
    assert!(
        README.contains("over-the-wire mTLS handshake")
            && README.contains("replacement leaf serial"),
        "README must describe the rotation proof as an over-the-wire served leaf serial"
    );
    assert!(
        README.contains("strictly newer than the pre-swap baseline")
            && README.contains("exact pod/node identity")
            && README.contains("surface=dp_grpc")
            && README.contains("surface=cp_grpc"),
        "README must require identity-correlated post-reload-anchor freshness \
         for rotation reconnect"
    );
    assert!(
        !RUN_SH.to_ascii_lowercase().contains("shred"),
        "run.sh must not claim keys are shredded unless the fixture actually shreds them"
    );
}

#[test]
fn live_contract_real_contract_declares_the_multicluster_suite_rows() {
    // Pin the real ga_contract.yaml against this validator for the
    // multicluster-federation suite (issue #2459): SPIRE trust federation,
    // bidirectional authenticated east-west traffic, untrusted-peer rejection,
    // trust revocation/recovery, and destination blackhole/recovery are all
    // ENFORCED and emitted by tests/k8s/multicluster-federation/run.sh.
    let contract = load_contract().expect("real contract loads");
    let multicluster_rows: Vec<_> = contract
        .ga_capabilities()
        .into_iter()
        .filter(|capability| capability.live_suite == "multicluster-federation")
        .collect();
    assert!(
        !multicluster_rows.is_empty(),
        "the multicluster-federation suite must have GA contract rows"
    );
    let enforced_ids: Vec<&str> = multicluster_rows
        .iter()
        .filter(|capability| capability.live_deferred.is_none())
        .flat_map(|capability| capability.live_assertions.iter().map(String::as_str))
        .collect();
    for required in [
        "multicluster.spire.federation_ready_a",
        "multicluster.spire.federation_ready_b",
        "multicluster.federation.trust_bundle_exchange",
        "multicluster.spire.workload_entries",
        "multicluster.eastwest.gateway_reachable",
        "multicluster.eastwest.a_to_b_authenticated",
        "multicluster.eastwest.b_to_a_authenticated",
        "multicluster.eastwest.bidirectional_authenticated_traffic",
        "multicluster.eastwest.untrusted_peer_rejected",
        "multicluster.federation.bundle_revoked_rejected",
        "multicluster.federation.trust_restored_recovers",
        "multicluster.eastwest.endpoint_blackhole_when_dest_down",
        "multicluster.eastwest.endpoint_recovers_when_dest_returns",
    ] {
        assert!(
            enforced_ids.contains(&required),
            "`{required}` must be an enforced GA live assertion"
        );
    }
    let deferred: Vec<&str> = multicluster_rows
        .iter()
        .filter(|capability| capability.live_deferred.is_some())
        .map(|capability| capability.id.as_str())
        .collect();
    assert!(
        deferred.is_empty(),
        "no multicluster row should remain live-deferred (found: {deferred:?})"
    );
    for capability in multicluster_rows
        .iter()
        .filter(|capability| capability.live_deferred.is_none())
    {
        assert_eq!(
            capability.platform_profile, "kind-spire-multicluster-federation",
            "enforced multicluster rows must pin the fixture's platform profile"
        );
    }
}

/// The `multicluster-federation` live suite has two fail-closed required-
/// assertion gates. The first is the fixture's own
/// `ferrum_live_assertions_require_all_passed` call over the run.sh-local
/// `REQUIRED_LIVE_ASSERTIONS` array, which proves what the fixture process
/// observed. The second is the `gate` job of
/// `.github/workflows/multicluster-federation-live.yml`, which downloads the
/// published artifact and validates the emitted `live-assertions.json` against
/// the same id set (see
/// `live_contract_multicluster_release_gate_requires_exactly_the_enforced_rows`).
///
/// Either only gates the GA contract if its id set and the contract stay the
/// same set, so this hosted test is the binding for the fixture half: drop an
/// id from the array (weakening the live gate) or add an enforced contract row
/// the fixture never requires, and this test fails in the ordinary `Tests`
/// aggregate.
#[test]
fn live_contract_multicluster_fixture_requires_exactly_the_enforced_rows() {
    const RUN_SH: &str = include_str!("../k8s/multicluster-federation/run.sh");

    let mut lines = RUN_SH.lines();
    assert!(
        lines.any(|line| line.trim_end() == "REQUIRED_LIVE_ASSERTIONS=("),
        "tests/k8s/multicluster-federation/run.sh must declare REQUIRED_LIVE_ASSERTIONS=( \
         on its own line — the fixture's fail-closed gate is what this test binds \
         to the GA contract"
    );
    let mut fixture_required: BTreeSet<&str> = BTreeSet::new();
    let mut closed = false;
    for line in lines {
        let trimmed = line.trim();
        if trimmed == ")" {
            closed = true;
            break;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        assert!(
            fixture_required.insert(trimmed),
            "run.sh REQUIRED_LIVE_ASSERTIONS lists `{trimmed}` more than once"
        );
    }
    assert!(
        closed,
        "run.sh REQUIRED_LIVE_ASSERTIONS array is unterminated — refusing to \
         validate a partially parsed required set"
    );

    let contract = load_contract().expect("real contract loads");
    let contract_required: BTreeSet<&str> = contract
        .ga_capabilities()
        .into_iter()
        .filter(|capability| {
            capability.live_suite == "multicluster-federation" && capability.live_deferred.is_none()
        })
        .flat_map(|capability| capability.live_assertions.iter().map(String::as_str))
        .collect();
    assert!(
        !contract_required.is_empty(),
        "the multicluster-federation suite must have enforced GA contract rows"
    );

    let missing_in_fixture: Vec<&&str> = contract_required.difference(&fixture_required).collect();
    assert!(
        missing_in_fixture.is_empty(),
        "GA-contract assertions the live fixture does not REQUIRE (they could be \
         skipped or absent without failing the live job): {missing_in_fixture:?}"
    );
    let missing_in_contract: Vec<&&str> = fixture_required.difference(&contract_required).collect();
    assert!(
        missing_in_contract.is_empty(),
        "live fixture requires assertions with no enforced GA-contract row \
         (add the row, or drop the id from REQUIRED_LIVE_ASSERTIONS): \
         {missing_in_contract:?}"
    );
}

/// The second fail-closed gate: the `gate` job of
/// `.github/workflows/multicluster-federation-live.yml` downloads the artifact
/// the live run PUBLISHED and validates it with
/// `.github/scripts/validate_live_assertions.py`. The fixture-side check cannot
/// prove the published artifact belongs to this commit, this platform profile,
/// or this run at all; the workflow gate can, and does.
///
/// The workflow spells its required ids explicitly, which is only a contract if
/// the spelling and `ga_contract.yaml` stay the same set. This test is that
/// binding, in both directions, so neither dropping an id from the workflow nor
/// adding an enforced contract row the workflow never checks can pass hosted
/// CI. It also pins the exactness flags, so the gate cannot be relaxed into a
/// shape that accepts a stale or foreign artifact.
#[test]
fn live_contract_multicluster_release_gate_requires_exactly_the_enforced_rows() {
    const WORKFLOW: &str = include_str!("../../.github/workflows/multicluster-federation-live.yml");

    let gate_start = WORKFLOW
        .find("\n  gate:\n")
        .expect("multicluster-federation-live.yml must declare a `gate` job");
    let gate_body = &WORKFLOW[gate_start..];

    for pinned in [
        "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
        "name: multicluster-federation-results",
        "python3 .github/scripts/validate_live_assertions.py --self-test",
        "--artifact multicluster-federation-artifact/live-assertions.json",
        "--schema-version 1",
        "--suite multicluster-federation",
        "--platform-profile kind-spire-multicluster-federation",
        "--commit \"$EXPECTED_COMMIT\"",
        "EXPECTED_COMMIT: ${{ github.sha }}",
        "--max-age-seconds 21600",
        "--required-namespace multicluster.",
        "if: steps.summarize.outputs.validate == 'true'",
    ] {
        assert!(
            gate_body.contains(pinned),
            "the multicluster live release gate must keep `{pinned}` — without it the \
             emitted artifact is no longer bound to this commit, this profile, this \
             freshness window, or this contract"
        );
    }
    assert!(
        !gate_body.contains("cargo "),
        "the aggregate gate must carry no build or toolchain surface"
    );

    let workflow_required: BTreeSet<&str> = gate_body
        .lines()
        .filter_map(|line| line.trim().strip_prefix("--require "))
        .map(|rest| rest.trim().trim_end_matches('\\').trim())
        .collect();
    assert!(
        !workflow_required.is_empty(),
        "the multicluster live release gate must pass an explicit --require id set"
    );

    let contract = load_contract().expect("real contract loads");
    let contract_required: BTreeSet<&str> = contract
        .ga_capabilities()
        .into_iter()
        .filter(|capability| {
            capability.live_suite == "multicluster-federation" && capability.live_deferred.is_none()
        })
        .flat_map(|capability| capability.live_assertions.iter().map(String::as_str))
        .collect();
    assert!(
        !contract_required.is_empty(),
        "the multicluster-federation suite must have enforced GA contract rows"
    );

    let missing_in_workflow: Vec<&&str> =
        contract_required.difference(&workflow_required).collect();
    assert!(
        missing_in_workflow.is_empty(),
        "GA-contract assertions the release gate does not validate in the emitted \
         artifact: {missing_in_workflow:?}"
    );
    let missing_in_contract: Vec<&&str> =
        workflow_required.difference(&contract_required).collect();
    assert!(
        missing_in_contract.is_empty(),
        "release gate requires assertion ids with no enforced GA-contract row \
         (add the row, or drop the --require): {missing_in_contract:?}"
    );
}

/// Issue #3608 / PR #3668 hosted NodeWaypoint regression: the production SPIRE
/// mesh path publishes `source="spire_agent"` identity telemetry, but the live
/// harness historically grepped for the generic `workload_api` label and
/// rejected scrapes that already contained the exact per-node SPIFFE ID under
/// `spire_agent`. Keep the fixture bound to the fail-closed proof helper and
/// execute that helper's static self-test in ordinary conformance CI.
#[test]
fn live_contract_node_waypoint_spire_agent_metric_proof_is_fail_closed() {
    const RUN_SH: &str = include_str!("../k8s/node_waypoint_ebpf_live/run.sh");
    const HELPER: &str = include_str!("../k8s/lib/spire_ambient_metrics.py");

    assert!(
        RUN_SH.contains("tests/k8s/lib/spire_ambient_metrics.py"),
        "node_waypoint_ebpf_live must invoke the shared SPIRE ambient metrics proof helper"
    );
    assert!(
        RUN_SH.contains("--expected-spiffe"),
        "node_waypoint_ebpf_live must pass the exact per-node SPIFFE ID into the metrics proof"
    );
    assert!(
        RUN_SH.contains("--trust-domain"),
        "node_waypoint_ebpf_live must pass the trust domain into the metrics proof"
    );
    assert!(
        !RUN_SH.contains("source=\\\"workload_api\\\""),
        "node_waypoint_ebpf_live must not grep cert-expiry under the historical workload_api \
         source label — production SPIRE mesh telemetry uses source=spire_agent"
    );
    assert!(
        HELPER.contains("source") && HELPER.contains("spire_agent"),
        "spire_ambient_metrics.py must require the spire_agent source label"
    );
    assert!(
        HELPER.contains("ca_type") && HELPER.contains("ferrum_mesh_ca_health"),
        "spire_ambient_metrics.py must require healthy ferrum_mesh_ca_health{{ca_type=spire_agent}}"
    );
    assert!(
        HELPER.contains("ferrum_mesh_trust_bundle_version"),
        "spire_ambient_metrics.py must require a spire_agent trust-bundle observation"
    );
    assert!(
        HELPER.contains("must be > 0"),
        "spire_ambient_metrics.py must reject non-positive certificate expiry"
    );

    let helper_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/k8s/lib/spire_ambient_metrics.py");
    let output = Command::new("python3")
        .arg("-I")
        .arg(&helper_path)
        .arg("--self-test")
        .output()
        .expect("spawn python3 for spire_ambient_metrics.py --self-test");
    assert!(
        output.status.success(),
        "spire_ambient_metrics.py --self-test failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

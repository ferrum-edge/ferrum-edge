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
    // identity plumbing, and the native MeshSubscribe config transport — all
    // ENFORCED and emitted by tests/k8s/mesh_e2e_sidecar/run.sh; the last
    // deferral, VS CORS, was closed by the mesh-slice CORS carriage of issue
    // #1973, and the config-transport row was live-backed by the in-fixture
    // Ferrum CP of issue #2002).
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
        "sidecar.destination_rule.tcp_max_connections",
        "sidecar.virtual_service.cors_policy",
        "sidecar.config.native_subscribe_delivered",
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
        "no sidecar row should remain live-deferred (found: {deferred:?})"
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

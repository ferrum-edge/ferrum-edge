//! Script-contract: local and CI coverage dispatch the same in-baseline Cargo
//! test targets (issue #5486).
//!
//! Source of truth is Cargo's test-target inventory: auto-discovered
//! `tests/*.rs` binaries plus explicit `Cargo.toml` `[[test]]` names.
//! `docs/coverage.md` documents the measured denominator, but it cannot see a
//! new `tests/*.rs` split until someone edits it. Cargo's inventory is the check
//! that a future target split cannot silently leave `scripts/coverage.sh` or
//! `.github/workflows/coverage.yml` behind.
//!
//! Suites that `docs/coverage.md` keeps outside the default baseline (subprocess
//! functional/conformance, container-backed service integration, secrets
//! functional, feature-gated ACME, and the live-cluster Istio status CAS proof
//! that only its dedicated workflow runs) are listed in
//! `OUTSIDE_DEFAULT_COVERAGE_BASELINE`. Adding a new Cargo test target fails this
//! check until it is either dispatched through both collectors or added to that
//! exclusion with an explicit reason.

use std::collections::BTreeSet;
use std::path::Path;

const COVERAGE_SH: &str = include_str!("../../../scripts/coverage.sh");
const COVERAGE_YML: &str = include_str!("../../../.github/workflows/coverage.yml");
const CARGO_TOML: &str = include_str!("../../../Cargo.toml");
const COVERAGE_MD: &str = include_str!("../../../docs/coverage.md");

/// Cargo test targets that are not part of the default llvm-cov denominator.
const OUTSIDE_DEFAULT_COVERAGE_BASELINE: &[&str] = &[
    "functional_tests",
    "conformance_tests",
    "secrets_functional",
    "service_integration",
    "acme_dns01_tests",
    // Live kind-cluster proof driven by `.github/workflows/istio-status-cas-live.yml`;
    // never part of the deterministic llvm-cov denominator.
    "k8s_istio_status_cas_live",
];

fn is_cargo_target_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn autodiscovered_test_targets() -> BTreeSet<String> {
    let tests_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut targets = BTreeSet::new();
    let entries = std::fs::read_dir(&tests_dir)
        .unwrap_or_else(|error| panic!("read {}: {error}", tests_dir.display()));
    for entry in entries {
        let entry = entry.unwrap_or_else(|error| panic!("tests/ entry: {error}"));
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .expect("tests/*.rs names are UTF-8");
        assert!(
            is_cargo_target_name(stem),
            "auto-discovered test target name must be a Cargo ident, got {stem:?}"
        );
        targets.insert(stem.to_string());
    }
    assert!(
        !targets.is_empty(),
        "expected auto-discovered tests/*.rs targets"
    );
    targets
}

fn cargo_toml_test_targets(manifest: &str) -> BTreeSet<String> {
    let mut targets = BTreeSet::new();
    let mut in_test = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_test = trimmed == "[[test]]";
            continue;
        }
        if !in_test {
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("name = ") {
            let name = value.trim().trim_matches('"');
            assert!(
                is_cargo_target_name(name),
                "Cargo.toml [[test]] name must be a Cargo ident, got {name:?}"
            );
            targets.insert(name.to_string());
        }
    }
    targets
}

fn all_cargo_test_targets() -> BTreeSet<String> {
    let mut targets = autodiscovered_test_targets();
    targets.extend(cargo_toml_test_targets(CARGO_TOML));
    targets
}

fn in_baseline_test_targets() -> BTreeSet<String> {
    let all = all_cargo_test_targets();
    for excluded in OUTSIDE_DEFAULT_COVERAGE_BASELINE {
        assert!(
            all.contains(*excluded),
            "exclusion {excluded} is not a Cargo test target; update the exclusion list"
        );
    }
    all.into_iter()
        .filter(|name| !OUTSIDE_DEFAULT_COVERAGE_BASELINE.contains(&name.as_str()))
        .collect()
}

fn coverage_md_intro() -> &'static str {
    COVERAGE_MD.split("\n## ").next().expect("coverage.md intro")
}

fn test_targets_in_order(source: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = source;
    while let Some(idx) = rest.find("--test ") {
        rest = &rest[idx + "--test ".len()..];
        let name = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect::<String>();
        if is_cargo_target_name(&name) {
            names.push(name);
        }
    }
    names
}

fn coverage_sh_dispatch_sequence() -> Vec<String> {
    let mut seq = Vec::new();
    for line in COVERAGE_SH.lines() {
        let trimmed = line.trim();
        if trimmed == "run_coverage_target --lib" {
            seq.push("--lib".to_string());
            continue;
        }
        let Some(rest) = trimmed.strip_prefix("run_coverage_target --test ") else {
            continue;
        };
        let name = rest.split_whitespace().next().unwrap_or("");
        assert!(
            is_cargo_target_name(name),
            "run_coverage_target --test must take a Cargo target name, got {trimmed:?}"
        );
        seq.push(format!("--test {name}"));
    }
    seq
}

fn documented_dispatch_sequence() -> Vec<String> {
    let intro = coverage_md_intro();
    let mut seq = Vec::new();
    if intro.contains("--lib") {
        seq.push("--lib".to_string());
    }
    for name in test_targets_in_order(intro) {
        seq.push(format!("--test {name}"));
    }
    seq
}

fn workflow_step_body(workflow: &str, step_name: &str) -> &str {
    let marker = format!("- name: {step_name}\n");
    let start = workflow
        .find(&marker)
        .unwrap_or_else(|| panic!("coverage.yml must contain step {step_name:?}"));
    let body = &workflow[start + marker.len()..];
    let end = body.find("\n      - ").unwrap_or(body.len());
    &body[..end]
}

fn llvm_cov_test_targets(source: &str) -> BTreeSet<String> {
    let mut targets = BTreeSet::new();
    let mut tokens = source
        .split_whitespace()
        .map(|token| token.trim_end_matches('\\'))
        .filter(|token| !token.is_empty());
    while let Some(token) = tokens.next() {
        if token != "--test" {
            continue;
        }
        let Some(name) = tokens.next() else {
            continue;
        };
        if is_cargo_target_name(name) {
            targets.insert(name.to_string());
        }
    }
    targets
}

fn workflow_step_has_lib_argument(step: &str) -> bool {
    step.lines()
        .any(|line| line.trim().trim_end_matches('\\').trim() == "--lib")
}

#[test]
fn coverage_dispatchers_match_in_baseline_cargo_test_targets() {
    let expected = in_baseline_test_targets();
    assert!(
        expected.contains("unit_tests")
            && expected.contains("unit_plugins_a_tests")
            && expected.contains("unit_plugins_b_tests")
            && expected.contains("unit_gateway_core_tests")
            && expected.contains("integration_tests"),
        "in-baseline set must include the four unit targets and integration_tests"
    );

    let script_tests: BTreeSet<String> = coverage_sh_dispatch_sequence()
        .into_iter()
        .filter_map(|flag| flag.strip_prefix("--test ").map(str::to_string))
        .collect();
    assert_eq!(
        script_tests, expected,
        "scripts/coverage.sh --test dispatch must match in-baseline Cargo targets"
    );

    let lib_unit = workflow_step_body(COVERAGE_YML, "Run lib and unit coverage");
    let integration = workflow_step_body(COVERAGE_YML, "Run integration coverage shard");
    let mut workflow_tests = llvm_cov_test_targets(lib_unit);
    workflow_tests.extend(llvm_cov_test_targets(integration));
    assert_eq!(
        workflow_tests, expected,
        "coverage.yml --test dispatch must match in-baseline Cargo targets"
    );

    let documented: BTreeSet<String> = test_targets_in_order(coverage_md_intro())
        .into_iter()
        .collect();
    assert_eq!(
        documented, expected,
        "docs/coverage.md intro --test list must match in-baseline Cargo targets"
    );
}

#[test]
fn coverage_script_and_workflow_collect_lib_in_documented_order() {
    let script = coverage_sh_dispatch_sequence();
    assert_eq!(
        script, documented_dispatch_sequence(),
        "scripts/coverage.sh run_coverage_target order must match docs/coverage.md"
    );
    assert!(
        script.first().is_some_and(|flag| flag == "--lib"),
        "scripts/coverage.sh must collect --lib through run_coverage_target"
    );

    let lib_unit = workflow_step_body(COVERAGE_YML, "Run lib and unit coverage");
    assert!(
        workflow_step_has_lib_argument(lib_unit),
        "coverage.yml lib-unit collection must pass --lib"
    );
}

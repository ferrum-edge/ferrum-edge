//! Drift guard: every functional test module must be assigned to a CI shard.
//!
//! `.github/workflows/ci.yml` runs the `functional_tests` binary in 4 parallel
//! shards (`application`, `protocols`, `data-plane`, `data-plane-runtime`) by
//! passing each shard a list of cargo test name filters. A new
//! `tests/functional/*_test.rs` file that is not added to any shard's
//! filter list will compile and link into the binary but never run in CI.
//!
//! This test parses the workflow, enumerates the test files on disk, and
//! fails if any file's module name does not appear as a substring in some
//! shard's filter block. Runs without the gateway binary, so it is NOT
//! `#[ignore]` — it runs in the application shard alongside the other smoke
//! checks.
//!
//! See PR #696 for the original parallelization that made this guard
//! necessary.
//!
//! Run locally with:
//!   cargo test --test functional_tests functional_ci_shard_coverage

use std::collections::BTreeSet;
use std::path::Path;

const WORKFLOW_PATH: &str = ".github/workflows/ci.yml";
const FUNCTIONAL_TESTS_DIR: &str = "tests/functional";

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read_shard_filter_text() -> String {
    let workflow = workspace_root().join(WORKFLOW_PATH);
    let raw =
        std::fs::read_to_string(&workflow).expect("read .github/workflows/ci.yml from repo root");
    let doc: serde_yaml::Value = serde_yaml::from_str(&raw).expect("parse ci.yml as YAML");

    let include = doc
        .get("jobs")
        .and_then(|j| j.get("test-functional"))
        .and_then(|j| j.get("strategy"))
        .and_then(|s| s.get("matrix"))
        .and_then(|m| m.get("include"))
        .and_then(|i| i.as_sequence())
        .expect("jobs.test-functional.strategy.matrix.include must be a sequence");

    let mut combined = String::new();
    for entry in include {
        if let Some(filters) = entry.get("filters").and_then(|f| f.as_str()) {
            combined.push_str(filters);
            combined.push('\n');
        }
    }
    assert!(
        !combined.trim().is_empty(),
        "no filters: blocks found under jobs.test-functional.strategy.matrix.include"
    );
    combined
}

fn discover_test_modules() -> BTreeSet<String> {
    let dir = workspace_root().join(FUNCTIONAL_TESTS_DIR);
    let mut out = BTreeSet::new();
    for entry in std::fs::read_dir(&dir).expect("read tests/functional dir") {
        let entry = entry.expect("read dir entry");
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_functional_test = name.starts_with("functional_") && name.ends_with("_test.rs");
        let is_scripted_backend_tests =
            name.starts_with("scripted_backend_") && name.ends_with("_tests.rs");
        if is_functional_test || is_scripted_backend_tests {
            out.insert(name.trim_end_matches(".rs").to_string());
        }
    }
    assert!(
        !out.is_empty(),
        "no functional test files discovered under {}",
        FUNCTIONAL_TESTS_DIR
    );
    out
}

#[test]
fn ci_workflow_assigns_every_functional_test_to_a_shard() {
    let filter_text = read_shard_filter_text();
    let modules = discover_test_modules();

    let missing: Vec<&str> = modules
        .iter()
        .filter(|m| !filter_text.contains(m.as_str()))
        .map(|s| s.as_str())
        .collect();

    assert!(
        missing.is_empty(),
        "These test modules are not assigned to any CI shard in {}: {:?}\n\
         Add each name to one of the shards' `filters:` blocks under \
         jobs.test-functional.strategy.matrix.include in the workflow.",
        WORKFLOW_PATH,
        missing
    );
}

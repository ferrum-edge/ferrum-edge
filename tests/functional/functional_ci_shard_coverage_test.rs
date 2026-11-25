//! Drift guard: every functional test module must be assigned to a CI shard.
//!
//! `.github/workflows/ci.yml` runs the `functional_tests` binary in 5 parallel
//! shards (`application`, `protocols-a`, `protocols-b`, `data-plane`,
//! `data-plane-runtime`) by passing each shard a list of cargo test name
//! filters. A new
//! `tests/functional/*_test.rs` file that is not added to any shard's
//! filter list will compile and link into the binary but never run in CI.
//!
//! This test parses the workflow, enumerates the test files on disk, and
//! enforces that every discovered module appears as an exact canonical filter
//! in exactly one shard (no missing, duplicate, non-canonical, or
//! substring-colliding filters; non-module filters are restricted to the
//! explicit harness namespaces). Runs without the gateway binary, so it is NOT
//! `#[ignore]` — CI runs it in a dedicated matrix-filter-independent step in
//! the `application` shard as well as alongside the other smoke checks.
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
const ALLOWED_HARNESS_FILTERS: &[&str] = &["common::", "scaffolding::", "scenarios::"];

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read_shard_filters() -> Vec<(String, Vec<String>)> {
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

    let mut shards = Vec::new();
    for entry in include {
        let shard = entry
            .get("shard")
            .and_then(|s| s.as_str())
            .expect("each functional shard entry must declare a string `shard` name")
            .to_string();
        let filters = entry
            .get("filters")
            .and_then(|f| f.as_str())
            .expect("each functional shard entry must declare a string `filters` block");
        // Mirror `ci.yml`'s `while IFS= read -r filter; do [ -z "$filter" ] && continue; ...`
        // without trimming whitespace or skipping `#` lines, so extra leading/trailing
        // spaces that would cause nextest to silently skip a module fail immediately.
        let tokens: Vec<String> = filters
            .lines()
            .filter(|line| !line.is_empty())
            .map(ToString::to_string)
            .collect();
        assert!(
            !tokens.is_empty(),
            "functional shard `{}` must declare at least one filter",
            shard
        );
        shards.push((shard, tokens));
    }
    assert!(
        shards.iter().any(|(_, tokens)| !tokens.is_empty()),
        "no filters: blocks found under jobs.test-functional.strategy.matrix.include"
    );
    shards
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
    let shards = read_shard_filters();
    let modules = discover_test_modules();
    let allowed_harness: BTreeSet<&str> = ALLOWED_HARNESS_FILTERS.iter().copied().collect();

    // Reject any non-canonical filter token (e.g., `functional_grpc_test::`,
    // partial prefixes, typos, or stale module names) that could cause
    // nextest substring matching to silently rerun or miss modules.
    let mut unexpected_tokens = Vec::new();
    for (shard, tokens) in &shards {
        for token in tokens {
            if !modules.contains(token.as_str()) && !allowed_harness.contains(token.as_str()) {
                unexpected_tokens.push((shard.as_str(), token.as_str()));
            }
        }
    }
    assert!(
        unexpected_tokens.is_empty(),
        "Non-canonical or unknown functional shard filter tokens in {}: {:?}\n\
         Every filter must be either an exact discovered module name or one of {:?}.",
        WORKFLOW_PATH,
        unexpected_tokens,
        ALLOWED_HARNESS_FILTERS
    );

    let mut missing = Vec::new();
    let mut duplicates = Vec::new();
    let mut substring_overlaps = Vec::new();
    for module in &modules {
        let assigned_shards: Vec<&str> = shards
            .iter()
            .flat_map(|(shard, tokens)| {
                tokens
                    .iter()
                    .filter(move |token| token.as_str() == module.as_str())
                    .map(move |_| shard.as_str())
            })
            .collect();
        match assigned_shards.len() {
            0 => missing.push(module.as_str()),
            1 => {}
            _ => duplicates.push((module.as_str(), assigned_shards)),
        }
        // Nextest matches positional filters as substrings of full test paths;
        // verify no other filter token is a substring of this module name.
        for (shard, tokens) in &shards {
            for token in tokens {
                if token.as_str() != module.as_str() && module.contains(token.as_str()) {
                    substring_overlaps.push((module.as_str(), shard.as_str(), token.as_str()));
                }
            }
        }
    }

    let mut harness_issues = Vec::new();
    for harness in ALLOWED_HARNESS_FILTERS {
        let count: usize = shards
            .iter()
            .flat_map(|(_, tokens)| tokens.iter())
            .filter(|token| token.as_str() == *harness)
            .count();
        if count != 1 {
            harness_issues.push((*harness, count));
        }
    }

    assert!(
        missing.is_empty(),
        "These test modules are not assigned to any CI shard in {}: {:?}\n\
         Add each name to one of the shards' `filters:` blocks under \
         jobs.test-functional.strategy.matrix.include in the workflow.",
        WORKFLOW_PATH,
        missing
    );
    assert!(
        duplicates.is_empty(),
        "These test modules are assigned more than once across CI shards in {}: {:?}",
        WORKFLOW_PATH,
        duplicates
    );
    assert!(
        substring_overlaps.is_empty(),
        "These shard filters are substrings of another functional module name in {} \
         (would double-run under nextest substring matching): {:?}",
        WORKFLOW_PATH,
        substring_overlaps
    );
    assert!(
        harness_issues.is_empty(),
        "Each allowed harness filter in {} must be assigned exactly once: {:?}",
        WORKFLOW_PATH,
        harness_issues
    );
}

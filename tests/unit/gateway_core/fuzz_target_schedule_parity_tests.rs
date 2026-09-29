//! Parity between the registered fuzz targets and the lanes that execute them
//! (issue #4442).
//!
//! `datagram_client_address` was registered, corpus-seeded, and property-tested
//! for a year before either libFuzzer lane ran it: registration and scheduling
//! are separate facts, and nothing compared them. These tests compare them.
//!
//! Both hosted lanes are byte-frozen by the trusted Cross build policy, so a
//! pull request cannot repair a divergence found here; it is a direct-to-`main`
//! trusted-policy change. That is exactly why the divergence has to be visible
//! in the ordinary test suite rather than only inside the policy self-test.

use std::path::{Path, PathBuf};

const FUZZ_MANIFEST: &str = include_str!("../../../fuzz/Cargo.toml");
const FUZZ_WORKFLOW: &str = include_str!("../../../.github/workflows/fuzz.yml");
const CI_WORKFLOW: &str = include_str!("../../../.github/workflows/ci.yml");
const FUZZ_DOCS: &str = include_str!("../../../docs/fuzz.md");

/// Every `[[bin]]` name in the isolated fuzz workspace manifest.
fn registered_targets() -> Vec<String> {
    let mut targets = Vec::new();
    let mut in_bin = false;
    for line in FUZZ_MANIFEST.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_bin = trimmed == "[[bin]]";
            continue;
        }
        if !in_bin {
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("name = ") {
            targets.push(value.trim().trim_matches('"').to_string());
        }
    }
    assert!(
        targets.len() >= 7,
        "expected the registered fuzz targets to be parsed from fuzz/Cargo.toml, got {targets:?}"
    );
    targets
}

fn repo_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// The `fuzz-smoke` job body in `ci.yml`, so a target named anywhere else in
/// that very large workflow cannot satisfy the assertions below. A job ends at
/// the next line indented by exactly two spaces, which is where the next
/// top-level job key starts.
fn fuzz_smoke_job() -> &'static str {
    let start = CI_WORKFLOW
        .find("\n  fuzz-smoke:\n")
        .expect("ci.yml carries the fuzz-smoke job")
        + 1;
    let body = &CI_WORKFLOW[start..];
    let mut offset = 0usize;
    for (index, line) in body.split_inclusive('\n').enumerate() {
        if index > 0
            && line.starts_with("  ")
            && !line.as_bytes().get(2).is_some_and(u8::is_ascii_whitespace)
        {
            return &body[..offset];
        }
        offset += line.len();
    }
    body
}

/// The literal `case` alternation the scheduled lane re-checks its matrix value
/// against before it can reach a command line.
fn scheduled_shell_allowlist() -> Vec<&'static str> {
    let line = FUZZ_WORKFLOW
        .lines()
        .find(|line| line.trim_start().starts_with("traceparent|"))
        .expect("fuzz.yml carries the literal target allowlist");
    line.trim()
        .trim_end_matches(";;")
        .trim_end()
        .trim_end_matches(')')
        .split('|')
        .map(str::trim)
        .collect()
}

#[test]
fn every_registered_fuzz_target_has_a_target_source_and_seed_corpus() {
    for target in registered_targets() {
        let source = repo_path(&format!("fuzz/fuzz_targets/{target}.rs"));
        assert!(
            source.is_file(),
            "fuzz target {target} is registered but {} does not exist",
            source.display()
        );
        let corpus = repo_path(&format!("fuzz/corpus/{target}"));
        assert!(
            corpus.is_dir(),
            "fuzz target {target} has no seed corpus directory at {}",
            corpus.display()
        );
        let seeds = std::fs::read_dir(&corpus)
            .unwrap_or_else(|error| panic!("read {}: {error}", corpus.display()))
            .filter_map(Result::ok)
            .filter(|entry| entry.path().is_file())
            .count();
        assert!(
            seeds > 0,
            "fuzz target {target} has an empty seed corpus directory"
        );
    }
}

#[test]
fn every_registered_fuzz_target_is_scheduled_in_both_required_lanes() {
    for target in registered_targets() {
        assert!(
            FUZZ_WORKFLOW.contains(&format!("          - {target}\n")),
            "fuzz target {target} is missing from the fuzz.yml sanitizer matrix"
        );
        // The matrix value reaches the shell only through a literal allowlist,
        // so a matrix entry that is not also allowlisted fails the lane closed.
        assert!(
            scheduled_shell_allowlist().contains(&target.as_str()),
            "fuzz target {target} is missing from the fuzz.yml shell allowlist"
        );
        assert!(
            fuzz_smoke_job().contains(target.as_str()),
            "fuzz target {target} is missing from the required ci.yml fuzz-smoke job"
        );
        assert!(
            FUZZ_DOCS.contains(&format!("`{target}`")),
            "fuzz target {target} is undocumented in docs/fuzz.md"
        );
    }
}

#[test]
fn datagram_client_address_is_fuzzed_at_its_documented_64_kib_budget() {
    // The smoke loop's generic ceiling is 4 KiB. This parser's documented
    // budget is 64 KiB, and the scheduled sanitizer lane already runs it there;
    // a boundary reachable in one required lane and not the other is not
    // actually scheduled.
    let job = fuzz_smoke_job();
    let invocation = job
        .find("cargo fuzz run --codegen-units 16 datagram_client_address --")
        .expect("the fuzz-smoke job invokes datagram_client_address on its own");
    let bounds = &job[invocation..];
    let terminator = bounds
        .find("-rss_limit_mb=1024")
        .expect("the datagram invocation keeps the shared RSS bound");
    let bounds = &bounds[..terminator];
    assert!(
        bounds.contains("-max_len=65536"),
        "the datagram_client_address smoke invocation must use the target's 64 KiB budget"
    );
    for shared in ["-runs=512", "-max_total_time=8", "-timeout=2"] {
        assert!(
            bounds.contains(shared),
            "the datagram_client_address smoke invocation must keep {shared}"
        );
    }
    assert!(
        FUZZ_WORKFLOW.contains("-max_len=65536"),
        "the scheduled sanitizer lane must keep the 64 KiB ceiling"
    );
    assert!(
        FUZZ_DOCS.contains("scheduled in **both** required"),
        "docs/fuzz.md must document both lanes rather than the retired deferral"
    );
}

#[test]
fn datagram_client_address_corpus_covers_the_documented_boundary_shapes() {
    let corpus = repo_path("fuzz/corpus/datagram_client_address");
    for seed in [
        "truncated_header",
        "v2_local",
        "v2_unspec_dgram",
        "v2_ipv4_dgram",
        "v2_ipv6_dgram",
        "v2_unix_dgram",
        "v2_invalid_family",
        "v2_ipv4_dgram_empty_tlv",
        "v2_ipv4_truncated_tlv",
        "v2_ipv4_duplicate_auth",
        "v2_ipv4_duplicate_freshness",
        "v2_ipv4_freshness_wrong_length",
        "v2_ipv4_dgram_authenticated",
    ] {
        let path = corpus.join(seed);
        assert!(
            path.is_file(),
            "missing datagram_client_address seed {seed} at {}",
            path.display()
        );
        let bytes = std::fs::read(&path).unwrap_or_else(|error| panic!("read {seed}: {error}"));
        assert!(!bytes.is_empty(), "seed {seed} is empty");
        // Crash artifacts are rejected above 64 KiB before upload; seeds must
        // stay far below that, and synthetic seeds have no reason to be large.
        assert!(
            bytes.len() <= 1024,
            "seed {seed} is {} bytes; synthetic boundary seeds stay small",
            bytes.len()
        );
    }
}
